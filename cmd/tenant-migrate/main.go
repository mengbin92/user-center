// Command tenant-migrate cuts existing tenant rows over from the platform
// schema into each organization's own schema. It is the data half of
// docs/tenancy.md: ensure-schema creates empty tenant databases, this copies
// the historical rows.
//
// Copy and optional purge are atomic for each organization. An existing
// destination must match the source before the platform copy can be removed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// The WHERE clause selects the rows that belong to one organization on the
// platform schema. Columns that are not organization-scoped use the parent
// table to resolve the tenant.
type tableSpec struct {
	name  string
	where string
}

func tableSpecs() []tableSpec {
	return []tableSpec{
		{"organization_departments", "organization_id = ?"},
		{"organization_members", "organization_id = ?"},
		{"organization_invitations", "organization_id = ?"},
		{"iam_roles", "context_type = 'organization' AND context_id = ?"},
		{"iam_role_permissions", "role_id IN (SELECT id FROM {{platform}}.iam_roles WHERE context_type = 'organization' AND context_id = ?)"},
		{"iam_role_inheritance", "role_id IN (SELECT id FROM {{platform}}.iam_roles WHERE context_type = 'organization' AND context_id = ?)"},
		{"iam_user_roles", "context_type = 'organization' AND context_id = ?"},
		{"iam_role_constraints", "context_type = 'organization' AND context_id = ?"},
		{"iam_delegations", "context_type = 'organization' AND context_id = ?"},
		{"iam_audit_events", "organization_id = ?"},
		{"scim_identities", "organization_id = ?"},
		{"scim_groups", "organization_id = ?"},
		{"scim_group_members", "group_id IN (SELECT id FROM {{platform}}.scim_groups WHERE organization_id = ?)"},
		{"directory_objects", "organization_id = ?"},
		{"directory_sync_runs", "organization_id = ?"},
	}
}

func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "config path")
	orgID := flag.Int64("org", 0, "cut over one organization id")
	all := flag.Bool("all", false, "cut over every organization with a prepared schema")
	dryRun := flag.Bool("dry-run", false, "report row counts without writing")
	purge := flag.Bool("purge", false, "delete the platform copies after a verified copy")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	dataConf := wiring.ProvideData(bootstrap)
	if driver := dataConf.GetDatabase().GetDriver(); driver != "" && driver != "mysql" {
		log.Fatal("tenant-migrate requires MySQL")
	}
	dataConf.Redis = nil
	d, cleanup, err := data.NewData(dataConf, wiring.ProvideSecurity(bootstrap), log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()
	if !d.IsolationEnabled() {
		log.Fatal("schema isolation is disabled; enable it before cutting over data")
	}
	platform, err := d.PlatformDBName()
	if err != nil {
		log.Fatal("resolve platform schema", zap.Error(err))
	}

	ids := []int64{}
	if *orgID > 0 {
		ids = append(ids, *orgID)
	}
	if *all {
		found, err := d.TenantOrganizationIDs(context.Background())
		if err != nil {
			log.Fatal("list tenant schemas", zap.Error(err))
		}
		for _, id := range found {
			if id != *orgID {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		log.Fatal("nothing to do; run cmd/tenant-schema first, then pass -org or -all")
	}

	for _, id := range ids {
		if err := cutover(context.Background(), d, platform, id, *dryRun, *purge, log); err != nil {
			log.Fatal("cutover failed", zap.Int64("organization_id", id), zap.Error(err))
		}
	}
}

func cutover(ctx context.Context, d *data.Data, platform string, orgID int64, dryRun, purge bool, log *zap.Logger) error {
	if d.DB().Dialector.Name() != "mysql" || platform == "" {
		return fmt.Errorf("tenant-migrate requires a named MySQL platform database")
	}
	schema := d.TenantSchemaName(orgID)
	if orgID <= 0 || strings.EqualFold(platform, schema) {
		return fmt.Errorf("invalid organization id or overlapping platform and tenant schemas")
	}
	platformName, schemaName := platform, schema
	platform = identifier(platform)
	db := d.DB().WithContext(ctx)
	var exists int64
	if err := countRows(db, "SELECT COUNT(*) FROM "+platform+".organizations WHERE id = ?", &exists, orgID); err != nil {
		return err
	}
	if exists != 1 {
		return fmt.Errorf("organization %d not found", orgID)
	}
	specs := tableSpecs()
	rows := make([]int64, len(specs))
	if dryRun {
		for i, spec := range specs {
			query := "SELECT COUNT(*) FROM " + platform + "." + identifier(spec.name) + " WHERE " + strings.ReplaceAll(spec.where, "{{platform}}", platform)
			if err := countRows(db, query, &rows[i], orgID); err != nil {
				return fmt.Errorf("count %s: %w", spec.name, err)
			}
			log.Info("dry-run", zap.String("table", spec.name), zap.Int64("rows", rows[i]))
		}
		return nil
	}
	if _, err := d.EnsureTenantSchema(ctx, orgID); err != nil {
		return fmt.Errorf("prepare schema: %w", err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		var lockedID int64
		lock := tx.Raw("SELECT id FROM "+platform+".organizations WHERE id = ? FOR UPDATE", orgID).Scan(&lockedID)
		if lock.Error != nil {
			return lock.Error
		}
		if lock.RowsAffected != 1 {
			return fmt.Errorf("organization %d not found", orgID)
		}
		for i, spec := range specs {
			source := platform + "." + identifier(spec.name)
			where := strings.ReplaceAll(spec.where, "{{platform}}", platform)
			if err := countRows(tx, "SELECT COUNT(*) FROM "+source+" WHERE "+where, &rows[i], orgID); err != nil {
				return fmt.Errorf("count %s: %w", spec.name, err)
			}
			if rows[i] == 0 {
				// A successful purge leaves the destination as the only copy.
				continue
			}
			if err := copyTable(tx, platformName, schemaName, where, spec.name, orgID, rows[i]); err != nil {
				return fmt.Errorf("copy %s: %w", spec.name, err)
			}
		}
		if purge {
			for i := len(specs) - 1; i >= 0; i-- {
				if rows[i] == 0 {
					continue
				}
				spec := specs[i]
				where := strings.ReplaceAll(spec.where, "{{platform}}", platform)
				res := tx.Exec("DELETE FROM "+platform+"."+identifier(spec.name)+" WHERE "+where, orgID)
				if res.Error != nil {
					return fmt.Errorf("purge %s: %w", spec.name, res.Error)
				}
				if res.RowsAffected != rows[i] {
					return fmt.Errorf("purge %s: expected %d rows, removed %d", spec.name, rows[i], res.RowsAffected)
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for i, spec := range specs {
		log.Info("cut over", zap.String("table", spec.name), zap.Int64("rows", rows[i]), zap.Bool("purged", purge))
	}
	return nil
}

func identifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func countRows(tx *gorm.DB, query string, count *int64, args ...any) error {
	return tx.Raw(query, args...).Scan(count).Error
}

type tableColumn struct {
	Name      string
	DataType  string
	KeyKind   string
	Collation string
	Engine    string
}

func loadColumns(tx *gorm.DB, schema, table string) ([]tableColumn, error) {
	var columns []tableColumn
	err := tx.Raw(`SELECT c.column_name AS name, c.column_type AS data_type, c.column_key AS key_kind,
		COALESCE(c.collation_name, '') AS collation, t.engine AS engine
		FROM information_schema.columns c
		JOIN information_schema.tables t USING (table_schema, table_name)
		WHERE c.table_schema = ? AND c.table_name = ?
		ORDER BY c.ordinal_position`, schema, table).Scan(&columns).Error
	if err != nil {
		return nil, err
	}
	if len(columns) == 0 || columns[0].Engine != "InnoDB" {
		return nil, fmt.Errorf("%s.%s must be an InnoDB table", schema, table)
	}
	return columns, nil
}

func copyTable(tx *gorm.DB, sourceSchema, targetSchema, where, table string, orgID, sourceCount int64) error {
	src, err := loadColumns(tx, sourceSchema, table)
	if err != nil {
		return err
	}
	dst, err := loadColumns(tx, targetSchema, table)
	if err != nil {
		return err
	}
	if len(src) != len(dst) {
		return fmt.Errorf("source and destination column counts differ")
	}
	names, keys, values := []string{}, []string{}, []string{}
	for _, col := range src {
		index := slices.IndexFunc(dst, func(c tableColumn) bool { return c.Name == col.Name })
		if index < 0 || dst[index].DataType != col.DataType || (dst[index].KeyKind == "PRI") != (col.KeyKind == "PRI") {
			return fmt.Errorf("incompatible destination column %s", col.Name)
		}
		name := identifier(col.Name)
		names = append(names, name)
		if col.KeyKind == "PRI" {
			key := "s." + name
			if col.Collation != "" && dst[index].Collation != col.Collation {
				key += " COLLATE " + identifier(dst[index].Collation)
			}
			keys = append(keys, "d."+name+" = "+key)
		}
		values = append(values, "CAST(d."+name+" AS BINARY) <=> CAST(s."+name+" AS BINARY)")
	}
	if len(keys) == 0 {
		return fmt.Errorf("table must have a primary key")
	}
	source, target := identifier(sourceSchema)+"."+identifier(table), identifier(targetSchema)+"."+identifier(table)
	var count int64
	if err := countRows(tx, "SELECT COUNT(*) FROM "+target, &count); err != nil {
		return err
	}
	fields := strings.Join(names, ", ")
	query := "SELECT " + fields + " FROM " + source + " WHERE " + where
	if count == 0 {
		res := tx.Exec("INSERT INTO "+target+" ("+fields+") "+query, orgID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != sourceCount {
			return fmt.Errorf("expected %d copied rows, got %d", sourceCount, res.RowsAffected)
		}
		if err := countRows(tx, "SELECT COUNT(*) FROM "+target, &count); err != nil {
			return err
		}
	}
	if count != sourceCount {
		return fmt.Errorf("destination holds %d rows, expected %d; resolve divergence before retrying", count, sourceCount)
	}
	match := "SELECT COUNT(*) FROM (" + query + ") s WHERE EXISTS (SELECT 1 FROM " + target + " d WHERE " +
		strings.Join(keys, " AND ") + " AND " + strings.Join(values, " AND ") + ")"
	if err := countRows(tx, match, &count, orgID); err != nil {
		return err
	}
	if count != sourceCount {
		return fmt.Errorf("destination contents differ from source; verified %d of %d rows", count, sourceCount)
	}
	return nil
}
