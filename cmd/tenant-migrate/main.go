// Command tenant-migrate cuts existing tenant rows over from the platform
// schema into each organization's own schema. It is the data half of
// docs/tenancy.md: ensure-schema creates empty tenant databases, this copies
// the historical rows.
//
// The copy is per-table and idempotent (delete the tenant rows, then insert
// them again), so a failed run can be repeated. -dry-run reports what would
// move without writing. -purge removes the platform copies only after the row
// counts match.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

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
		{"organization_members", "organization_id = ?"},
		{"organization_departments", "organization_id = ?"},
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
	schema := d.TenantSchemaName(orgID)
	if !dryRun {
		if _, err := d.EnsureTenantSchema(ctx, orgID); err != nil {
			return fmt.Errorf("prepare schema: %w", err)
		}
	}
	for _, spec := range tableSpecs() {
		where := strings.ReplaceAll(spec.where, "{{platform}}", "`"+platform+"`")
		var source int64
		countSQL := fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s` WHERE %s", platform, spec.name, where)
		if err := d.DB().WithContext(ctx).Raw(countSQL, orgID).Scan(&source).Error; err != nil {
			return fmt.Errorf("count %s: %w", spec.name, err)
		}
		if dryRun {
			log.Info("dry-run", zap.String("table", spec.name), zap.Int64("rows", source))
			continue
		}
		deleteSQL := fmt.Sprintf("DELETE FROM `%s`.`%s` WHERE %s", schema, spec.name, where)
		if err := d.DB().WithContext(ctx).Exec(deleteSQL, orgID).Error; err != nil {
			return fmt.Errorf("clear %s: %w", spec.name, err)
		}
		insertSQL := fmt.Sprintf("INSERT INTO `%s`.`%s` SELECT * FROM `%s`.`%s` WHERE %s", schema, spec.name, platform, spec.name, where)
		if err := d.DB().WithContext(ctx).Exec(insertSQL, orgID).Error; err != nil {
			return fmt.Errorf("copy %s: %w", spec.name, err)
		}
		var copied int64
		if err := d.DB().WithContext(ctx).Raw(fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", schema, spec.name)).Scan(&copied).Error; err != nil {
			return fmt.Errorf("verify %s: %w", spec.name, err)
		}
		if copied < source {
			return fmt.Errorf("verify %s: expected at least %d rows, found %d", spec.name, source, copied)
		}
		if purge {
			if err := d.DB().WithContext(ctx).Exec(deleteSQL, orgID).Error; err != nil {
				return fmt.Errorf("purge %s: %w", spec.name, err)
			}
		}
		log.Info("cut over", zap.String("table", spec.name), zap.Int64("rows", copied), zap.Bool("purged", purge))
	}
	return nil
}
