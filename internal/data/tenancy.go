package data

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	driverMySQL "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/platform/tenant"
)

// Per-organization schema isolation.
//
// Two storage shapes, one router:
//
//   - MySQL has schemas, so routing rewrites the table name to
//     `schema`.`table` and keeps the platform connection. That is what makes
//     the isolation complete: one transaction writes platform and tenant
//     tables atomically (InnoDB is atomic across schemas on one instance), so
//     no usecase needs a second transaction or a compensating job.
//   - SQLite has no schemas. Each tenant gets its own database file and its own
//     pool. Isolation is still physical, but a tenant write is not part of the
//     platform transaction; SQLite is dev/test only and that limitation is
//     documented.
//
// Every table is created from a checked-in SQL file (tenantddl/*.sql), never by
// GORM's Migrator, so tenant DDL is reviewable and diffable like any migration.

//go:embed tenantddl/*.sql
var tenantDDLFS embed.FS

type tenantDialector struct{ gorm.Dialector }

// QuoteTo splits a dotted identifier so `schema.table` is emitted as
// `schema`.`table`. Column names that arrive as `alias.column` are already
// valid in that form, so the rewrite is safe for JOINs too.
func (t tenantDialector) QuoteTo(w clause.Writer, s string) {
	if strings.Contains(s, ".") && !strings.ContainsAny(s, "`\"") {
		parts := strings.SplitN(s, ".", 2)
		w.WriteByte('`')
		w.WriteString(parts[0])
		w.WriteString("`.`")
		w.WriteString(parts[1])
		w.WriteByte('`')
		return
	}
	t.Dialector.QuoteTo(w, s)
}

// tenantTables is the closed set of tables that belong to one organization.
// Everything not listed here (users, organizations, event_outbox, platform IAM
// rows, settings, sessions ...) stays on the platform schema.
var tenantTables = map[string]bool{
	"organization_members":     true,
	"organization_departments": true,
	"organization_invitations": true,
	"iam_roles":                true,
	"iam_role_permissions":     true,
	"iam_role_inheritance":     true,
	"iam_user_roles":           true,
	"iam_role_constraints":     true,
	"iam_delegations":          true,
	"iam_audit_events":         true,
	"scim_identities":          true,
	"scim_groups":              true,
	"scim_group_members":       true,
	"directory_objects":        true,
	"directory_sync_runs":      true,
}

const defaultSchemaPrefix = "usercenter_org_"

func (d *Data) IsolationEnabled() bool {
	return d.tenancy != nil && d.tenancy.SchemaIsolation
}

func (d *Data) schemaPrefix() string {
	if d.tenancy != nil && strings.TrimSpace(d.tenancy.SchemaPrefix) != "" {
		return strings.TrimSpace(d.tenancy.SchemaPrefix)
	}
	return defaultSchemaPrefix
}

func (d *Data) TenantSchemaName(orgID int64) string {
	return d.schemaPrefix() + strconv.FormatInt(orgID, 10)
}

func (d *Data) isSQLite() bool {
	return d.driver == "sqlite" || d.driver == "sqlite3"
}

// TenantDB returns the handle that should serve tenant data. On MySQL it is
// the platform pool (routing is by table name); on SQLite it is the tenant's
// own database file.
func (d *Data) TenantDB(ctx context.Context) *gorm.DB {
	if !d.IsolationEnabled() || !d.isSQLite() {
		return d.db
	}
	orgID := tenant.From(ctx)
	if orgID <= 0 {
		return d.db
	}
	db, err := d.sqliteTenantDB(orgID)
	if err != nil {
		if d.log != nil {
			d.log.Warn("tenant database unavailable", zap.Int64("organization_id", orgID), zap.Error(err))
		}
		return d.db.Session(&gorm.Session{NewDB: true}).Table("__tenant_database_missing__")
	}
	return db.WithContext(ctx)
}

// tenantOr is the tenant-aware equivalent of dbOr. MySQL keeps the caller's
// transaction so tenant writes stay atomic with platform writes; SQLite swaps
// in the tenant file.
func (d *Data) tenantOr(ctx context.Context, tx biz.Tx) *gorm.DB {
	if !d.IsolationEnabled() {
		return d.dbOr(tx)
	}
	if d.isSQLite() {
		if tenant.From(ctx) <= 0 {
			return d.dbOr(tx)
		}
		return d.TenantDB(ctx)
	}
	return d.dbOr(tx)
}

// TenantTable returns the schema-qualified name for a tenant table when the
// context is bound to an organization, and the bare name otherwise. Queries
// built with Table("x AS alias") set Statement.TableExpr, which the routing
// callback cannot rewrite, so those call sites must use this helper instead.
func (d *Data) TenantTable(ctx context.Context, table string) string {
	if !d.IsolationEnabled() || d.isSQLite() {
		return table
	}
	orgID := tenant.From(ctx)
	if orgID <= 0 {
		return table
	}
	return d.TenantSchemaName(orgID) + "." + table
}

// TenantTxManager opens transactions on the platform pool.
type TenantTxManager struct{ d *Data }

func (m *TenantTxManager) InTx(ctx context.Context, fn func(context.Context, biz.Tx) error) error {
	return m.d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(ctx, tx)
	})
}

func (d *Data) TenantTxManager() biz.TxManager { return &TenantTxManager{d: d} }

// registerTenantRouting installs the table rewrite on every read and write
// path. SQLite does not use it: its tenant handle already points at the right
// file, and rewriting the table would look for a schema that does not exist.
func (d *Data) registerTenantRouting() {
	if d.isSQLite() {
		return
	}
	rewrite := func(tx *gorm.DB) {
		if !d.IsolationEnabled() || tx.Statement == nil {
			return
		}
		orgID := tenant.From(tx.Statement.Context)
		if orgID <= 0 {
			return
		}
		table := tx.Statement.Table
		if table == "" || strings.Contains(table, ".") || !tenantTables[table] {
			return
		}
		tx.Statement.Table = d.TenantSchemaName(orgID) + "." + table
	}
	d.db.Callback().Query().Before("gorm:query").Register("tenant:query", rewrite)
	d.db.Callback().Create().Before("gorm:create").Register("tenant:create", rewrite)
	d.db.Callback().Update().Before("gorm:update").Register("tenant:update", rewrite)
	d.db.Callback().Delete().Before("gorm:delete").Register("tenant:delete", rewrite)
}

func (d *Data) tenantSource(orgID int64) (string, string, error) {
	name := d.TenantSchemaName(orgID)
	if d.isSQLite() {
		base := d.baseSource
		if base == "" {
			base = "file::memory:?cache=shared"
		}
		path := strings.TrimPrefix(base, "file:")
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		dir := filepath.Dir(path)
		if dir == "." || dir == "" || strings.Contains(path, ":memory:") {
			dir = filepath.Join(os.TempDir(), "usercenter-tenants")
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", name, err
		}
		return filepath.Join(dir, fmt.Sprintf("tenant_%d.db", orgID)), name, nil
	}
	cfg, err := driverMySQL.ParseDSN(d.baseSource)
	if err != nil {
		return "", name, fmt.Errorf("parse MySQL DSN: %w", err)
	}
	cfg.DBName = name
	return cfg.FormatDSN(), name, nil
}

func (d *Data) sqliteTenantDB(orgID int64) (*gorm.DB, error) {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	if db, ok := d.tenants[orgID]; ok {
		return db, nil
	}
	source, _, err := d.tenantSource(orgID)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open(sqlite.Open("file:"+source+"?_fk=1"), &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, err
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(4)
		sqlDB.SetMaxIdleConns(2)
	}
	d.tenants[orgID] = db
	return db, nil
}

// tenantStatements strips comments, substitutes the schema placeholder and
// splits a checked-in DDL file into executable statements. The files contain no
// semicolons inside string literals, so a plain split is safe.
func tenantStatements(raw, schema string) []string {
	lines := make([]string, 0, 64)
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		lines = append(lines, line)
	}
	out := make([]string, 0, 32)
	for _, stmt := range strings.Split(strings.Join(lines, "\n"), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(stmt, "{{schema}}", schema))
	}
	return out
}

func (d *Data) execTenantDDL(db *gorm.DB, file, schema string) error {
	raw, err := tenantDDLFS.ReadFile("tenantddl/" + file + ".sql")
	if err != nil {
		return fmt.Errorf("read tenant ddl %s: %w", file, err)
	}
	for _, stmt := range tenantStatements(string(raw), schema) {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("execute tenant ddl for %s: %w", schema, err)
		}
	}
	return nil
}

// EnsureTenantSchema prepares the physical schema for one organization using
// the checked-in DDL. It is idempotent and is the entry point of
// cmd/tenant-schema and of organization creation once isolation is enabled.
func (d *Data) EnsureTenantSchema(ctx context.Context, orgID int64) (string, error) {
	if orgID <= 0 {
		return "", fmt.Errorf("organization id must be positive")
	}
	if !d.IsolationEnabled() {
		return "", fmt.Errorf("schema isolation is disabled in configuration")
	}
	_, name, err := d.tenantSource(orgID)
	if err != nil {
		return "", err
	}
	if d.isSQLite() {
		db, err := d.sqliteTenantDB(orgID)
		if err != nil {
			return "", fmt.Errorf("open tenant database: %w", err)
		}
		if err := d.execTenantDDL(db, "sqlite", "main"); err != nil {
			return "", err
		}
	} else {
		stmt := "CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
		if err := d.db.Exec(stmt).Error; err != nil {
			return "", fmt.Errorf("create tenant schema: %w", err)
		}
		if err := d.execTenantDDL(d.db, "mysql", name); err != nil {
			return "", err
		}
	}
	now := time.Now().UTC()
	if err := d.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"schema_name", "status", "updated_at"}),
	}).Create(&tenantSchemaPO{
		OrganizationID: orgID, SchemaName: name, Status: "ready",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		return "", fmt.Errorf("record tenant schema: %w", err)
	}
	d.tenantsMu.Lock()
	d.attached[name] = true
	d.tenantsMu.Unlock()
	return name, nil
}

// TenantSchemas lists schemas prepared on this instance.
func (d *Data) TenantSchemas() []string {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	out := make([]string, 0, len(d.attached))
	for name := range d.attached {
		out = append(out, name)
	}
	return out
}

// TenantOrganizationIDs returns every organization with a prepared schema,
// ordered by id. Cross-tenant queries iterate this list.
func (d *Data) TenantOrganizationIDs(ctx context.Context) ([]int64, error) {
	if !d.IsolationEnabled() {
		return nil, nil
	}
	var ids []int64
	err := d.db.WithContext(ctx).Model(&tenantSchemaPO{}).
		Where("status = ?", "ready").Order("organization_id ASC").Pluck("organization_id", &ids).Error
	return ids, err
}

func (d *Data) closeTenantPools() {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	for id, db := range d.tenants {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		delete(d.tenants, id)
	}
}

// TenancyConfig is exposed for the CLI and readiness reporting.
func (d *Data) TenancyConfig() *conf.Tenancy { return d.tenancy }

var _ = sql.ErrNoRows

// PlatformDBName is the schema that holds the shared identity and governance
// tables. The cutover CLI needs it to copy tenant rows across schemas.
func (d *Data) PlatformDBName() (string, error) {
	if d.isSQLite() {
		return "main", nil
	}
	cfg, err := driverMySQL.ParseDSN(d.baseSource)
	if err != nil {
		return "", err
	}
	return cfg.DBName, nil
}
