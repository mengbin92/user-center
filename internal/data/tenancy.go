package data

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	driverMySQL "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/platform/tenant"
)

// Per-organization schema isolation.
//
// In MySQL a schema IS a database, so "one schema per tenant" is implemented
// as one database per organization with its own connection pool. The platform
// pool keeps the shared identity and cross-tenant governance tables. Routing
// is driven solely by the organization id in the request context, which the
// transport injects from the verified URL path or the authenticated SCIM token
// -- never from a request body.
//
// Isolation is opt-in (Tenancy.SchemaIsolation). When it is off, TenantDB
// returns the platform pool and the system keeps its original logical
// isolation unchanged, including all existing tests.

type tenantPool struct {
	db   *gorm.DB
	sql  *sql.DB
	name string
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

// TenantDB resolves the connection pool for the organization bound to ctx.
// An unbound (platform) request always uses the platform pool. When isolation
// is enabled and the tenant database does not exist yet, the returned handle
// points at a missing schema and every query fails closed: it never silently
// falls back to the shared pool, which would mix tenant data.
func (d *Data) TenantDB(ctx context.Context) *gorm.DB {
	if !d.IsolationEnabled() {
		return d.db
	}
	orgID := tenant.From(ctx)
	if orgID <= 0 {
		return d.db
	}
	db, err := d.tenantDB(orgID)
	if err != nil {
		if d.log != nil {
			d.log.Warn("tenant schema unavailable", zap.Int64("organization_id", orgID), zap.Error(err))
		}
		return d.db.Session(&gorm.Session{NewDB: true}).Table("__tenant_schema_missing__")
	}
	return db
}

// tenantOr is the tenant-aware equivalent of dbOr.
//
// With isolation OFF it must honour tx exactly like dbOr does: several repos
// call it from inside a transaction on a single-connection SQLite/MySQL pool,
// and borrowing a second connection there deadlocks (the caller already holds
// the only one). With isolation ON, tenant tables live in a different database,
// so the platform transaction cannot be reused -- the write intentionally goes
// to the tenant pool outside that transaction.
func (d *Data) tenantOr(ctx context.Context, tx biz.Tx) *gorm.DB {
	if !d.IsolationEnabled() {
		return d.dbOr(tx)
	}
	return d.TenantDB(ctx)
}

// TenantTxManager opens transactions on the connection selected by ctx.
// Without this, a tenant repository could read from its schema but write
// through a platform transaction, which would split one logical change across
// two databases.
type TenantTxManager struct{ d *Data }

func (m *TenantTxManager) InTx(ctx context.Context, fn func(context.Context, biz.Tx) error) error {
	return m.d.TenantDB(ctx).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(ctx, tx)
	})
}

// TenantTxManager satisfies the optional interface NewServices probes, so the
// usecase graph gains tenant-aware transactions without changing the Wire
// signature of every existing constructor.
func (d *Data) TenantTxManager() biz.TxManager { return &TenantTxManager{d: d} }

func (d *Data) tenantSource(orgID int64) (string, string, error) {
	name := d.TenantSchemaName(orgID)
	switch d.driver {
	case "sqlite", "sqlite3":
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
		return "file:" + filepath.Join(dir, fmt.Sprintf("tenant_%d.db", orgID)) + "?_fk=1", name, nil
	default:
		cfg, err := driverMySQL.ParseDSN(d.baseSource)
		if err != nil {
			return "", name, fmt.Errorf("parse MySQL DSN: %w", err)
		}
		cfg.DBName = name
		return cfg.FormatDSN(), name, nil
	}
}

func (d *Data) tenantDB(orgID int64) (*gorm.DB, error) {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	if pool, ok := d.tenants[orgID]; ok {
		return pool.db, nil
	}
	source, name, err := d.tenantSource(orgID)
	if err != nil {
		return nil, err
	}
	// MySQL needs the database to exist before GORM can open a pool on it.
	if d.driver != "sqlite" && d.driver != "sqlite3" {
		stmt := "CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
		if err := d.db.Exec(stmt).Error; err != nil {
			return nil, fmt.Errorf("create tenant schema: %w", err)
		}
	}
	var dial gorm.Dialector
	if d.driver == "sqlite" || d.driver == "sqlite3" {
		dial = sqlite.Open(source)
	} else {
		dial = mysql.Open(source)
	}
	db, err := gorm.Open(dial, &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, err
	}
	// A tenant schema carries the same table set as the platform schema. This
	// keeps tenant transactions self-contained: a provisioning write touches
	// users, audit and the tenant tables in ONE database.
	if err := db.AutoMigrate(models()...); err != nil {
		return nil, fmt.Errorf("migrate tenant schema: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	maxOpen, maxIdle := 8, 4
	if d.tenancy != nil {
		if d.tenancy.MaxOpenConns > 0 {
			maxOpen = int(d.tenancy.MaxOpenConns)
		}
		if d.tenancy.MaxIdleConns > 0 {
			maxIdle = int(d.tenancy.MaxIdleConns)
		}
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(time.Hour)
	d.tenants[orgID] = &tenantPool{db: db, sql: sqlDB, name: name}
	return db, nil
}

// EnsureTenantSchema prepares the physical schema for one organization. It is
// idempotent and is the entry point of cmd/tenant-schema; the static SQL
// migrations cannot express "create one schema per organization".
func (d *Data) EnsureTenantSchema(_ context.Context, orgID int64) (string, error) {
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
	if _, err := d.tenantDB(orgID); err != nil {
		return "", err
	}
	return name, nil
}

// TenantSchemas lists the schemas opened on this instance. MySQL deployments
// can also enumerate them with SHOW DATABASES; the in-process list is what the
// router actually uses.
func (d *Data) TenantSchemas() []string {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	out := make([]string, 0, len(d.tenants))
	for _, pool := range d.tenants {
		out = append(out, pool.name)
	}
	return out
}

func (d *Data) closeTenantPools() {
	d.tenantsMu.Lock()
	defer d.tenantsMu.Unlock()
	for id, pool := range d.tenants {
		if pool.sql != nil {
			_ = pool.sql.Close()
		}
		delete(d.tenants, id)
	}
}

// TenancyConfig is exposed for the CLI and readiness reporting.
func (d *Data) TenancyConfig() *conf.Tenancy { return d.tenancy }
