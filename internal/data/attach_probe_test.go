package data

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/platform/tenant"
)

type probePO struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name"`
}

func (probePO) TableName() string { return "probe" }

type probeDialector struct{ gorm.Dialector }

func (p probeDialector) QuoteTo(w clause.Writer, s string) {
	if strings.Contains(s, ".") && !strings.Contains(s, "`") {
		parts := strings.SplitN(s, ".", 2)
		w.WriteByte('`')
		w.WriteString(parts[0])
		w.WriteString("`.`")
		w.WriteString(parts[1])
		w.WriteByte('`')
		return
	}
	p.Dialector.QuoteTo(w, s)
}

// Verifies the mechanism the tenant router relies on: GORM can be made to emit
// `schema`.`table` for a model, and SQLite resolves that against an ATTACHed
// database on the same connection. If this works, tenant tables can be written
// inside the SAME transaction as platform tables (MySQL is atomic across
// schemas on one instance), so no usecase needs a second transaction.
func TestAttachProbe(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(probeDialector{sqlite.Open("file:" + filepath.Join(dir, "platform.db") + "?_fk=1")}, &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	t.Cleanup(func() { _ = sqlDB.Close() })

	require.NoError(t, db.Exec("ATTACH DATABASE ? AS `tenant7`", filepath.Join(dir, "t7.db")).Error)
	require.NoError(t, db.Exec("CREATE TABLE `tenant7`.`probe` (id INTEGER PRIMARY KEY, name TEXT)").Error)

	ctx7 := tenant.With(context.Background(), 7)
	rewrite := func(tx *gorm.DB) {
		if tenant.From(tx.Statement.Context) == 7 && tx.Statement.Table == "probe" {
			tx.Statement.Table = "tenant7.probe"
		}
	}
	db.Callback().Query().Before("gorm:query").Register("probe:query", rewrite)
	db.Callback().Create().Before("gorm:create").Register("probe:create", rewrite)
	db.Callback().Update().Before("gorm:update").Register("probe:update", rewrite)
	db.Callback().Delete().Before("gorm:delete").Register("probe:delete", rewrite)

	require.NoError(t, db.AutoMigrate(&probePO{}))
	require.NoError(t, db.WithContext(ctx7).Create(&probePO{ID: 1, Name: "routed"}).Error)

	var found probePO
	require.NoError(t, db.WithContext(ctx7).Where("id = ?", 1).First(&found).Error)
	require.Equal(t, "routed", found.Name)

	// A platform-level query (no rewrite) must not see the tenant row.
	var count int64
	require.NoError(t, db.Table("probe").Count(&count).Error)
	require.Zero(t, count)

	// The row is really in the attached file.
	var raw string
	require.NoError(t, db.Raw("SELECT name FROM `tenant7`.`probe` WHERE id = 1").Scan(&raw).Error)
	require.Equal(t, "routed", raw)

	// AutoMigrate into an attached schema is what the CLI needs.
	require.NoError(t, db.WithContext(ctx7).AutoMigrate(&probePO{}))
}

type probe2PO struct {
	ID int64 `gorm:"column:id;primaryKey"`
}

func (probe2PO) TableName() string { return "probe2" }

// AutoMigrate creates the table through the Migrator, which does not always go
// through the query callbacks. This checks whether the router can also drive
// DDL, because cmd/tenant-schema depends on it.
func TestAttachProbeAutoMigrate(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(probeDialector{sqlite.Open("file:" + filepath.Join(dir, "p.db") + "?_fk=1")}, &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.Exec("ATTACH DATABASE ? AS `tenant7`", filepath.Join(dir, "t7.db")).Error)

	ctx7 := tenant.With(context.Background(), 7)
	rewrite := func(tx *gorm.DB) {
		if tenant.From(tx.Statement.Context) == 7 && tx.Statement.Table == "probe2" {
			tx.Statement.Table = "tenant7.probe2"
		}
	}
	db.Callback().Query().Before("gorm:query").Register("probe2:query", rewrite)
	db.Callback().Create().Before("gorm:create").Register("probe2:create", rewrite)

	require.NoError(t, db.WithContext(ctx7).Table("tenant7.probe2").AutoMigrate(&probe2PO{}))

	var count int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM `tenant7`.`sqlite_master` WHERE type='table' AND name='probe2'").Scan(&count).Error)
	require.Equal(t, int64(1), count, "AutoMigrate must create the table inside the attached schema")

	var platform int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM `main`.`sqlite_master` WHERE type='table' AND name='probe2'").Scan(&platform).Error)
	require.Zero(t, platform, "AutoMigrate must not create it on the platform schema")
}
