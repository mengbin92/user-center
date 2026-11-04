package main

import (
	"os"
	"testing"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOIDCMySQLMigrations(t *testing.T) {
	dsn := os.Getenv("USER_CENTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set USER_CENTER_MYSQL_TEST_DSN to an isolated MySQL test database")
	}
	secret := "isolated-mysql-test-secret-at-least-32-bytes"
	d, cleanup, err := data.NewData(&conf.Data{Database: &conf.Database{Driver: "mysql", Source: dsn}}, &conf.Security{SessionSecret: secret, CsrfSecret: secret, MfaEncryptionKey: secret}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	for range 2 {
		require.NoError(t, runSQLMigrations(d.DB(), "../../migrations/mysql", zap.NewNop()))
		require.NoError(t, data.SeedCatalog(d.DB()))
	}
	for _, table := range []string{"oidc_authorization_codes", "oidc_refresh_tokens"} {
		require.True(t, d.DB().Migrator().HasColumn(table, "identity_version"))
	}
	require.True(t, d.DB().Migrator().HasColumn("oidc_refresh_tokens", "family_id"))
	var versions int64
	require.NoError(t, d.DB().Table("schema_migrations").Count(&versions).Error)
	require.GreaterOrEqual(t, versions, int64(4))
}
