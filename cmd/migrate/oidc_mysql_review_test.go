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
	// V2.4: consent, logout whitelist, invitations and tenant exports.
	for _, table := range []string{"oidc_consents", "oidc_consent_requests", "organization_invitations", "webauthn_credentials", "user_legal_holds"} {
		require.True(t, d.DB().Migrator().HasTable(table), "%s", table)
	}
	for _, column := range []struct{ table, name string }{
		{"oidc_clients", "post_logout_redirect_uris"},
		{"export_jobs", "organization_id"},
		{"users", "anonymized_at"},
	} {
		require.True(t, d.DB().Migrator().HasColumn(column.table, column.name), "%s.%s", column.table, column.name)
	}
	for _, column := range []struct{ table, name string }{
		{"iam_roles", "context_type"},
		{"iam_roles", "context_id"},
		{"iam_user_roles", "context_type"},
		{"iam_user_roles", "context_id"},
		{"iam_audit_events", "organization_id"},
	} {
		require.True(t, d.DB().Migrator().HasColumn(column.table, column.name), "%s.%s", column.table, column.name)
	}
	var versions int64
	require.NoError(t, d.DB().Table("schema_migrations").Count(&versions).Error)
	require.GreaterOrEqual(t, versions, int64(6))
}
