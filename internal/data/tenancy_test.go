package data

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/platform/tenant"
)

func newTenantTestData(t *testing.T, enabled bool) *Data {
	t.Helper()
	return openTenantTestData(t, filepath.Join(t.TempDir(), "platform.db"), enabled)
}

func openTenantTestData(t *testing.T, path string, enabled bool) *Data {
	t.Helper()
	cfg := &conf.Data{
		Database: &conf.Database{
			Driver: "sqlite", Source: "file:" + path + "?_fk=1",
		},
		Tenancy: &conf.Tenancy{SchemaIsolation: enabled},
	}
	sec := &conf.Security{SessionSecret: "test", CsrfSecret: "test", MfaEncryptionKey: "test"}
	d, cleanup, err := NewData(cfg, sec, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.NoError(t, d.AutoMigrate())
	return d
}

func TestSQLiteTenantFilesAreScopedToPlatformDatabase(t *testing.T) {
	dir := t.TempDir()
	platformA := filepath.Join(dir, "platform-a.db")
	platformB := filepath.Join(dir, "platform-b.db")
	a := openTenantTestData(t, platformA, true)
	b := openTenantTestData(t, platformB, true)
	ctx := tenant.With(context.Background(), 7)
	var count int64
	require.Error(t, b.TenantDB(ctx).Table("organization_members").Count(&count).Error)
	require.NoDirExists(t, platformB+".tenants")

	_, err := a.EnsureTenantSchema(ctx, 7)
	require.NoError(t, err)
	_, err = b.EnsureTenantSchema(ctx, 7)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(platformA+".tenants", "tenant_7.db"))
	require.FileExists(t, filepath.Join(platformB+".tenants", "tenant_7.db"))
}

func TestSQLiteTenantFilesRequireExplicitLegacyOwnership(t *testing.T) {
	dir := t.TempDir()
	platform := filepath.Join(dir, "platform.db")
	d := openTenantTestData(t, platform, true)
	legacy := filepath.Join(dir, "tenant_7.db")
	require.NoError(t, os.WriteFile(legacy, nil, 0o600))
	_, err := d.EnsureTenantSchema(context.Background(), 7)
	require.ErrorContains(t, err, "legacy SQLite tenant file")
	require.FileExists(t, legacy)
	require.NoDirExists(t, platform+".tenants")
}

func TestTenantSchemaConfigurationRejectsInvalidNamespaces(t *testing.T) {
	require.Error(t, validateTenantPrefix("user-center_"))
	require.Error(t, validateTenantMySQLSource("user@tcp(localhost)/UserCenter_Org_9", ""))
	require.NoError(t, validateTenantMySQLSource("user@tcp(localhost)/usercenter", ""))
}

func TestTenantSchemasArePhysicallySeparate(t *testing.T) {
	d := newTenantTestData(t, true)
	ctx := context.Background()
	require.True(t, d.IsolationEnabled())
	require.Equal(t, d.DB(), d.TenantDB(ctx), "an unbound request must use the platform schema")

	nameA, err := d.EnsureTenantSchema(ctx, 7)
	require.NoError(t, err)
	nameB, err := d.EnsureTenantSchema(ctx, 8)
	require.NoError(t, err)
	require.NotEqual(t, nameA, nameB)
	require.Contains(t, nameA, "7")
	require.Contains(t, nameB, "8")
	require.Len(t, d.TenantSchemas(), 2)

	ctxA, ctxB := tenant.With(ctx, 7), tenant.With(ctx, 8)
	// SQLite has no schemas, so tenant contexts use a separate database file
	// while platform contexts keep the platform pool.
	require.NotEqual(t, d.DB(), d.TenantDB(ctxA))
	require.Equal(t, d.DB(), d.TenantDB(context.Background()))

	repo := NewSCIMRepo(d)
	_, err = repo.UpsertIdentity(ctxA, nil, &biz.SCIMIdentity{
		OrganizationID: 7, Kind: biz.SCIMKindUser, ExternalID: "ext-1", LocalID: 101,
	})
	require.NoError(t, err)

	found, err := repo.GetIdentityByExternal(ctxA, nil, 7, biz.SCIMKindUser, "ext-1")
	require.NoError(t, err)
	require.Equal(t, int64(101), found.LocalID)

	_, err = repo.GetIdentityByExternal(ctxB, nil, 8, biz.SCIMKindUser, "ext-1")
	require.Error(t, err, "tenant B's schema must not contain tenant A's object")

	var platformCount int64
	require.NoError(t, d.DB().Table("scim_identities").Count(&platformCount).Error)
	require.Zero(t, platformCount, "tenant-owned rows must not land in the platform schema")

	// A second object with the same externalId is legal in another tenant:
	// uniqueness is per physical schema, not global.
	_, err = repo.UpsertIdentity(ctxB, nil, &biz.SCIMIdentity{
		OrganizationID: 8, Kind: biz.SCIMKindUser, ExternalID: "ext-1", LocalID: 202,
	})
	require.NoError(t, err)
	foundB, err := repo.GetIdentityByExternal(ctxB, nil, 8, biz.SCIMKindUser, "ext-1")
	require.NoError(t, err)
	require.Equal(t, int64(202), foundB.LocalID)
}

func TestTenantRoutingIsOptIn(t *testing.T) {
	d := newTenantTestData(t, false)
	require.False(t, d.IsolationEnabled())
	ctx := tenant.With(context.Background(), 7)
	require.Equal(t, d.DB(), d.TenantDB(ctx), "with isolation off every request keeps using the platform pool")
	_, err := d.EnsureTenantSchema(ctx, 7)
	require.Error(t, err, "the CLI must not silently create schemas when isolation is disabled")
	require.Empty(t, d.TenantSchemas())
}

func TestTenantSchemaNameRejectsNonPositiveID(t *testing.T) {
	d := newTenantTestData(t, true)
	_, err := d.EnsureTenantSchema(context.Background(), 0)
	require.Error(t, err)
}
