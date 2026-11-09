package data

import (
	"context"
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
	dir := t.TempDir()
	cfg := &conf.Data{
		Database: &conf.Database{
			Driver: "sqlite", Source: "file:" + filepath.Join(dir, "platform.db") + "?_fk=1",
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
