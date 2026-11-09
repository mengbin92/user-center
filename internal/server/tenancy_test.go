package server_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/conf"
)

// Schema isolation at the HTTP boundary. The bearer token decides which
// physical schema a SCIM request may touch; even a known id from another
// tenant must resolve to 404 because the mapping lives in the other schema.

func TestTenantSchemaIsolationAtHTTPBoundary(t *testing.T) {
	dir := t.TempDir()
	h := newHarnessFor(t, &conf.Data{
		Database: &conf.Database{
			Driver: "sqlite", Source: "file:" + filepath.Join(dir, "platform.db") + "?_fk=1",
		},
		Tenancy: &conf.Tenancy{SchemaIsolation: true},
	})
	require.True(t, h.d.IsolationEnabled())

	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgA := orgByCode(t, h, "iso-a")
	orgB := orgByCode(t, h, "iso-b")
	tokenA, _ := scimToken(t, h, orgA, "idp-a")
	tokenB, _ := scimToken(t, h, orgB, "idp-b")

	userA := scimCreateUser(t, h, tokenA, "iso-alice", "iso-alice@example.com", "a-1")
	userB := scimCreateUser(t, h, tokenB, "iso-bob", "iso-bob@example.com", "b-1")

	// Each tenant has its own schema and the platform schema holds no tenant
	// identity rows at all.
	require.Len(t, h.d.TenantSchemas(), 2)
	var platformCount int64
	require.NoError(t, h.d.DB().Table("scim_identities").Count(&platformCount).Error)
	require.Zero(t, platformCount)

	// A's token sees its own object but not B's, and B's token sees its own.
	rec := h.do(http.MethodGet, "/scim/v2/Users/"+userA["id"].(string), nil, tokenA, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/scim/v2/Users/"+userB["id"].(string), nil, tokenA, false)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/scim/v2/Users/"+userB["id"].(string), nil, tokenB, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// A tenant's list only contains its own provisioned objects.
	listA := h.do(http.MethodGet, "/scim/v2/Users", nil, tokenA, false)
	require.Equal(t, http.StatusOK, listA.Code, listA.Body.String())
	require.Equal(t, float64(1), decode[map[string]any](t, listA)["totalResults"])

	// Governance credentials stay on the platform schema: they are bound to an
	// organization but are not tenant data themselves.
	var tokenCount int64
	require.NoError(t, h.d.DB().Table("scim_tokens").Count(&tokenCount).Error)
	require.Equal(t, int64(2), tokenCount)
}
