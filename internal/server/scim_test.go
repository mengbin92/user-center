package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// SCIM 2.0 provisioning.
//
// The security claim under test is that the bearer token is the only tenant
// selector: a request body may carry any id, organization or externalId, but
// every lookup goes through the (organization_id, kind, externalId) mapping of
// the token's own organization. These are HTTP-level cases because that
// boundary lives in three places (token auth, identity map, group membership
// validation) and only an end-to-end call proves they agree.

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
const scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
const scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// scimDoRaw builds a request with arbitrary headers (If-Match in particular),
// which h.do does not expose. It still goes through the real HTTP stack.
func scimDoRaw(h *harness, method, path, token string, body any, headers map[string]string) *httptest.ResponseRecorder {
	raw := []byte(nil)
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "http://example.com"+path, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", scimContentTypeForTest)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

const scimContentTypeForTest = "application/scim+json"

func scimToken(t *testing.T, h *harness, orgID, name string) (string, map[string]any) {
	t.Helper()
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.do(http.MethodPost, "/api/v1/admin/scim/tokens", map[string]any{
		"organization_id": orgID, "name": name, "reason": "scim fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	reply := decode[map[string]any](t, rec)
	tokenValue, ok := reply["token_value"].(string)
	require.True(t, ok && tokenValue != "", "the plaintext token must be returned exactly once")
	return tokenValue, reply["token"].(map[string]any)
}

func scimCreateUser(t *testing.T, h *harness, token, userName, email, externalID string) map[string]any {
	t.Helper()
	rec := h.do(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":     []string{scimUserSchema},
		"userName":    userName,
		"externalId":  externalID,
		"displayName": userName + " display",
		"emails":      []map[string]any{{"value": email, "type": "work", "primary": true}},
		"active":      true,
	}, token, false)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)
}

func TestSCIMDiscoveryAndAuthentication(t *testing.T) {
	h := newHarness(t)
	orgID := func() string {
		require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
		return orgByCode(t, h, "scim-discovery")
	}()
	token, _ := scimToken(t, h, orgID, "okta")

	for _, path := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/ResourceTypes",
		"/scim/v2/ResourceTypes/User",
		"/scim/v2/Schemas",
		"/scim/v2/Users",
		"/scim/v2/Groups",
	} {
		rec := h.do(http.MethodGet, path, nil, token, false)
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", path, rec.Body.String())
	}

	// No token, a wrong token, and a token from a disabled credential all fail
	// closed with the SCIM error shape, never a redirect or an HTML page.
	for _, bad := range []string{"", "not-a-token", "ucs_" + "0"} {
		rec := h.do(http.MethodGet, "/scim/v2/Users", nil, bad, false)
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), scimErrorSchema)
	}

	// Missing schemas is a protocol error, not a silently accepted create.
	rec := h.do(http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "no-schema"}, token, false)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// Unsupported filter grammar is refused, not interpreted loosely.
	rec = h.do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape("userName sw \"a\""), nil, token, false)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "invalidFilter")
}

func TestSCIMProvisioningLifecycle(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "scim-life")
	token, _ := scimToken(t, h, orgID, "entra")

	created := scimCreateUser(t, h, token, "alice", "alice@example.com", "entra-alice")
	userID := created["id"].(string)
	require.Equal(t, "entra-alice", created["externalId"])
	require.Equal(t, true, created["active"])
	etag := created["meta"].(map[string]any)["version"].(string)

	// Filtering and paging use the closed grammar.
	list := h.do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape("userName eq \"alice\""), nil, token, false)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Equal(t, float64(1), decode[map[string]any](t, list)["totalResults"])
	emailFilter := url.QueryEscape(`emails[type eq "work"].value eq "alice@example.com" and active eq true`)
	filteredByEmail := h.do(http.MethodGet, "/scim/v2/Users?filter="+emailFilter, nil, token, false)
	require.Equal(t, http.StatusOK, filteredByEmail.Code, filteredByEmail.Body.String())
	require.Equal(t, float64(1), decode[map[string]any](t, filteredByEmail)["totalResults"])

	// A duplicate externalId is a SCIM uniqueness conflict.
	dup := h.do(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas": []string{scimUserSchema}, "userName": "alice2",
		"externalId": "entra-alice", "active": true,
	}, token, false)
	require.Equal(t, http.StatusConflict, dup.Code, dup.Body.String())

	// PATCH active=false deprovisions membership; the global account survives.
	patch := h.do(http.MethodPatch, "/scim/v2/Users/"+userID, map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	}, token, false)
	require.Equal(t, http.StatusOK, patch.Code, patch.Body.String())
	require.Equal(t, false, decode[map[string]any](t, patch)["active"])

	// A stale If-Match must not overwrite the version just written.
	stale := scimDoRaw(h, http.MethodPut, "/scim/v2/Users/"+userID, token,
		map[string]any{"schemas": []string{scimUserSchema}, "userName": "alice", "active": true},
		map[string]string{"If-Match": `W/"999999"`})
	require.Equal(t, http.StatusPreconditionFailed, stale.Code, stale.Body.String())
	require.NotEmpty(t, etag)

	// PUT without If-Match is allowed by the spec (many IdPs never send it).
	ok := h.do(http.MethodPut, "/scim/v2/Users/"+userID, map[string]any{
		"schemas": []string{scimUserSchema}, "userName": "alice", "active": true,
	}, token, false)
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	// Unsupported PATCH path is refused rather than ignored.
	badPatch := h.do(http.MethodPatch, "/scim/v2/Users/"+userID, map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{
			{"op": "add", "path": "roles[primary eq true].value", "value": "admin"},
		},
	}, token, false)
	require.Equal(t, http.StatusBadRequest, badPatch.Code, badPatch.Body.String())

	// Deprovisioning removes the mapping and the membership, not the account.
	del := h.do(http.MethodDelete, "/scim/v2/Users/"+userID, nil, token, false)
	require.Equal(t, http.StatusNoContent, del.Code, del.Body.String())
	get := h.do(http.MethodGet, "/scim/v2/Users/"+userID, nil, token, false)
	require.Equal(t, http.StatusNotFound, get.Code, get.Body.String())
}

func TestSCIMTenantBoundaryAndGroupMembership(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgA := orgByCode(t, h, "scim-a")
	orgB := orgByCode(t, h, "scim-b")
	tokenA, tokenRow := scimToken(t, h, orgA, "idp-a")
	tokenB, _ := scimToken(t, h, orgB, "idp-b")

	userA := scimCreateUser(t, h, tokenA, "tenant-a-user", "a@example.com", "a-1")
	userB := scimCreateUser(t, h, tokenB, "tenant-b-user", "b@example.com", "b-1")

	// A's token cannot see B's user id, and B's token cannot see A's.
	rec := h.do(http.MethodGet, "/scim/v2/Users/"+userB["id"].(string), nil, tokenA, false)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	rec = h.do(http.MethodDelete, "/scim/v2/Users/"+userA["id"].(string), nil, tokenB, false)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// An e-mail that already belongs to another tenant must not be silently
	// attached to this one, even with a fresh externalId.
	rec = h.do(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas": []string{scimUserSchema}, "userName": "impostor",
		"externalId": "a-2",
		"emails":     []map[string]any{{"value": "b@example.com", "primary": true}},
		"active":     true,
	}, tokenA, false)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// Groups may only contain users provisioned into THIS tenant.
	group := h.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{scimGroupSchema},
		"displayName": "Finance",
		"externalId":  "fin-1",
		"members":     []map[string]any{{"value": userA["id"]}},
	}, tokenA, false)
	require.Equal(t, http.StatusCreated, group.Code, group.Body.String())
	groupID := decode[map[string]any](t, group)["id"].(string)

	badGroup := h.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{scimGroupSchema},
		"displayName": "Cross tenant",
		"externalId":  "fin-2",
		"members":     []map[string]any{{"value": userB["id"]}},
	}, tokenA, false)
	require.Equal(t, http.StatusBadRequest, badGroup.Code, badGroup.Body.String())

	// PATCH add/remove members.
	patched := h.do(http.MethodPatch, "/scim/v2/Groups/"+groupID, map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{
			{"op": "remove", "path": "members", "value": []map[string]any{{"value": userA["id"]}}},
		},
	}, tokenA, false)
	require.Equal(t, http.StatusOK, patched.Code, patched.Body.String())

	// Disabling the token immediately closes the whole protocol surface.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	disable := h.do(http.MethodPost, "/api/v1/admin/scim/tokens/"+tokenRow["id"].(string)+":disable", map[string]any{
		"expected_revision": tokenRow["revision"], "reason": "incident response",
	}, "", true)
	require.Equal(t, http.StatusOK, disable.Code, disable.Body.String())
	after := h.do(http.MethodGet, "/scim/v2/Users", nil, tokenA, false)
	require.Equal(t, http.StatusUnauthorized, after.Code, after.Body.String())
}

func TestSCIMTokenGovernanceDenials(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "scim-gov")
	_, _ = scimToken(t, h, orgID, "primary")

	// reason is mandatory on every credential write.
	noReason := h.do(http.MethodPost, "/api/v1/admin/scim/tokens", map[string]any{
		"organization_id": orgID, "name": "no-reason",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, noReason.Code, noReason.Body.String())

	// A non-platform account cannot issue a token for any tenant.
	_ = iamFixtureUser(t, h, "scim-outsider")
	require.Equal(t, http.StatusOK, h.login("scim-outsider", "FixturePass-123").Code)
	fixtureStepUp(h)
	denied := h.do(http.MethodPost, "/api/v1/admin/scim/tokens", map[string]any{
		"organization_id": orgID, "name": "escalation", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())

	// The token value is never echoed by the list endpoint.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	list := h.do(http.MethodGet, "/api/v1/admin/scim/tokens?organization_id="+orgID, nil, "", false)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.NotContains(t, list.Body.String(), "ucs_")
	require.NotContains(t, list.Body.String(), "token_hash")
}

func TestSCIMPreservesPlatformIdentityAndLastOwner(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "scim-owner")
	token, _ := scimToken(t, h, orgID, "directory")
	created := scimCreateUser(t, h, token, "root", "root@example.com", "root-in-directory")
	path := "/scim/v2/Users/" + created["id"].(string)

	profile := h.do(http.MethodPatch, path, map[string]any{
		"schemas":    []string{scimPatchSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "emails.value", "value": "new@example.com"}},
	}, token, false)
	require.Equal(t, http.StatusBadRequest, profile.Code, profile.Body.String())
	require.Contains(t, profile.Body.String(), "mutability")
	root, err := h.svc.Users.GetByUsername(context.Background(), nil, "root")
	require.NoError(t, err)
	require.Equal(t, "root@example.com", root.Email)

	disable := h.do(http.MethodPatch, path, map[string]any{
		"schemas":    []string{scimPatchSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}, token, false)
	require.Equal(t, http.StatusConflict, disable.Code, disable.Body.String())
	remove := h.do(http.MethodDelete, path, nil, token, false)
	require.Equal(t, http.StatusConflict, remove.Code, remove.Body.String())
	current := h.do(http.MethodGet, path, nil, token, false)
	require.Equal(t, http.StatusOK, current.Code, current.Body.String())
	require.Equal(t, true, decode[map[string]any](t, current)["active"])
}

func TestSCIMGroupReplacementAndConditionalWrites(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "scim-groups-etag")
	token, _ := scimToken(t, h, orgID, "directory")
	alice := scimCreateUser(t, h, token, "group-alice", "alice@example.com", "alice")
	bob := scimCreateUser(t, h, token, "group-bob", "bob@example.com", "bob")
	group := h.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas": []string{scimGroupSchema}, "displayName": "Project",
		"members": []map[string]any{{"value": alice["id"]}, {"value": bob["id"]}},
	}, token, false)
	require.Equal(t, http.StatusCreated, group.Code, group.Body.String())
	path := "/scim/v2/Groups/" + decode[map[string]any](t, group)["id"].(string)
	oldTag := group.Header().Get("ETag")
	replaced := scimDoRaw(h, http.MethodPut, path, token, map[string]any{
		"schemas": []string{scimGroupSchema}, "displayName": "Project", "externalId": "remapped-project",
		"members": []map[string]any{{"value": alice["id"]}},
	}, map[string]string{"If-Match": oldTag})
	require.Equal(t, http.StatusOK, replaced.Code, replaced.Body.String())
	replacedGroup := decode[map[string]any](t, replaced)
	require.Equal(t, "remapped-project", replacedGroup["externalId"])
	members := replacedGroup["members"].([]any)
	require.Len(t, members, 1)
	require.Equal(t, alice["id"], members[0].(map[string]any)["value"])
	newTag := replaced.Header().Get("ETag")
	require.NotEqual(t, oldTag, newTag)

	removed := scimDoRaw(h, http.MethodDelete, path, token, nil, map[string]string{"If-Match": oldTag})
	require.Equal(t, http.StatusPreconditionFailed, removed.Code, removed.Body.String())
	patched := scimDoRaw(h, http.MethodPatch, path, token, map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{
			{"op": "remove", "path": "members"},
			{"op": "add", "path": "members", "value": []map[string]any{{"value": bob["id"]}}},
		},
	}, map[string]string{"If-Match": newTag})
	require.Equal(t, http.StatusOK, patched.Code, patched.Body.String())
	patchTag := patched.Header().Get("ETag")
	require.NotEqual(t, newTag, patchTag)
	members = decode[map[string]any](t, patched)["members"].([]any)
	require.Len(t, members, 1)
	require.Equal(t, bob["id"], members[0].(map[string]any)["value"])

	deprovision := h.do(http.MethodDelete, "/scim/v2/Users/"+bob["id"].(string), nil, token, false)
	require.Equal(t, http.StatusNoContent, deprovision.Code, deprovision.Body.String())
	updated := h.do(http.MethodGet, path, nil, token, false)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	require.Empty(t, decode[map[string]any](t, updated)["members"])
	require.NotEqual(t, patchTag, updated.Header().Get("ETag"))
}

func TestSCIMCollectionRoutesAndProjection(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "scim-routing")
	token, _ := scimToken(t, h, orgID, "directory")
	created := scimCreateUser(t, h, token, "projection", "projection@example.com", "projection")
	path := "/scim/v2/Users/" + created["id"].(string)
	invalidItem := h.do(http.MethodGet, "/scim/v2/Users/no-such-id", nil, token, false)
	require.Equal(t, http.StatusNotFound, invalidItem.Code, invalidItem.Body.String())
	unsupported := h.do(http.MethodGet, path+"?excludedAttributes=emails.value", nil, token, false)
	require.Equal(t, http.StatusBadRequest, unsupported.Code, unsupported.Body.String())
	require.NotContains(t, unsupported.Body.String(), "projection@example.com")
	projected := h.do(http.MethodGet, path+"?excludedAttributes=EMAILS,id", nil, token, false)
	require.Equal(t, http.StatusOK, projected.Code, projected.Body.String())
	result := decode[map[string]any](t, projected)
	require.NotContains(t, result, "emails")
	require.Equal(t, created["id"], result["id"])
}
