package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagementWriteRequiresReason(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "reason-org", "name": "Reason"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	orgID := decode[map[string]any](t, rec)["id"].(string)

	// The audit contract requires an explicit reason; a defaulted string hides
	// the operator's intent.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles", map[string]any{
		"code": "no_reason", "name": "No Reason", "grants": []map[string]any{},
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "reason")

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles", map[string]any{
		"code": "with_reason", "name": "With Reason", "grants": []map[string]any{}, "reason": "explicit",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestArchivedOrganizationRoleCannotChangeGrants(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "frozen-org", "name": "Frozen"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	orgID := decode[map[string]any](t, rec)["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles", map[string]any{
		"code": "temp", "name": "Temp", "reason": "create",
		"grants": []map[string]any{{"operation": "organization.audit.read", "effect": "allow", "scope": map[string]any{"all": true}}},
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	role := decode[map[string]any](t, rec)
	roleID := role["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles/"+roleID+":archive", map[string]any{
		"expected_revision": role["revision"], "reason": "archive",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPut, "/api/v1/orgs/"+orgID+"/iam/roles/"+roleID+"/permissions", map[string]any{
		"grants": []map[string]any{}, "expected_revision": "3", "reason": "edit archived",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "已归档")
}

func TestAddMemberDoesNotRevealAccountExistence(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "enum-org", "name": "Enum"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	orgID := decode[map[string]any](t, rec)["id"].(string)

	// A disabled account and an unknown account must be indistinguishable.
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "disabled_target", "email": "disabled@example.com",
		"initial_password": "DisabledPass-123", "reason": "fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	disabledID := decode[map[string]any](t, rec)["id"].(string)
	rec = h.management(http.MethodPost, "/api/v1/admin/users/"+disabledID+":set-status", map[string]any{
		"status": "disabled", "reason": "fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	unknown := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "no_such_account", "role": "member", "reason": "probe",
	}, "", true)
	disabled := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "disabled_target", "role": "member", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, unknown.Code, unknown.Body.String())
	require.Equal(t, unknown.Code, disabled.Code)
	require.Equal(t, unknown.Body.String(), disabled.Body.String())
}

func TestExplainRejectsResourceScopedRequests(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	rec := h.do(http.MethodPost, "/api/v1/admin/iam/authorization:explain", map[string]any{
		"user_id": "1", "operation": "identity.user.read", "resource_id": "42",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "资源 owner")
}
