package server_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
)

func orgByCode(t *testing.T, h *harness, code string) string {
	t.Helper()
	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": code, "name": code}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)["id"].(string)
}

func orgRoleID(t *testing.T, h *harness, orgID, code string) string {
	t.Helper()
	rec := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/roles", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	items := decode[map[string]any](t, rec)["items"].([]any)
	for _, raw := range items {
		role := raw.(map[string]any)
		if role["code"] == code {
			return role["id"].(string)
		}
	}
	t.Fatalf("role %s not found in organization %s", code, orgID)
	return ""
}

func TestOrganizationIAMTenantIsolation(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "tenant-a")
	orgB := orgByCode(t, h, "tenant-b")

	// Every organization materializes the built-in role set in its own tenant.
	ownerRole := orgRoleID(t, h, orgA, "org_owner")
	orgRoleID(t, h, orgA, "org_admin")
	orgRoleID(t, h, orgA, "org_member")

	// A custom tenant role may only reference organization-scoped permissions.
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/roles", map[string]any{
		"code": "auditor", "name": "审计员",
		"grants": []map[string]any{{
			"operation": "organization.audit.read", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "tenant auditor",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	auditorRole := decode[map[string]any](t, rec)["id"].(string)

	// A platform permission cannot be granted through an organization role.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/roles", map[string]any{
		"code":   "escalate",
		"name":   "escalate",
		"grants": []map[string]any{{"operation": "identity.user.archive", "effect": "allow", "scope": map[string]any{"all": true}}},
		"reason": "attempt platform escalation",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// Built-in roles are immutable.
	rec = h.do(http.MethodPut, "/api/v1/orgs/"+orgA+"/iam/roles/"+ownerRole+"/permissions", map[string]any{
		"grants": []map[string]any{}, "expected_revision": "1", "reason": "strip owner",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// A role from another tenant is not visible or assignable.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgB+"/iam/roles", map[string]any{
		"code": "auditor", "name": "审计员",
		"grants": []map[string]any{{
			"operation": "organization.audit.read", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "second tenant auditor",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	foreignRole := decode[map[string]any](t, rec)["id"].(string)

	member := iamFixtureUser(t, h, "tenant_member")
	memberID := strconv.FormatInt(member.ID, 10)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/members", map[string]any{
		"identifier": "tenant_member", "role": "member", "reason": "add",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberID, "role_id": foreignRole, "reason": "cross tenant",
	}, "", true)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// Assign the tenant auditor role to the member.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberID, "role_id": auditorRole, "reason": "grant auditor",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assignmentID := decode[map[string]any](t, rec)["id"].(string)

	// A custom role can grant management operations, not just reads.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/roles", map[string]any{
		"code": "ops", "name": "运营",
		"grants": []map[string]any{{
			"operation": "organization.department.manage", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "tenant operations",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	opsRole := decode[map[string]any](t, rec)["id"].(string)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberID, "role_id": opsRole, "reason": "grant ops",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	opsAssignment := decode[map[string]any](t, rec)["id"].(string)

	// The same role cannot be granted twice to one member.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberID, "role_id": opsRole, "reason": "duplicate",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// A role in use cannot be archived.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/roles/"+auditorRole+":archive", map[string]any{
		"expected_revision": "2", "reason": "archive in use",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// ---------------------------------------------------------------------
	// Switch to the plain member: membership is the tenant boundary.
	// ---------------------------------------------------------------------
	require.Equal(t, http.StatusOK, h.login("tenant_member", "FixturePass-123").Code)

	// The custom role grants tenant audit visibility.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/audits", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "organization.member.add")

	// A different custom role grants department management.
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/departments", map[string]any{
		"code": "ops-dept", "name": "Ops",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// ... but does not widen anything else inside the tenant.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/iam/roles", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/iam/assignments", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// Another tenant is invisible, including its audit trail.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/iam/roles", nil, "", false)
	require.True(t, rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/audits", nil, "", false)
	require.True(t, rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/members", nil, "", false)
	require.True(t, rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound, rec.Body.String())

	// ---------------------------------------------------------------------
	// Back as the owner: revoke the custom role, then the role may be archived.
	// ---------------------------------------------------------------------
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgA+"/iam/assignments/"+assignmentID+"?expected_revision=1&reason=revoke", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgA+"/iam/assignments/"+opsAssignment+"?expected_revision=1&reason=revoke", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/roles/"+auditorRole+":archive", map[string]any{
		"expected_revision": "2", "reason": "archive role",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Tenant audit stays scoped: org B events never appear in org A.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/audits", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "second tenant auditor")
	bItems := decode[map[string]any](t, rec)["items"].([]any)
	require.NotEmpty(t, bItems)
	for _, raw := range bItems {
		target := raw.(map[string]any)["target"].(string)
		require.NotEqual(t, orgA, target, "tenant B audit leaked an event from tenant A")
	}
}

func TestOrganizationMembershipRoleDrivesBuiltInAssignment(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "role-sync")
	user := iamFixtureUser(t, h, "sync_member")
	userID := strconv.FormatInt(user.ID, 10)

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "sync_member", "role": "member", "reason": "add",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Regression: the member list must carry ids and roles (the embedded PO
	// scan used to drop them and returned zero values).
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	listed := decode[map[string]any](t, rec)["items"].([]any)
	var first map[string]any
	for _, raw := range listed {
		if item := raw.(map[string]any); item["user_id"] == userID {
			first = item
		}
	}
	require.NotNil(t, first)
	require.Equal(t, "member", first["role"])
	require.NotEqual(t, "0", first["id"])

	roleOf := func() string {
		rec := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/assignments", nil, "", false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		items := decode[map[string]any](t, rec)["items"].([]any)
		for _, raw := range items {
			item := raw.(map[string]any)
			if item["user_id"] == userID && item["status"] == "active" {
				return item["role_code"].(string)
			}
		}
		return ""
	}
	require.Equal(t, "org_member", roleOf())

	// Promoting the membership role replaces the built-in assignment.
	rec = h.do(http.MethodPatch, "/api/v1/orgs/"+orgID+"/members/"+userID, map[string]any{
		"role": "admin", "expected_revision": "1", "reason": "promote",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "org_admin", roleOf())

	// Removing the member revokes every organization grant.
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/members/"+userID+"?expected_revision=2&reason=remove", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "", roleOf())
}

func TestLegacyOrganizationGainsIAMOnFirstAccess(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	// Simulate an organization created before V2.3: membership exists, no IAM.
	ctx := context.Background()
	org, err := h.svc.Organizations.CreateOrganization(ctx, nil, &biz.Organization{Code: "legacy-org", Name: "Legacy"})
	require.NoError(t, err)
	owner := iamFixtureUser(t, h, "legacy_owner")
	_, err = h.svc.Organizations.AddMember(ctx, nil, &biz.OrganizationMember{
		OrganizationID: org.ID, UserID: owner.ID, Role: biz.OrgRoleOwner, InvitedBy: owner.ID,
	})
	require.NoError(t, err)

	orgID := strconv.FormatInt(org.ID, 10)
	require.Equal(t, http.StatusOK, h.login(owner.Username, "FixturePass-123").Code)
	rec := h.do(http.MethodGet, "/api/v1/orgs/"+orgID, nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/roles", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "org_owner")
}
