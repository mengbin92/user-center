package server_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

// Organization-scoped segregation of duties (S12).
//
// The design's central claim is that a tenant can tighten its own rules but can
// never touch platform policy. These tests drive that through HTTP, because the
// boundary is enforced by three different layers (context filter, role-reference
// validation, permission code) and only an end-to-end call proves they agree.

// policyRevision reads the current policy revision, which every constraint write
// must quote. It comes from the authorization explain endpoint that already
// exposes it.
func policyRevision(t *testing.T, h *harness) string {
	t.Helper()
	rec := h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rev := decode[map[string]any](t, rec)["policy_revision"].(string)
	require.NotEmpty(t, rev)
	return rev
}

func createOrgRole(t *testing.T, h *harness, orgID, code string) string {
	t.Helper()
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles", map[string]any{
		"code": code, "name": code,
		"grants": []map[string]any{{
			"operation": "organization.audit.read", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "test role",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)["id"].(string)
}

// createOrgMemberForConstraint adds an existing user to the organization and
// returns its id. Constraint tests need a second real member because a
// self-grant is refused, so the actor cannot also be the target.
func createOrgMemberForConstraint(t *testing.T, h *harness, orgID, username string) string {
	t.Helper()
	user := iamFixtureUser(t, h, username)
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": username, "role": "member", "reason": "constraint fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return strconv.FormatInt(user.ID, 10)
}

// fixturePlatformRoles returns n existing platform role ids, for cross-context
// reference tests and for building a valid platform mutual-exclusion.
func fixturePlatformRoles(t *testing.T, h *harness, n int) []string {
	t.Helper()
	roles, err := h.svc.IAM.ListRoles(t.Context(), nil, biz.RoleFilter{})
	require.NoError(t, err)
	out := make([]string, 0, n)
	for _, r := range roles {
		// Skip rooted roles: constraints may not reference them, and a valid
		// fixture must not depend on seed ordering.
		if r.Code == "root" {
			continue
		}
		out = append(out, strconv.FormatInt(r.ID, 10))
		if len(out) == n {
			return out
		}
	}
	t.Fatalf("need %d non-root platform roles, found %d", n, len(out))
	return nil
}

func fixturePlatformRole(t *testing.T, h *harness) string {
	t.Helper()
	return fixturePlatformRoles(t, h, 1)[0]
}

func mustParseID(t *testing.T, raw string) int64 {
	t.Helper()
	v, err := strconv.ParseInt(raw, 10, 64)
	require.NoError(t, err)
	return v
}

// A platform constraint must stay invisible inside a tenant: the two role-id
// spaces are global (roles are one table), so the only thing preventing a
// platform rule from reaching a tenant is explicit context filtering.
func TestOrgConstraintIgnoresPlatformPolicy(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-tenant")
	roleX := createOrgRole(t, h, orgA, "approver")
	roleY := createOrgRole(t, h, orgA, "payer")

	// A regular member as the target: the actor (root) cannot be assigned roles.
	member := createOrgMemberForConstraint(t, h, orgA, "sod-target")

	// Both roles assigned: legal, because this tenant has no constraint yet.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": member, "role_id": roleX, "reason": "grant x",
	}, "", true).Code)

	// A platform mutual-exclusion over two platform roles must not change that.
	platformRoles := fixturePlatformRoles(t, h, 2)
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/constraints", map[string]any{
		"kind": "mutual_exclusion", "name": "platform-sod",
		"role_ids": platformRoles, "max_count": 0,
		"reason": "platform rule", "expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": member, "role_id": roleY, "reason": "grant y",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code,
		"a platform constraint must not block an organization assignment: %s", rec.Body.String())
}

// The tenant's own mutual-exclusion does block the pair, and only inside that
// tenant.
func TestOrgConstraintBlocksMutuallyExclusiveRoles(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-a")
	orgB := orgByCode(t, h, "sod-b")
	roleX := createOrgRole(t, h, orgA, "approver")
	roleY := createOrgRole(t, h, orgA, "payer")
	memberA := createOrgMemberForConstraint(t, h, orgA, "sod-a-target")

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/constraints", map[string]any{
		"kind": "mutual_exclusion", "name": "no-approve-and-pay",
		"role_ids": []string{roleX, roleY}, "enabled": true,
		"reason": "SoD", "expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberA, "role_id": roleX, "reason": "grant x",
	}, "", true).Code)

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": memberA, "role_id": roleY, "reason": "grant y",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "ROLE_CONSTRAINT_VIOLATION")

	// Tenant B is unaffected even though it uses the same role codes: the rule
	// belongs to tenant A only.
	roleXB := createOrgRole(t, h, orgB, "approver")
	roleYB := createOrgRole(t, h, orgB, "payer")
	memberB := createOrgMemberForConstraint(t, h, orgB, "sod-b-target")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgB+"/iam/assignments", map[string]any{
		"user_id": memberB, "role_id": roleXB, "reason": "grant x",
	}, "", true).Code)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgB+"/iam/assignments", map[string]any{
		"user_id": memberB, "role_id": roleYB, "reason": "grant y",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, "tenant A's rule must not apply in tenant B: %s", rec.Body.String())
}

// A tenant may not write a rule over a role it does not own. Allowing it would
// let an org admin reshape platform decisions through policy, which is exactly
// the escalation this design exists to prevent.
func TestOrgConstraintRejectsForeignRole(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-x")
	platformRole := fixturePlatformRole(t, h)

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/constraints", map[string]any{
		"kind": "mutual_exclusion", "name": "cross-context", "role_ids": []string{platformRole},
		"enabled": true, "reason": "attempt escalation",
		"expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "VALIDATION_FAILED")
}

// Another tenant's constraint id must look like it does not exist, and its
// rules must not apply. 403 would confirm the id exists somewhere.
func TestOrgConstraintCrossTenantIsNotFound(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-owner-a")
	orgB := orgByCode(t, h, "sod-owner-b")
	roleX := createOrgRole(t, h, orgA, "approver")
	roleY := createOrgRole(t, h, orgA, "payer")

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/constraints", map[string]any{
		"kind": "mutual_exclusion", "name": "a-only", "role_ids": []string{roleX, roleY},
		"enabled": true, "reason": "SoD", "expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	constraintID := decode[map[string]any](t, rec)["id"].(string)

	// Tenant B lists nothing.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/iam/constraints", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Empty(t, decode[map[string]any](t, rec)["items"],
		"tenant B must not see tenant A's constraint")

	// Tenant B cannot patch or delete it either.
	rec = h.do(http.MethodPatch, "/api/v1/orgs/"+orgB+"/iam/constraints/"+constraintID, map[string]any{
		"name": "hijacked", "role_ids": []string{}, "enabled": false,
		"expected_revision": "1", "reason": "cross tenant",
		"expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgB+"/iam/constraints/"+constraintID+
		"?expected_revision=1&reason=cross&expected_policy_revision="+policyRevision(t, h), nil, "", true)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// A member may not grant themselves a role. Without this, "org defines its own
// constraints" plus "org can self-grant" means the constraints are decorative.
func TestOrgSelfGrantIsRefused(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-self")
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	roleX := createOrgRole(t, h, orgA, "self-grant-target")

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": strconv.FormatInt(root.ID, 10), "role_id": roleX, "reason": "self grant",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "ORGANIZATION_SELF_GRANT")
}

// A tightening edit that invalidates existing assignments must be acknowledged
// first: organization permissions are recomputed per request, so the affected
// members lose access immediately rather than at their next login.
func TestOrgConstraintTighteningRequiresAcknowledgement(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-tighten")
	roleX := createOrgRole(t, h, orgA, "role-x")
	roleY := createOrgRole(t, h, orgA, "role-y")
	member := createOrgMemberForConstraint(t, h, orgA, "tighten-target")

	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": member, "role_id": roleX, "reason": "grant x",
	}, "", true).Code)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/assignments", map[string]any{
		"user_id": member, "role_id": roleY, "reason": "grant y",
	}, "", true).Code)

	body := map[string]any{
		"kind": "mutual_exclusion", "name": "late-sod", "role_ids": []string{roleX, roleY},
		"enabled": true, "reason": "tighten", "expected_policy_revision": policyRevision(t, h),
	}
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/constraints", body, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "ORGANIZATION_POLICY_VIOLATIONS_PENDING")

	// Refusing must not have written anything.
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/iam/constraints", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, decode[map[string]any](t, rec)["items"], "a rejected constraint must not be stored")

	// With the acknowledgement the same write succeeds and reports the count.
	body["acknowledge_violations"] = true
	body["expected_policy_revision"] = policyRevision(t, h)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/constraints", body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "1", decode[map[string]any](t, rec)["violating_assignments"])
}

// Removing a member must also invalidate the delegations involving them. Only
// the assignment half existed before V2.5.
func TestOrgMemberRemovalInvalidatesDelegations(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "sod-delegation")
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	member := createOrgMemberForConstraint(t, h, orgA, "delegation-target")
	memberID, err := strconv.ParseInt(member, 10, 64)
	require.NoError(t, err)
	managerRole := orgRoleID(t, h, orgA, "org_owner")
	targetRole := createOrgRole(t, h, orgA, "delegated-role")
	targetRoleID, err := strconv.ParseInt(targetRole, 10, 64)
	require.NoError(t, err)
	managerRoleID, err := strconv.ParseInt(managerRole, 10, 64)
	require.NoError(t, err)

	orgCtx := authorization.Organization(mustParseID(t, orgA))
	now := time.Now().UTC()
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: managerRoleID, TargetRoleID: targetRoleID, TargetKind: "role",
		Actions:         []string{biz.DelegationActionAssign},
		TargetUserScope: authorization.Scope{UserIDs: []int64{memberID}},
		GrantCeiling:    []biz.DelegationCeiling{{Operation: "organization.audit.read", Scope: authorization.Scope{All: true}}},
		StartsAt:        now, CreatedBy: root.ID, Context: orgCtx,
	})
	require.NoError(t, err)

	// Removing the member must revoke it in the same transaction.
	members := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/members", nil, "", false))
	targetRevision := "1"
	for _, raw := range members["items"].([]any) {
		item := raw.(map[string]any)
		if item["user_id"] == member || item["id"] == member {
			targetRevision = item["revision"].(string)
		}
	}
	rec := h.do(http.MethodDelete, "/api/v1/orgs/"+orgA+"/members/"+member+
		"?expected_revision="+targetRevision+"&reason=remove", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	active, err := h.svc.IAM.ListDelegations(t.Context(), nil, biz.DelegationFilter{
		Status: "active", Context: orgCtx,
	})
	require.NoError(t, err)
	require.Empty(t, active, "removing a member must invalidate delegations targeting them")
}
