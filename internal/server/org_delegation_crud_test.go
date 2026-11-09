package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

// HTTP-level coverage for the organization delegation write path.
//
// The evaluator (checkOrgDelegation) was already tested by injecting rows
// straight through the platform usecase. Those tests proved the rule, but they
// could not prove the product entry point: before this change no HTTP request
// could produce a delegation with context_type='organization', so Branch 2 was
// unreachable in production. The first test closes that gap end to end; the
// second pins the denial cases that keep the new write surface from becoming a
// cross-tenant or privilege-escalation channel.

func orgDelegationBody(managerRole, targetRole string, policy string) map[string]any {
	return map[string]any{
		"manager_role_id": managerRole,
		"target_role_id":  targetRole,
		"actions":         []string{biz.DelegationActionAssign},
		"grant_ceiling": []map[string]any{{
			"operation": biz.PermOrgAuditRead, "scope": map[string]any{"all": true},
		}},
		// The evaluator requires the delegation's window to contain the
		// assignment being written; a starts_at of "now" loses that race.
		"starts_at":                time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		"reason":                   "delegate the audit role",
		"expected_policy_revision": policy,
	}
}

// The delegation created through HTTP must actually unlock the evaluator's
// delegation branch, and revoking it must take that capability away again.
func TestOrgDelegationCRUDUnlocksAssignment(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "dlg-crud")
	delegatorRole := createOrgRoleWithGrants(t, h, orgID, "dlg-delegator", biz.PermOrgAssignmentManage)
	auditorRole := createOrgRoleWithGrants(t, h, orgID, "dlg-auditor", biz.PermOrgAuditRead)
	delegatorUser := joinOrg(t, h, orgID, "dlg-user", "member")
	target := joinOrg(t, h, orgID, "dlg-target", "member")
	target2 := joinOrg(t, h, orgID, "dlg-target2", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	// Baseline: holding assignment.manage is not authority over the audit role.
	require.Equal(t, http.StatusOK, h.login("dlg-user", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec := assignOrgRole(t, h, orgID, target2, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// The owner creates the delegation through the new HTTP entry point.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/delegations",
		orgDelegationBody(delegatorRole, auditorRole, policyRevision(t, h)), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)
	delegationID := created["id"].(string)
	revision := created["revision"].(string)
	require.NotEmpty(t, delegationID)
	require.Equal(t, "role", created["target_kind"])

	list := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/delegations", nil, "", false)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Len(t, decode[map[string]any](t, list)["items"].([]any), 1)

	// Branch 2 is now reachable in production: the same write succeeds.
	require.Equal(t, http.StatusOK, h.login("dlg-user", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec = assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Revoke through HTTP and confirm the capability disappears again.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/delegations/"+delegationID+":revoke", map[string]any{
		"expected_revision":        revision,
		"reason":                   "rotate delegation",
		"expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, true, decode[map[string]any](t, rec)["revoked"])

	require.Equal(t, http.StatusOK, h.login("dlg-user", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec = assignOrgRole(t, h, orgID, target2, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")
}

// Every way the new write surface could widen authority must be refused at the
// HTTP boundary, not only in a unit test.
func TestOrgDelegationWriteDenials(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgA := orgByCode(t, h, "dlg-deny-a")
	orgB := orgByCode(t, h, "dlg-deny-b")
	managerA := createOrgRoleWithGrants(t, h, orgA, "dlg-deny-mgr", biz.PermOrgAssignmentManage)
	roleA := createOrgRoleWithGrants(t, h, orgA, "dlg-deny-auditor", biz.PermOrgAuditRead)
	roleB := createOrgRoleWithGrants(t, h, orgB, "dlg-deny-foreign", biz.PermOrgAuditRead)
	platformRole := fixturePlatformRole(t, h)
	_ = joinOrg(t, h, orgA, "dlg-deny-member", "member")

	create := func(body map[string]any) *httptest.ResponseRecorder {
		return h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/delegations", body, "", true)
	}

	// reason is mandatory on every governance write.
	withoutReason := orgDelegationBody(managerA, roleA, policyRevision(t, h))
	delete(withoutReason, "reason")
	require.Equal(t, http.StatusBadRequest, create(withoutReason).Code,
		"a delegation without a reason must be refused")

	// A platform role id must not be referenceable from a tenant (§3.2).
	withPlatformRole := orgDelegationBody(managerA, platformRole, policyRevision(t, h))
	require.Equal(t, http.StatusBadRequest, create(withPlatformRole).Code,
		"a platform role must not be a delegation target")

	// Nor a role from another tenant.
	withForeignRole := orgDelegationBody(managerA, roleB, policyRevision(t, h))
	require.Equal(t, http.StatusBadRequest, create(withForeignRole).Code,
		"another tenant's role must not be a delegation target")

	// The ceiling must not contain authority the issuer does not hold, and a
	// platform operation is by definition outside an organization's grants.
	overreaching := orgDelegationBody(managerA, roleA, policyRevision(t, h))
	overreaching["grant_ceiling"] = []map[string]any{{
		"operation": "iam.role.update", "scope": map[string]any{"all": true},
	}}
	require.Equal(t, http.StatusBadRequest, create(overreaching).Code,
		"a ceiling over a platform operation must be refused")

	// Two-phase CAS: a policy snapshot that does not match must not be written
	// against. A large value cannot accidentally equal the live revision.
	stale := orgDelegationBody(managerA, roleA, "999999")
	require.Equal(t, http.StatusConflict, create(stale).Code,
		"a stale expected_policy_revision must be refused")

	// A member (not owner) has no write permission, and an outsider has no
	// entry point at all -- including platform administrators (D7).
	require.Equal(t, http.StatusOK, h.login("dlg-deny-member", "FixturePass-123").Code)
	fixtureStepUp(h)
	require.Equal(t, http.StatusForbidden, create(orgDelegationBody(managerA, roleA, policyRevision(t, h))).Code,
		"a non-owner member must not write delegations")

	_ = iamFixtureUser(t, h, "dlg-outsider")
	require.Equal(t, http.StatusOK, h.login("dlg-outsider", "FixturePass-123").Code)
	outsiderList := h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/iam/delegations", nil, "", false)
	require.Equal(t, http.StatusNotFound, outsiderList.Code,
		"a non-member must not even see the delegation surface: %s", outsiderList.Body.String())

	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	// A platform delegation over the same role ids must stay invisible here.
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: mustParseID(t, managerA), TargetRoleID: mustParseID(t, roleA),
		TargetKind: "role", Actions: []string{biz.DelegationActionAssign},
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: biz.PermOrgAuditRead, Scope: authorization.Scope{All: true},
		}},
		StartsAt: time.Now().UTC().Add(-time.Minute), CreatedBy: root.ID,
		Context: authorization.Platform(),
	})
	require.NoError(t, err)

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/iam/delegations",
		orgDelegationBody(managerA, roleA, policyRevision(t, h)), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)
	delegationID := created["id"].(string)
	revision := created["revision"].(string)

	list := h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/iam/delegations", nil, "", false)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Len(t, decode[map[string]any](t, list)["items"].([]any), 1,
		"the platform delegation must not leak into the tenant list")

	// The same id addressed from another tenant is "not found", for both write
	// shapes. A 403 would confirm the id exists somewhere else.
	revokeBody := map[string]any{
		"expected_revision":        revision,
		"reason":                   "cross-tenant probe",
		"expected_policy_revision": policyRevision(t, h),
	}
	foreignRevoke := h.do(http.MethodPost,
		"/api/v1/orgs/"+orgB+"/iam/delegations/"+delegationID+":revoke", revokeBody, "", true)
	require.Equal(t, http.StatusNotFound, foreignRevoke.Code, foreignRevoke.Body.String())

	foreignUpdate := h.do(http.MethodPatch,
		"/api/v1/orgs/"+orgB+"/iam/delegations/"+delegationID,
		map[string]any{
			"actions":                  []string{biz.DelegationActionAssign},
			"grant_ceiling":            []map[string]any{{"operation": biz.PermOrgAuditRead, "scope": map[string]any{"all": true}}},
			"expected_revision":        revision,
			"reason":                   "cross-tenant probe",
			"expected_policy_revision": policyRevision(t, h),
		}, "", true)
	require.Equal(t, http.StatusNotFound, foreignUpdate.Code, foreignUpdate.Body.String())

	// Revision CAS on the legitimate path.
	badRevision := h.do(http.MethodPost,
		"/api/v1/orgs/"+orgA+"/iam/delegations/"+delegationID+":revoke", map[string]any{
			"expected_revision":        "999999",
			"reason":                   "stale revision",
			"expected_policy_revision": policyRevision(t, h),
		}, "", true)
	require.Equal(t, http.StatusConflict, badRevision.Code, badRevision.Body.String())
}
