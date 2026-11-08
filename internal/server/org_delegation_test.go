package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

// createOrgRoleWithGrants creates a custom organization role carrying exactly
// the supplied operations.
func createOrgRoleWithGrants(t *testing.T, h *harness, orgID, code string, operations ...string) string {
	t.Helper()
	grants := make([]map[string]any, 0, len(operations))
	for _, op := range operations {
		grants = append(grants, map[string]any{
			"operation": op, "effect": "allow", "scope": map[string]any{"all": true},
		})
	}
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/roles", map[string]any{
		"code": code, "name": code, "grants": grants, "reason": "delegation fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)["id"].(string)
}

func joinOrg(t *testing.T, h *harness, orgID, username, role string) string {
	t.Helper()
	user := iamFixtureUser(t, h, username)
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": username, "role": role, "reason": "delegation fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return strconv.FormatInt(user.ID, 10)
}

func assignOrgRole(t *testing.T, h *harness, orgID, userID, roleID string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/assignments", map[string]any{
		"user_id": userID, "role_id": roleID, "reason": "delegation fixture",
	}, "", true)
}

// Holding organization.iam.assignment.manage is not authority over the roles it
// can reach. Before this check existed, a member with only that operation could
// grant the audit role -- authority they did not hold and had not been delegated.
//
// The fix is the platform rule, applied to organization facts: direct capability
// plus the assignment operation, or an active delegation in this tenant.
// revokeBeforeTx runs fn exactly once, immediately before the first transaction
// started through it. It reproduces the window between orgGuard (which checks the
// operation before the transaction opens) and the write itself.
type revokeBeforeTx struct {
	inner biz.TxManager
	fn    func() error
	once  sync.Once
	ran   bool
	err   error
}

func (r *revokeBeforeTx) InTx(ctx context.Context, fn func(context.Context, biz.Tx) error) error {
	r.once.Do(func() {
		r.ran = true
		r.err = r.fn()
	})
	if r.err != nil {
		return r.err
	}
	return r.inner.InTx(ctx, fn)
}
func TestRevokedPermissionIsRecheckedInsideTheWriteTransaction(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "recheck-tenant")
	assignerRole := createOrgRoleWithGrants(t, h, orgID, "assigner", biz.PermOrgAssignmentManage)
	auditRole := createOrgRoleWithGrants(t, h, orgID, "auditor", biz.PermOrgAuditRead)
	actorUser := joinOrg(t, h, orgID, "recheck-actor", "member")
	target := joinOrg(t, h, orgID, "recheck-target", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, actorUser, assignerRole).Code)
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, actorUser, auditRole).Code)

	require.Equal(t, http.StatusOK, h.login("recheck-actor", "FixturePass-123").Code)
	fixtureStepUp(h)

	// Just before the write transaction starts, another actor (root) revokes the
	// one permission this request was authorised by.
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	wrapped := &revokeBeforeTx{
		inner: h.svc.Tx,
		fn: func() error {
			_, rerr := h.svc.OrgIAM.RevokeMemberAssignments(t.Context(), nil,
				authorization.Organization(mustParseID(t, orgID)), mustParseID(t, actorUser),
				[]int64{mustParseID(t, assignerRole)}, root.ID)
			return rerr
		},
	}
	h.svc.Tx = wrapped
	t.Cleanup(func() { h.svc.Tx = wrapped.inner })

	rec := assignOrgRole(t, h, orgID, target, auditRole)
	require.True(t, wrapped.ran, "fixture invalid: the revocation never ran before the transaction")
	require.NoError(t, wrapped.err)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"the write must not survive the revocation of the permission it was authorised by: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")

	// Nothing was written (the built-in membership assignment is expected; the
	// audit role is not).
	items, err := h.svc.OrgIAM.ListAssignments(t.Context(), nil,
		authorization.Organization(mustParseID(t, orgID)), mustParseID(t, target))
	require.NoError(t, err)
	for _, item := range items {
		if item.Assignment == nil {
			continue
		}
		require.NotEqual(t, mustParseID(t, auditRole), item.Assignment.RoleID,
			"a rejected request must not have granted the target role")
	}
}

// D7 removed the platform bypass for the *constraint* endpoints only. The older
// organization role-management path keeps it: a platform administrator acting on
// a tenant is a deliberate, audited governance capability, and the new capability
// check must not silently close it.
func TestPlatformAdminKeepsOrganizationRoleGovernance(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "gov-tenant")
	// The user exists but is not a member yet: adding them is the governance call
	// under test.
	targetUser := iamFixtureUser(t, h, "gov-target")
	target := strconv.FormatInt(targetUser.ID, 10)

	// Hand the tenant over and leave: root becomes a platform administrator who
	// is not a member of this organization.
	iamFixtureUser(t, h, "gov-owner")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "gov-owner", "role": "owner", "reason": "hand over",
	}, "", true).Code)
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	member, err := h.svc.Organizations.GetMember(t.Context(), nil, mustParseID(t, orgID), root.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.Organizations.RemoveMember(t.Context(), nil, mustParseID(t, orgID), root.ID, member.Revision))

	// Governance still works for the non-member platform administrator.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "gov-target", "role": "member", "reason": "governance",
	}, "", true).Code)

	roleID := createOrgRoleWithGrants(t, h, orgID, "gov-auditor", biz.PermOrgAuditRead)
	rec := assignOrgRole(t, h, orgID, target, roleID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	listRec := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/assignments", nil, "", false)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var assignmentID, revision string
	for _, raw := range decode[map[string]any](t, listRec)["items"].([]any) {
		item := raw.(map[string]any)
		if item["user_id"] == target && item["role_id"] == roleID {
			assignmentID = item["id"].(string)
			revision = item["revision"].(string)
		}
	}
	require.NotEmpty(t, assignmentID)
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/iam/assignments/"+assignmentID+
		"?expected_revision="+revision+"&reason=governance+revoke", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// D10: a removed member must not regain their delegation by rejoining and being
// granted the same role again. The manager side of the revocation is therefore
// derived from the role losing its last holder, not from created_by (which is the
// issuer, not the manager).
func TestOrgAssignmentRequiresCapabilityOrDelegation(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "bnd-tenant")
	delegatorRole := createOrgRoleWithGrants(t, h, orgID, "delegator", biz.PermOrgAssignmentManage)
	auditorRole := createOrgRoleWithGrants(t, h, orgID, "auditor", biz.PermOrgAuditRead)

	delegatorUser := joinOrg(t, h, orgID, "bnd-delegator", "member")
	target := joinOrg(t, h, orgID, "bnd-target", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	// As the delegator: assignment.manage alone is not enough.
	require.Equal(t, http.StatusOK, h.login("bnd-delegator", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec := assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// A delegation issued in another context (platform) must not unlock it.
	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	now := time.Now().UTC()
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: mustParseID(t, delegatorRole), TargetRoleID: mustParseID(t, auditorRole),
		TargetKind: "role", Actions: []string{biz.DelegationActionAssign},
		TargetUserScope: authorization.Scope{UserIDs: []int64{mustParseID(t, target)}},
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: biz.PermOrgAuditRead, Scope: authorization.Scope{All: true},
		}},
		StartsAt: now.Add(-time.Minute), CreatedBy: root.ID, Context: authorization.Platform(),
	})
	require.NoError(t, err)
	rec = assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"a platform delegation must not authorise an organization assignment: %s", rec.Body.String())

	// The same delegation in this tenant does unlock it.
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: mustParseID(t, delegatorRole), TargetRoleID: mustParseID(t, auditorRole),
		TargetKind: "role", Actions: []string{biz.DelegationActionAssign},
		TargetUserScope: authorization.Scope{UserIDs: []int64{mustParseID(t, target)}},
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: biz.PermOrgAuditRead, Scope: authorization.Scope{All: true},
		}},
		StartsAt: now.Add(-time.Minute), CreatedBy: root.ID,
		Context: authorization.Organization(mustParseID(t, orgID)),
	})
	require.NoError(t, err)
	rec = assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// The delegation's own window and ceiling bound what it can authorise.
func TestOrgDelegationWindowAndCeilingAreEnforced(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "bnd-window")
	delegatorRole := createOrgRoleWithGrants(t, h, orgID, "delegator", biz.PermOrgAssignmentManage)
	auditorRole := createOrgRoleWithGrants(t, h, orgID, "auditor", biz.PermOrgAuditRead)
	delegatorUser := joinOrg(t, h, orgID, "win-delegator", "member")
	target := joinOrg(t, h, orgID, "win-target", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	now := time.Now().UTC()

	// Ceiling too narrow: covers a different operation than the role grants.
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: mustParseID(t, delegatorRole), TargetRoleID: mustParseID(t, auditorRole),
		TargetKind: "role", Actions: []string{biz.DelegationActionAssign},
		TargetUserScope: authorization.Scope{UserIDs: []int64{mustParseID(t, target)}},
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: biz.PermOrgMemberRead, Scope: authorization.Scope{All: true},
		}},
		StartsAt: now.Add(-time.Minute), CreatedBy: root.ID,
		Context: authorization.Organization(mustParseID(t, orgID)),
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, h.login("win-delegator", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec := assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"a ceiling over a different operation must not cover the grant: %s", rec.Body.String())
}

// A delegation is bounded on four axes, and each one has to be checked: who it
// covers, which role, which action, and when. A delegation that covers the right
// role but the wrong person (or an expired window) must not authorise anything.
func TestOrgDelegationScopeIsEnforcedExactly(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "bnd-scope")
	delegatorRole := createOrgRoleWithGrants(t, h, orgID, "delegator", biz.PermOrgAssignmentManage)
	auditorRole := createOrgRoleWithGrants(t, h, orgID, "auditor", biz.PermOrgAuditRead)
	delegatorUser := joinOrg(t, h, orgID, "scope-delegator", "member")
	covered := joinOrg(t, h, orgID, "scope-covered", "member")
	other := joinOrg(t, h, orgID, "scope-other", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	now := time.Now().UTC()
	orgCtx := authorization.Organization(mustParseID(t, orgID))
	delegate := func(scope authorization.Scope, actions []string, starts time.Time, expires *time.Time) {
		t.Helper()
		_, err := h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
			ManagerRoleID: mustParseID(t, delegatorRole), TargetRoleID: mustParseID(t, auditorRole),
			TargetKind: "role", Actions: actions, TargetUserScope: scope,
			GrantCeiling: []biz.DelegationCeiling{{
				Operation: biz.PermOrgAuditRead, Scope: authorization.Scope{All: true},
			}},
			StartsAt: starts, ExpiresAt: expires, CreatedBy: root.ID, Context: orgCtx,
		})
		require.NoError(t, err)
	}

	require.Equal(t, http.StatusOK, h.login("scope-delegator", "FixturePass-123").Code)
	fixtureStepUp(h)

	// Wrong person: the delegation names somebody else.
	delegate(authorization.Scope{UserIDs: []int64{mustParseID(t, covered)}},
		[]string{biz.DelegationActionAssign}, now.Add(-time.Minute), nil)
	rec := assignOrgRole(t, h, orgID, other, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"a delegation for another user must not authorise this one: %s", rec.Body.String())

	// Expired window.
	delegate(authorization.Scope{UserIDs: []int64{mustParseID(t, other)}},
		[]string{biz.DelegationActionAssign}, now.Add(-2*time.Hour), ptrTime(now.Add(-time.Hour)))
	rec = assignOrgRole(t, h, orgID, other, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"an expired delegation must not authorise anything: %s", rec.Body.String())

	// Wrong action: the delegation only covers assignment, so revocation is not
	// implied. Grant the role as root (who may), then let the delegator try to
	// undo it -- the delegator holds assignment.manage but no revoke delegation.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, covered, auditorRole).Code)
	listRec := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/assignments", nil, "", false)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var assignmentID, revision string
	for _, raw := range decode[map[string]any](t, listRec)["items"].([]any) {
		item := raw.(map[string]any)
		if item["user_id"] == covered && item["role_id"] == auditorRole {
			assignmentID = item["id"].(string)
			revision = item["revision"].(string)
		}
	}
	require.NotEmpty(t, assignmentID, "fixture must have granted the audit role")

	require.Equal(t, http.StatusOK, h.login("scope-delegator", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/iam/assignments/"+assignmentID+
		"?expected_revision="+revision+"&reason=delegator+revoke", nil, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"an assign-only delegation must not authorise a revoke: %s", rec.Body.String())
}

func TestRemovedMemberDoesNotRegainDelegationAfterRejoining(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	orgID := orgByCode(t, h, "lifecycle-tenant")
	delegatorRole := createOrgRoleWithGrants(t, h, orgID, "delegator", biz.PermOrgAssignmentManage)
	auditorRole := createOrgRoleWithGrants(t, h, orgID, "auditor", biz.PermOrgAuditRead)
	delegatorUser := joinOrg(t, h, orgID, "life-manager", "member")
	target := joinOrg(t, h, orgID, "life-target", "member")
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	root, err := h.svc.Users.GetByUsername(t.Context(), nil, "root")
	require.NoError(t, err)
	now := time.Now().UTC()
	orgCtx := authorization.Organization(mustParseID(t, orgID))
	_, err = h.svc.IAM.CreateDelegation(t.Context(), nil, &biz.Delegation{
		ManagerRoleID: mustParseID(t, delegatorRole), TargetRoleID: mustParseID(t, auditorRole),
		TargetKind: "role", Actions: []string{biz.DelegationActionAssign},
		TargetUserScope: authorization.Scope{UserIDs: []int64{mustParseID(t, target)}},
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: biz.PermOrgAuditRead, Scope: authorization.Scope{All: true},
		}},
		StartsAt: now.Add(-time.Minute), CreatedBy: root.ID, Context: orgCtx,
	})
	require.NoError(t, err)

	// Remove the member through the real endpoint, then put them back with the
	// same role.
	members := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false))
	revision := "1"
	for _, raw := range members["items"].([]any) {
		item := raw.(map[string]any)
		if item["user_id"] == delegatorUser || item["id"] == delegatorUser {
			revision = item["revision"].(string)
		}
	}
	rec := h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/members/"+delegatorUser+
		"?expected_revision="+revision+"&reason=offboarding", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "life-manager", "role": "member", "reason": "rehired",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, assignOrgRole(t, h, orgID, delegatorUser, delegatorRole).Code)

	// The pre-removal delegation must stay dead.
	active, err := h.svc.IAM.ListDelegations(t.Context(), nil, biz.DelegationFilter{Status: "active", Context: orgCtx})
	require.NoError(t, err)
	require.Empty(t, active, "a delegation must not survive its manager leaving the tenant")

	require.Equal(t, http.StatusOK, h.login("life-manager", "FixturePass-123").Code)
	fixtureStepUp(h)
	rec = assignOrgRole(t, h, orgID, target, auditorRole)
	require.Equal(t, http.StatusForbidden, rec.Code,
		"rejoining must not restore the old delegation: %s", rec.Body.String())
}
