package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

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
