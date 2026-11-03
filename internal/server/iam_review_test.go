package server_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

func iamBody(h *harness, body map[string]any) map[string]any {
	policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(h.t, err)
	copy := map[string]any{}
	for k, v := range body {
		copy[k] = v
	}
	copy["expected_policy_revision"] = strconv.FormatUint(policy, 10)
	return copy
}

func iamFixtureUser(t *testing.T, h *harness, name string) *biz.User {
	t.Helper()
	ctx := context.Background()
	u, err := h.svc.Users.Create(ctx, nil, &biz.User{Username: name, UsernameNormalized: name, Status: biz.UserStatusEnabled})
	require.NoError(t, err)
	hash, err := biz.HashPassword("FixturePass-123")
	require.NoError(t, err)
	require.NoError(t, h.svc.Credentials.Create(ctx, nil, &biz.Credential{UserID: u.ID, PasswordHash: hash, Algorithm: "bcrypt", Revision: 1}))
	return u
}

func iamFixtureRole(t *testing.T, h *harness, code string, grants ...biz.Grant) *biz.Role {
	t.Helper()
	ctx := context.Background()
	r, err := h.svc.IAM.CreateRole(ctx, nil, &biz.Role{Code: code, Name: code, Status: biz.RoleStatusActive})
	require.NoError(t, err)
	_, err = h.svc.IAM.PutRoleGrants(ctx, nil, r.ID, grants, r.Revision)
	require.NoError(t, err)
	r, err = h.svc.IAM.GetRole(ctx, nil, r.ID)
	require.NoError(t, err)
	return r
}

func iamFixtureAssign(t *testing.T, h *harness, userID, roleID int64, scope authorization.Scope) *biz.Assignment {
	t.Helper()
	a, err := h.svc.IAM.CreateAssignment(context.Background(), nil, &biz.Assignment{UserID: userID, RoleID: roleID, Boundary: scope, StartsAt: time.Now().Add(-time.Minute), Origin: biz.OriginExplicit})
	require.NoError(t, err)
	return a
}

func TestIAMSelfScopeCannotExpandThroughAssignmentBoundary(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "scoped_actor")
	target := iamFixtureUser(t, h, "other_target")
	role := iamFixtureRole(t, h, "self_reader", biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}})
	iamFixtureAssign(t, h, actor.ID, role.ID, authorization.Scope{UserIDs: []int64{actor.ID, target.ID}})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec := h.do(http.MethodGet, "/api/v1/admin/users/"+strconv.FormatInt(target.ID, 10), nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/admin/users/"+strconv.FormatInt(actor.ID, 10), nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestIAMInheritanceFollowsAssignedRoleActivationAndStatus(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "inherited_actor")
	target := iamFixtureUser(t, h, "inherited_target")
	parent := iamFixtureRole(t, h, "parent_reader", biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	child := iamFixtureRole(t, h, "child_reader")
	_, err := h.svc.IAM.PutRoleInheritance(context.Background(), nil, child.ID, []int64{parent.ID}, child.Revision)
	require.NoError(t, err)
	iamFixtureAssign(t, h, actor.ID, child.ID, authorization.Scope{UserIDs: []int64{target.ID}})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	path := "/api/v1/admin/users/" + strconv.FormatInt(target.ID, 10)
	rec := h.do(http.MethodGet, path, nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	child, err = h.svc.IAM.GetRole(context.Background(), nil, child.ID)
	require.NoError(t, err)
	child.Status = biz.RoleStatusDisabled
	_, err = h.svc.IAM.UpdateRole(context.Background(), nil, child, child.Revision)
	require.NoError(t, err)
	rec = h.do(http.MethodGet, path, nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

func TestIAMProtectedRootCannotBeCopiedInheritedAssignedOrRevoked(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	root, err := h.svc.IAM.GetRoleByCode(context.Background(), nil, "root")
	require.NoError(t, err)
	u := iamFixtureUser(t, h, "root_target")
	rootID := strconv.FormatInt(root.ID, 10)
	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/api/v1/admin/iam/roles/" + rootID + ":copy", map[string]any{"code": "root_copy", "name": "copy", "reason": "review", "expected_revision": strconv.FormatUint(root.Revision, 10)}},
		{"/api/v1/admin/iam/roles", map[string]any{"code": "inherited_root", "name": "inherited", "inherits": []string{rootID}, "reason": "review"}},
		{"/api/v1/admin/iam/assignments", map[string]any{"user_id": strconv.FormatInt(u.ID, 10), "role_id": rootID, "reason": "review"}},
	} {
		rec := h.do(http.MethodPost, tc.path, iamBody(h, tc.body), "", true)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "PROTECTED_ACCOUNT")
	}
	rootUser, err := h.svc.Users.GetByUsername(context.Background(), nil, "root")
	require.NoError(t, err)
	assignments, err := h.svc.IAM.ListAssignmentsForUser(context.Background(), nil, rootUser.ID)
	require.NoError(t, err)
	for _, a := range assignments {
		if a.RoleID != root.ID {
			continue
		}
		rec := h.do(http.MethodPost, "/api/v1/admin/iam/assignments/"+strconv.FormatInt(a.ID, 10)+":revoke", iamBody(h, map[string]any{"reason": "review", "expected_revision": strconv.FormatUint(a.Revision, 10)}), "", true)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	}
}

func TestIAMBatchRequiresStepUpAndRollsBackCapacityFailure(t *testing.T) {
	h := newHarness(t)
	u1 := iamFixtureUser(t, h, "batch_first")
	u2 := iamFixtureUser(t, h, "batch_second")
	r := iamFixtureRole(t, h, "single_member")
	limit := int64(1)
	r.MaxMembers = &limit
	var err error
	r, err = h.svc.IAM.UpdateRole(context.Background(), nil, r, r.Revision)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	body := map[string]any{"user_ids": []string{strconv.FormatInt(u1.ID, 10), strconv.FormatInt(u2.ID, 10)}, "role_id": strconv.FormatInt(r.ID, 10), "reason": "review"}
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/assignments:batch-assign", iamBody(h, body), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "STEP_UP_REQUIRED")
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/assignments:batch-assign", iamBody(h, body), "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	count, err := h.svc.IAM.CountActiveAssignmentsForRole(context.Background(), nil, r.ID)
	require.NoError(t, err)
	require.Zero(t, count, "capacity failure must roll back the entire batch")
}

func TestIAMPolicyEditorCannotGrantCapabilitiesTheyDoNotHold(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "limited_editor")
	role := iamFixtureRole(t, h, "policy_editor", biz.Grant{Operation: "iam.role.create", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, actor.ID, role.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	sessions, err := h.svc.Sessions.ListByUser(context.Background(), nil, actor.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.StepUp.Put(context.Background(), biz.StepUpKey(sessions[0]), time.Now().Add(time.Minute)))
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/roles", iamBody(h, map[string]any{
		"code": "escalated_role", "name": "escalated", "reason": "review", "grants": []any{map[string]any{"operation": "settings.auth.update", "effect": "allow", "scope": map[string]any{"all": true}}},
	}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")
}

func TestIAMMutationRequiresReasonAndCurrentPolicyAndTargetRevisions(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	base := map[string]any{"code": "contract_role", "name": "contract", "reason": "review"}
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/roles", base, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "expected_policy_revision")
	noReason := iamBody(h, base)
	noReason["reason"] = "  "
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/roles", noReason, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "reason")
	stale := iamBody(h, base)
	stale["expected_policy_revision"] = "99999"
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/roles", stale, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "POLICY_CONFLICT")
	role := iamFixtureRole(t, h, "revision_role")
	u := iamFixtureUser(t, h, "revision_target")
	a := iamFixtureAssign(t, h, u.ID, role.ID, authorization.Scope{All: true})
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/roles/"+strconv.FormatInt(role.ID, 10)+":copy", iamBody(h, map[string]any{"code": "revision_copy", "name": "copy", "reason": "review", "expected_revision": strconv.FormatUint(role.Revision+1, 10)}), "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/assignments/"+strconv.FormatInt(a.ID, 10)+":revoke", iamBody(h, map[string]any{"reason": "review", "expected_revision": strconv.FormatUint(a.Revision+1, 10)}), "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	after, err := h.svc.IAM.GetAssignment(context.Background(), nil, a.ID)
	require.NoError(t, err)
	require.False(t, after.Revoked)
}

func TestIAMInactiveDenyAndEmptySessionRolesRemainRestrictive(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "deny_actor")
	target := iamFixtureUser(t, h, "deny_target")
	allow := iamFixtureRole(t, h, "allow_reader", biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	deny := iamFixtureRole(t, h, "deny_reader", biz.Grant{Operation: "identity.user.read", Effect: authorization.Deny, Scope: authorization.Scope{UserIDs: []int64{target.ID}}})
	iamFixtureAssign(t, h, actor.ID, allow.ID, authorization.Scope{All: true})
	iamFixtureAssign(t, h, actor.ID, deny.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec := h.do(http.MethodGet, "/api/v1/me/session-roles", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	revision := decode[map[string]any](t, rec)["revision"]
	rec = h.do(http.MethodPut, "/api/v1/me/session-roles", map[string]any{"role_ids": []string{strconv.FormatInt(allow.ID, 10)}, "expected_revision": revision}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/admin/users/"+strconv.FormatInt(target.ID, 10), nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"effect":"deny"`)
	rec = h.do(http.MethodGet, "/api/v1/me/session-roles", nil, "", false)
	revision = decode[map[string]any](t, rec)["revision"]
	rec = h.do(http.MethodPut, "/api/v1/me/session-roles", map[string]any{"role_ids": []string{}, "expected_revision": revision}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), `"effect":"allow"`)
}

func TestIAMUpdatesLoadImmutableFieldsAndConstraintDeleteChecksRevision(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	ctx := context.Background()
	permission, err := h.svc.IAM.GetPermissionByCode(ctx, nil, "audit.read")
	require.NoError(t, err)
	rec := h.do(http.MethodPatch, "/api/v1/admin/iam/permissions/"+strconv.FormatInt(permission.ID, 10), iamBody(h, map[string]any{"name": "审计查看", "category": permission.Category, "risk_level": permission.RiskLevel, "supported_scopes": permission.SupportedScopes, "expected_revision": strconv.FormatUint(permission.Revision, 10), "reason": "review"}), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"code":"audit.read"`)
	role := iamFixtureRole(t, h, "constraint_member")
	constraint, err := h.svc.IAM.CreateConstraint(ctx, nil, &biz.Constraint{Name: "capacity", Kind: "max_roles", RoleIDs: []int64{role.ID}, MaxCount: 1, Enabled: true})
	require.NoError(t, err)
	constraintPath := "/api/v1/admin/iam/constraints/" + strconv.FormatInt(constraint.ID, 10)
	rec = h.do(http.MethodPatch, constraintPath, iamBody(h, map[string]any{"name": "capacity updated", "role_ids": []string{strconv.FormatInt(role.ID, 10)}, "max_count": 2, "enabled": true, "expected_revision": strconv.FormatUint(constraint.Revision, 10), "reason": "review"}), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"kind":"max_roles"`)
	policy, err := h.svc.Policy.PolicyRevision(ctx, nil)
	require.NoError(t, err)
	rec = h.do(http.MethodDelete, constraintPath+"?expected_revision="+strconv.FormatUint(constraint.Revision, 10)+"&expected_policy_revision="+strconv.FormatUint(policy, 10)+"&reason=review", nil, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	_, err = h.svc.IAM.GetConstraint(ctx, nil, constraint.ID)
	require.NoError(t, err)
	menus, err := h.svc.IAM.ListMenus(ctx, nil)
	require.NoError(t, err)
	menu := menus[0]
	rec = h.do(http.MethodPatch, "/api/v1/admin/iam/menus/"+strconv.FormatInt(menu.ID, 10), iamBody(h, map[string]any{"name": "菜单更新", "enabled": true, "required_all": menu.RequiredAll, "required_any": menu.RequiredAny, "expected_revision": strconv.FormatUint(menu.Revision, 10), "reason": "review"}), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"route_key":"`+menu.RouteKey+`"`)
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/menus", iamBody(h, map[string]any{"route_key": "https://untrusted.invalid", "name": "invalid", "reason": "review"}), "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestIAMAssignmentPermissionDoesNotImplyAuthorityToGrantAdmin(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "assignment_only")
	manager := iamFixtureRole(t, h, "assignment_manager", biz.Grant{Operation: "iam.assignment.create", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, actor.ID, manager.ID, authorization.Scope{All: true})
	admin, err := h.svc.IAM.GetRoleByCode(context.Background(), nil, "admin")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	sessions, err := h.svc.Sessions.ListByUser(context.Background(), nil, actor.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.StepUp.Put(context.Background(), biz.StepUpKey(sessions[0]), time.Now().Add(time.Minute)))
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/assignments", iamBody(h, map[string]any{"user_id": strconv.FormatInt(actor.ID, 10), "role_id": strconv.FormatInt(admin.ID, 10), "boundary": map[string]any{"all": true}, "reason": "review"}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	roles, err := h.svc.Users.RolesForUser(context.Background(), nil, actor.ID)
	require.NoError(t, err)
	for _, r := range roles {
		require.NotEqual(t, "admin", r.Code)
	}
}

func TestIAMSimulationAddsAndRemovesHypotheticalAssignmentsWithoutPersisting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	user := iamFixtureUser(t, h, "simulated_user")
	role := iamFixtureRole(t, h, "simulated_settings_reader", biz.Grant{Operation: "settings.auth.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/authorization:simulate", map[string]any{"user_id": strconv.FormatInt(user.ID, 10), "add_role_ids": []string{strconv.FormatInt(role.ID, 10)}, "operation": "settings.auth.read"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	result := decode[map[string]any](t, rec)
	require.Equal(t, false, result["before_allowed"])
	require.Equal(t, true, result["after_allowed"])
	assignments, err := h.svc.IAM.ListAssignmentsForUser(ctx, nil, user.ID)
	require.NoError(t, err)
	require.Empty(t, assignments, "simulation must not create a real assignment")
	require.Equal(t, http.StatusOK, h.login(user.Username, "FixturePass-123").Code)
	rec = h.do(http.MethodGet, "/api/v1/admin/settings/auth", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	allow := iamFixtureRole(t, h, "simulated_allow", biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	deny := iamFixtureRole(t, h, "simulated_deny", biz.Grant{Operation: "identity.user.read", Effect: authorization.Deny, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, user.ID, allow.ID, authorization.Scope{All: true})
	iamFixtureAssign(t, h, user.ID, deny.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/authorization:simulate", map[string]any{"user_id": strconv.FormatInt(user.ID, 10), "remove_role_ids": []string{strconv.FormatInt(deny.ID, 10)}, "operation": "identity.user.read"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	result = decode[map[string]any](t, rec)
	require.Equal(t, false, result["before_allowed"])
	require.Equal(t, "DENY_MATCHED", result["before_reason"])
	require.Equal(t, true, result["after_allowed"])
	assignments, err = h.svc.IAM.ListAssignmentsForUser(ctx, nil, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 2)
	require.Equal(t, http.StatusOK, h.login(user.Username, "FixturePass-123").Code)
	rec = h.do(http.MethodGet, "/api/v1/admin/users/"+strconv.FormatInt(user.ID, 10), nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

type iamDisableAfterAuthenticationRepo struct {
	biz.UserRepo
	userID  int64
	changed bool
}

func (r *iamDisableAfterAuthenticationRepo) Get(ctx context.Context, tx biz.Tx, id int64) (*biz.User, error) {
	user, err := r.UserRepo.Get(ctx, tx, id)
	if err != nil || id != r.userID || r.changed {
		return user, err
	}
	r.changed = true
	disabled := *user
	disabled.Status = biz.UserStatusDisabled
	if _, err := r.UserRepo.Update(ctx, tx, &disabled, user.Revision); err != nil {
		return nil, err
	}
	return user, nil
}

func TestIAMRechecksIdentityAfterTransportAuthentication(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	root, err := h.svc.Users.GetByUsername(context.Background(), nil, "root")
	require.NoError(t, err)
	h.svc.Users = &iamDisableAfterAuthenticationRepo{UserRepo: h.svc.Users, userID: root.ID}
	// The middleware receives an enabled snapshot. The account is disabled
	// before the usecase guard, which must use the current database facts.
	rec := h.do(http.MethodGet, "/api/v1/admin/iam/roles", nil, "", false)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), `"items"`)
}

func TestIAMRevokedManagerRoleCannotKeepUsingDelegation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := iamFixtureUser(t, h, "delegated_actor")
	target := iamFixtureUser(t, h, "delegated_target")
	targetScope := authorization.Scope{UserIDs: []int64{target.ID}}
	manager := iamFixtureRole(t, h, "delegated_manager")
	operator := iamFixtureRole(t, h, "bounded_operator", biz.Grant{Operation: "iam.assignment.create", Effect: authorization.Allow, Scope: targetScope})
	reader := iamFixtureRole(t, h, "delegated_reader", biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}})
	managerAssignment := iamFixtureAssign(t, h, actor.ID, manager.ID, authorization.Scope{All: true})
	iamFixtureAssign(t, h, actor.ID, operator.ID, authorization.Scope{All: true})
	until := time.Now().Add(time.Hour)
	_, err := h.svc.IAM.CreateDelegation(ctx, nil, &biz.Delegation{ManagerRoleID: manager.ID, TargetRoleID: reader.ID, Actions: []string{"assign"}, TargetUserScope: targetScope, GrantCeiling: []biz.DelegationCeiling{{Operation: "identity.user.read", Scope: targetScope}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: &until})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	fixtureStepUp(h)
	// Revoke the assignment after login. Its stale session activation row must
	// not qualify as a manager role for delegation checks.
	require.NoError(t, h.svc.IAM.RevokeAssignment(ctx, nil, managerAssignment.ID, managerAssignment.Revision, actor.ID))
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/assignments", iamBody(h, map[string]any{"user_id": strconv.FormatInt(target.ID, 10), "role_id": strconv.FormatInt(reader.ID, 10), "boundary": map[string]any{"user_ids": []string{strconv.FormatInt(target.ID, 10)}}, "expires_at": time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339), "reason": "review"}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")
	assignments, err := h.svc.IAM.ListAssignmentsForUser(ctx, nil, target.ID)
	require.NoError(t, err)
	require.Empty(t, assignments)
}
