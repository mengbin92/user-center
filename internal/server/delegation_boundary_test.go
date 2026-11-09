package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

// The platform delegation contract has two halves:
//
//   - a delegation only relaxes the capability check for assigning/revoking one
//     target role, inside a target-user scope, for one action, inside its own
//     window and grant ceiling;
//   - it never becomes policy authority. Role grants and inheritance still
//     require iam.role.update plus checkGrantAuthority, and delegation CRUD
//     still requires iam.delegation.update.
//
// These are HTTP-level denial tests: the unit checks already exist, but the
// README makes a security promise that must fail closed at the transport too.
func TestPlatformDelegationOnlyAuthorizesTheBoundedAssignment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	actor := iamFixtureUser(t, h, "bounded_actor")
	target := iamFixtureUser(t, h, "bounded_target")
	other := iamFixtureUser(t, h, "bounded_other")

	manager := iamFixtureRole(t, h, "bounded_manager")
	operator := iamFixtureRole(t, h, "bounded_operator",
		biz.Grant{Operation: "iam.assignment.create", Effect: authorization.Allow, Scope: authorization.Scope{All: true}},
		biz.Grant{Operation: "iam.assignment.revoke", Effect: authorization.Allow, Scope: authorization.Scope{All: true}},
	)
	reader := iamFixtureRole(t, h, "bounded_reader",
		biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}},
	)
	otherRole := iamFixtureRole(t, h, "bounded_other_role",
		biz.Grant{Operation: "identity.user.update", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}},
	)
	expiredRole := iamFixtureRole(t, h, "bounded_expired_role",
		biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}},
	)
	ceilingRole := iamFixtureRole(t, h, "bounded_ceiling_role",
		biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}},
	)

	iamFixtureAssign(t, h, actor.ID, manager.ID, authorization.Scope{All: true})
	iamFixtureAssign(t, h, actor.ID, operator.ID, authorization.Scope{All: true})

	now := time.Now().UTC()
	targetScope := authorization.Scope{UserIDs: []int64{target.ID}}
	// The positive delegation: assign bounded_reader to bounded_target only.
	_, err := h.svc.IAM.CreateDelegation(ctx, nil, &biz.Delegation{
		ManagerRoleID: manager.ID, TargetRoleID: reader.ID, TargetKind: "role",
		Actions:         []string{biz.DelegationActionAssign},
		TargetUserScope: targetScope,
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: "identity.user.read", Scope: targetScope,
		}},
		StartsAt: now.Add(-time.Minute), ExpiresAt: ptrTime(now.Add(time.Hour)),
		CreatedBy: actor.ID, Context: authorization.Platform(),
	})
	require.NoError(t, err)

	// A delegation for another role, but already expired.
	_, err = h.svc.IAM.CreateDelegation(ctx, nil, &biz.Delegation{
		ManagerRoleID: manager.ID, TargetRoleID: expiredRole.ID, TargetKind: "role",
		Actions:         []string{biz.DelegationActionAssign},
		TargetUserScope: targetScope,
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: "identity.user.read", Scope: targetScope,
		}},
		StartsAt: now.Add(-2 * time.Hour), ExpiresAt: ptrTime(now.Add(-time.Hour)),
		CreatedBy: actor.ID, Context: authorization.Platform(),
	})
	require.NoError(t, err)

	// A delegation for the right role, but its ceiling names another operation.
	_, err = h.svc.IAM.CreateDelegation(ctx, nil, &biz.Delegation{
		ManagerRoleID: manager.ID, TargetRoleID: ceilingRole.ID, TargetKind: "role",
		Actions:         []string{biz.DelegationActionAssign},
		TargetUserScope: targetScope,
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: "identity.user.update", Scope: targetScope,
		}},
		StartsAt: now.Add(-time.Minute), ExpiresAt: ptrTime(now.Add(time.Hour)),
		CreatedBy: actor.ID, Context: authorization.Platform(),
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	fixtureStepUp(h)
	expires := now.Add(30 * time.Minute).Format(time.RFC3339)

	assign := func(targetID, roleID int64) *httptest.ResponseRecorder {
		return h.do(http.MethodPost, "/api/v1/admin/iam/assignments", iamBody(h, map[string]any{
			"user_id":    strconv.FormatInt(targetID, 10),
			"role_id":    strconv.FormatInt(roleID, 10),
			"boundary":   map[string]any{"user_ids": []string{strconv.FormatInt(targetID, 10)}},
			"expires_at": expires,
			"reason":     "delegation boundary",
		}), "", true)
	}

	// Positive control: the delegation is usable for exactly what it names.
	rec := assign(target.ID, reader.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)

	// Wrong user: the delegation names bounded_target, not bounded_other.
	rec = assign(other.ID, reader.ID)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// Wrong target role: bounded_other_role grants an operation the actor does
	// not hold and no delegation covers.
	rec = assign(target.ID, otherRole.ID)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// Expired delegation must not authorise the same shape later.
	rec = assign(target.ID, expiredRole.ID)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// Ceiling over a different operation must not cover the grant.
	rec = assign(target.ID, ceilingRole.ID)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")

	// Wrong action: an assign-only delegation is not a revoke delegation. The
	// actor does hold iam.assignment.revoke, so the denial is specifically the
	// delegation boundary, not a missing operation.
	rec = h.do(http.MethodPost,
		"/api/v1/admin/iam/assignments/"+created["id"].(string)+":revoke",
		iamBody(h, map[string]any{
			"expected_revision": created["revision"].(string),
			"reason":            "assign-only delegation must not revoke",
		}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DELEGATION_REQUIRED")
}

func TestPlatformDelegationCannotEditRolePolicy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	actor := iamFixtureUser(t, h, "policy_delegate")
	target := iamFixtureUser(t, h, "policy_target")
	peer := iamFixtureUser(t, h, "policy_peer")

	manager := iamFixtureRole(t, h, "policy_manager")
	operator := iamFixtureRole(t, h, "policy_operator",
		biz.Grant{Operation: "iam.assignment.create", Effect: authorization.Allow, Scope: authorization.Scope{All: true}},
	)
	reader := iamFixtureRole(t, h, "policy_reader",
		biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{Self: true}},
	)
	peerRole := iamFixtureRole(t, h, "policy_peer_role",
		biz.Grant{Operation: "identity.user.list", Effect: authorization.Allow, Scope: authorization.Scope{All: true}},
	)

	iamFixtureAssign(t, h, actor.ID, manager.ID, authorization.Scope{All: true})
	iamFixtureAssign(t, h, actor.ID, operator.ID, authorization.Scope{All: true})

	now := time.Now().UTC()
	targetScope := authorization.Scope{UserIDs: []int64{target.ID}}
	_, err := h.svc.IAM.CreateDelegation(ctx, nil, &biz.Delegation{
		ManagerRoleID: manager.ID, TargetRoleID: reader.ID, TargetKind: "role",
		Actions:         []string{biz.DelegationActionAssign},
		TargetUserScope: targetScope,
		GrantCeiling: []biz.DelegationCeiling{{
			Operation: "identity.user.read", Scope: targetScope,
		}},
		StartsAt: now.Add(-time.Minute), ExpiresAt: ptrTime(now.Add(time.Hour)),
		CreatedBy: actor.ID, Context: authorization.Platform(),
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	fixtureStepUp(h)

	// The actor is a real delegate: this assignment succeeds.
	rec := h.do(http.MethodPost, "/api/v1/admin/iam/assignments", iamBody(h, map[string]any{
		"user_id":    strconv.FormatInt(target.ID, 10),
		"role_id":    strconv.FormatInt(reader.ID, 10),
		"boundary":   map[string]any{"user_ids": []string{strconv.FormatInt(target.ID, 10)}},
		"expires_at": now.Add(30 * time.Minute).Format(time.RFC3339),
		"reason":     "delegated assignment",
	}), "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	role, err := h.svc.IAM.GetRole(ctx, nil, reader.ID)
	require.NoError(t, err)

	// Delegation does not relax iam.role.update. Grant changes stay direct.
	rec = h.do(http.MethodPut, "/api/v1/admin/iam/roles/"+strconv.FormatInt(reader.ID, 10)+"/permissions", iamBody(h, map[string]any{
		"grants": []map[string]any{{
			"operation": "identity.user.read", "effect": "allow",
			"scope": map[string]any{"all": true},
		}},
		"expected_revision": strconv.FormatUint(role.Revision, 10),
		"reason":            "delegation must not edit grants",
	}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")

	// Inheritance is policy too.
	rec = h.do(http.MethodPut, "/api/v1/admin/iam/roles/"+strconv.FormatInt(reader.ID, 10)+"/inheritance", iamBody(h, map[string]any{
		"inherits":          []string{strconv.FormatInt(peerRole.ID, 10)},
		"expected_revision": strconv.FormatUint(role.Revision, 10),
		"reason":            "delegation must not edit inheritance",
	}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")

	// A delegate cannot widen the delegation system itself either.
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/delegations", iamBody(h, map[string]any{
		"manager_role_id": strconv.FormatInt(manager.ID, 10),
		"target_role_id":  strconv.FormatInt(peerRole.ID, 10),
		"target_kind":     "role",
		"actions":         []string{biz.DelegationActionAssign},
		"target_user_scope": map[string]any{
			"user_ids": []string{strconv.FormatInt(peer.ID, 10)},
		},
		"grant_ceiling": []map[string]any{{
			"operation": "identity.user.list",
			"scope":     map[string]any{"user_ids": []string{strconv.FormatInt(peer.ID, 10)}},
		}},
		"reason": "delegation must not edit policy",
	}), "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")

	// Nothing changed: one grant, no inheritance, and no second delegation.
	role, err = h.svc.IAM.GetRole(ctx, nil, reader.ID)
	require.NoError(t, err)
	require.Len(t, role.Grants, 1)
	require.Equal(t, "identity.user.read", role.Grants[0].Operation)
	require.False(t, role.Grants[0].Scope.All)
	require.True(t, role.Grants[0].Scope.Self)
	require.Empty(t, role.Inherits)

	delegations, err := h.svc.IAM.ListDelegations(ctx, nil, biz.DelegationFilter{})
	require.NoError(t, err)
	require.Len(t, delegations, 1)
}
