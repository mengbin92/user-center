package biz

import (
	"context"
	"slices"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Organization role delegation and the assignment boundary it feeds.
//
// The platform has had "you may only hand out authority you already hold, or
// authority covered by a delegation" since V2.2 (Services.checkDelegation).
// The organization domain shipped assignment management without either half:
// any member holding organization.iam.assignment.manage could grant the audit
// role on the strength of that one operation. This file supplies the missing
// check, in the organization's own facts.
//
// It cannot reuse checkDelegation. That function resolves the actor through
// platform facts -- ScopeFor, ListAllRolesWithGrants, actor.Session.ActiveRoleIDs
// -- and organization assignments are not in any of those, so it would deny
// every legitimate tenant case. The rule is copied deliberately; the mechanics
// are not.

// boundaryCovered reports whether at least one of the actor's operations
// reaches as wide as the boundary being granted. An empty boundary (the
// platform's "whole object" shape) imposes no extra constraint.
func boundaryCovered(held map[string]authorization.Scope, boundary authorization.Scope) bool {
	if boundary.Empty() {
		return true
	}
	for _, scope := range held {
		if authorization.Covers(scope, boundary) {
			return true
		}
	}
	return false
}

// orgRoleOperations resolves the operations a set of roles confers inside one
// tenant, following inheritance and skipping disabled roles.
func orgRoleOperations(roleIDs []int64, byID map[int64]*Role, edges map[int64][]int64, authCtx authorization.Context) map[string]authorization.Scope {
	out := map[string]authorization.Scope{}
	for _, id := range roleIDs {
		for _, inherited := range authorization.ResolveInheritance(id, edges) {
			role := byID[inherited]
			if role == nil || role.Status != RoleStatusActive {
				continue
			}
			// An organization role is never allowed to cross contexts; a role
			// that claims another context is ignored rather than trusted.
			if role.Context.Normalize() != authCtx.Normalize() {
				continue
			}
			for _, g := range role.Grants {
				if g.Effect != authorization.Allow {
					continue
				}
				if prev, ok := out[g.Operation]; ok {
					out[g.Operation] = widestScope(prev, g.Scope)
					continue
				}
				out[g.Operation] = g.Scope
			}
		}
	}
	return out
}

func widestScope(a, b authorization.Scope) authorization.Scope {
	if authorization.Covers(a, b) {
		return a
	}
	if authorization.Covers(b, a) {
		return b
	}
	merged := a
	merged.All = a.All || b.All
	merged.Self = a.Self || b.Self
	for _, id := range b.UserIDs {
		if !slices.Contains(merged.UserIDs, id) {
			merged.UserIDs = append(slices.Clone(merged.UserIDs), id)
		}
	}
	return merged
}

// coversOperations reports whether `held` grants every operation in `required`
// with a scope at least as wide.
func coversOperations(held, required map[string]authorization.Scope) bool {
	for operation, requiredScope := range required {
		actorScope, ok := held[operation]
		if !ok {
			return false
		}
		// An empty required scope means "this grant confers nothing usable",
		// and Covers reports false for it. Skip instead of denying: a role with
		// a malformed grant must not become an unassignable role.
		if requiredScope.Empty() {
			continue
		}
		if !authorization.Covers(actorScope, requiredScope) {
			return false
		}
	}
	return true
}

// checkOrgDelegation is the organization counterpart of checkDelegation: the
// actor must either already hold the target role's capabilities, or be covered
// by an active delegation in this tenant.
//
// It runs inside the caller's transaction and before the assignment is written,
// so the decision and the insert see the same snapshot. Revocation uses the same
// function with action=revoke, mirroring the platform's four entry points.
func (uc *OrgIAMUsecase) checkOrgDelegation(ctx context.Context, tx Tx, actor ActorContext, authCtx authorization.Context, targetUserID, targetRoleID int64, action string, boundary authorization.Scope, starts time.Time, expires *time.Time) error {
	roles, err := uc.OrgIAM.ListRoles(ctx, tx, authCtx)
	if err != nil {
		return ErrDependency
	}
	byID := make(map[int64]*Role, len(roles))
	edges := make(map[int64][]int64, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
		edges[r.ID] = r.Inherits
	}
	targetOps := orgRoleOperations([]int64{targetRoleID}, byID, edges, authCtx)

	assignments, err := uc.OrgIAM.ListAssignments(ctx, tx, authCtx, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	now := uc.Clock.Now()
	actorRoleIDs := make([]int64, 0, len(assignments))
	for _, item := range assignments {
		if !assignmentHolds(item.Assignment, byID, now) {
			continue
		}
		actorRoleIDs = append(actorRoleIDs, item.Assignment.RoleID)
	}

	// Branch 1: direct authority. Holding the assignment operation is not the
	// same as holding the target role's capabilities -- that conflation is the
	// hole this function closes.
	actorOps := orgRoleOperations(actorRoleIDs, byID, edges, authCtx)
	if coversOperations(actorOps, targetOps) && boundaryCovered(actorOps, boundary) {
		return nil
	}

	// Branch 2: a delegation issued in this tenant. The filter carries the
	// context, so a platform delegation (or another tenant's) can never match.
	delegations, err := uc.IAM.ListDelegations(ctx, tx, DelegationFilter{
		Status: "active", TargetRoleID: targetRoleID, Context: authCtx,
	})
	if err != nil {
		return ErrDelegationRequired
	}
	for _, d := range delegations {
		if !slices.Contains(actorRoleIDs, d.ManagerRoleID) || !d.Active(now) {
			continue
		}
		if d.TargetRoleID != targetRoleID || !slices.Contains(d.Actions, action) {
			continue
		}
		if !authorization.Covers(d.TargetUserScope, authorization.Scope{UserIDs: []int64{targetUserID}}) {
			continue
		}
		// The target-user scope is the operative limit here, and the assignment
		// boundary is deliberately not compared against it. An organization
		// assignment always stores Boundary=All: the role's data scope lives in
		// its own grants, not in the assignment row. Requiring the delegation's
		// user list to cover All would make every user-scoped delegation
		// unusable, which is the shape a tenant actually writes.
		// The delegation's own validity must contain the assignment being
		// written: a delegation that ends in March cannot authorise one that
		// runs to December.
		if action == DelegationActionAssign && (starts.Before(d.StartsAt) ||
			d.ExpiresAt != nil && (expires == nil || expires.After(*d.ExpiresAt))) {
			continue
		}
		// And its grant ceiling must cover what the role actually confers.
		ceiling := make(map[string]authorization.Scope, len(d.GrantCeiling))
		for _, c := range d.GrantCeiling {
			if prev, ok := ceiling[c.Operation]; ok {
				ceiling[c.Operation] = widestScope(prev, c.Scope)
				continue
			}
			ceiling[c.Operation] = c.Scope
		}
		if !coversOperations(ceiling, targetOps) {
			continue
		}
		return nil
	}
	return ErrDelegationRequired
}
