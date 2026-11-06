package biz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// currentIAMActor closes the gap between transport authentication and a
// policy transaction. Session role switches and identity changes must be
// rechecked before a management operation uses their authority.
func (s *Services) currentIAMActor(ctx context.Context, actor ActorContext) (ActorContext, error) {
	if actor.User == nil || actor.Session == nil {
		return actor, ErrUnauthenticated
	}
	user, err := s.Users.Get(ctx, nil, actor.User.ID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return actor, ErrUnauthenticated
		}
		return actor, ErrDependency
	}
	session, err := s.Sessions.Get(ctx, nil, actor.Session.ID)
	if err != nil {
		return actor, ErrUnauthenticated
	}
	if user.Status != UserStatusEnabled || session.UserID != user.ID || session.IdentityVersion != user.IdentityVersion || !session.Valid(s.Clock.Now()) {
		return actor, ErrUnauthenticated
	}
	active, err := s.Sessions.ListActiveRoleIDs(ctx, nil, session.ID)
	if err != nil {
		return actor, ErrDependency
	}
	roles, err := s.Users.RolesForUser(ctx, nil, user.ID)
	if err != nil {
		return actor, ErrDependency
	}
	user.Roles, session.ActiveRoleIDs = roles, active
	actor.User, actor.Session = user, session
	actor.Actor.UserID, actor.Actor.SessionID, actor.Actor.ExpiresAt = user.ID, session.ID, session.ExpiresAt
	return actor, nil
}

func protectedRoot(role *Role) bool { return role != nil && role.Code == "root" }

// checkGrantAuthority prevents a policy editor from manufacturing capabilities
// outside their own effective permissions. Root is maintained by the offline
// bootstrap/rescue path and may define new catalog operations.
func (s *Services) checkGrantAuthority(ctx context.Context, actor ActorContext, grants []Grant) error {
	current, err := s.currentIAMActor(ctx, actor)
	if err != nil {
		return err
	}
	actor = current
	facts, err := s.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return ErrAuthorizationDown
	}
	for _, a := range facts.Assignments {
		if a.Active(s.Clock.Now()) && slices.Contains(actor.Session.ActiveRoleIDs, a.RoleID) && protectedRoot(facts.Roles[a.RoleID]) {
			return nil
		}
	}
	for _, g := range grants {
		if g.Effect != authorization.Allow {
			continue
		}
		scope := g.Scope
		if scope.All {
			d, err := s.decideWithFacts(ctx, facts, actor, g.Operation, 0, true)
			if err != nil || !d.Allowed {
				return ErrPermissionDenied
			}
			continue
		}
		targets := slices.Clone(scope.UserIDs)
		if scope.Self {
			targets = append(targets, actor.User.ID)
		}
		for _, id := range targets {
			d, err := s.decideWithFacts(ctx, facts, actor, g.Operation, id, false)
			if err != nil || !d.Allowed {
				return ErrPermissionDenied
			}
		}
	}
	return nil
}

func (uc *IAMUsecase) checkInheritanceAuthority(ctx context.Context, actor ActorContext, roles []*Role, inherits []int64) error {
	byID := map[int64]*Role{}
	edges := map[int64][]int64{}
	for _, role := range roles {
		byID[role.ID], edges[role.ID] = role, role.Inherits
	}
	for _, id := range inherits {
		if byID[id] == nil {
			return Validation("继承角色不存在")
		}
		for _, inherited := range authorization.ResolveInheritance(id, edges) {
			role := byID[inherited]
			if protectedRoot(role) {
				return ErrProtectedAccount
			}
			if role != nil {
				if err := uc.checkGrantAuthority(ctx, actor, role.Grants); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func normalizeAssignmentScope(scope authorization.Scope) (authorization.Scope, error) {
	if scope.Empty() {
		scope = authorization.Scope{All: true}
	}
	if scope.Validate([]authorization.ScopeKind{authorization.All, authorization.Self, authorization.Users}) != nil {
		return scope, Validation("分配边界不合法")
	}
	return scope, nil
}

func (uc *IAMUsecase) validateAssignment(ctx context.Context, tx Tx, a *Assignment) error {
	if _, err := uc.Users.Get(ctx, tx, a.UserID); err != nil {
		return ErrUserNotFound
	}
	roles, err := uc.Users.RolesForUser(ctx, tx, a.UserID)
	if err != nil {
		return ErrDependency
	}
	for _, r := range roles {
		if r.Code == "root" {
			return ErrProtectedAccount
		}
	}
	role, err := uc.IAM.GetRole(ctx, tx, a.RoleID)
	if err != nil || role.Status != RoleStatusActive {
		return Validation("角色不可分配")
	}
	if protectedRoot(role) {
		return ErrProtectedAccount
	}
	if err := uc.checkRoleCapacity(ctx, tx, role); err != nil {
		return err
	}
	constraints, err := uc.IAM.ListConstraints(ctx, tx, authorization.Platform())
	if err != nil {
		return ErrDependency
	}
	current, err := uc.IAM.ListAssignmentsForUser(ctx, tx, a.UserID)
	if err != nil {
		return ErrDependency
	}
	// Check every existing assignment whose interval overlaps the new grant,
	// including future assignments, so constraints cannot be bypassed by delay.
	active := []int64{}
	for _, x := range current {
		if x.Revoked || !intervalsOverlap(x.StartsAt, x.ExpiresAt, a.StartsAt, a.ExpiresAt) {
			continue
		}
		if x.RoleID == a.RoleID {
			return Validation("已拥有该角色的有效授权")
		}
		active = append(active, x.RoleID)
	}
	return CheckConstraints(append(active, a.RoleID), constraints)
}

func intervalsOverlap(a time.Time, aEnd *time.Time, b time.Time, bEnd *time.Time) bool {
	return (aEnd == nil || b.Before(*aEnd)) && (bEnd == nil || a.Before(*bEnd))
}

func (uc *IAMUsecase) bumpPolicy(ctx context.Context, tx Tx) error {
	revision, err := uc.Policy.BumpPolicyRevision(ctx, tx)
	if err != nil {
		return err
	}
	return uc.emit(ctx, tx, "policy", 1, revision, "authorization.changed", string(mustJSON(map[string]string{"policy_revision": fmt.Sprint(revision)})))
}
