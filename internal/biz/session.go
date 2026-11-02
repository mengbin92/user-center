package biz

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// ValidateSession resolves a raw browser cookie value into an authoritative
// actor. The database row, user status and identity version are all checked;
// a signed cookie alone is never sufficient.
func (uc *SessionUsecase) ValidateSession(ctx context.Context, raw string) (ActorContext, error) {
	if raw == "" {
		return ActorContext{}, ErrUnauthenticated
	}
	hash := HashToken(raw)
	session, err := uc.Sessions.GetByTokenHash(ctx, nil, hash)
	if err != nil {
		return ActorContext{}, ErrUnauthenticated
	}
	now := uc.Clock.Now()
	if !session.Valid(now) {
		return ActorContext{}, ErrSessionRevoked
	}
	user, err := uc.Users.Get(ctx, nil, session.UserID)
	if err != nil {
		return ActorContext{}, ErrUnauthenticated
	}
	if user.Status != UserStatusEnabled {
		return ActorContext{}, ErrUnauthenticated
	}
	if user.IdentityVersion != session.IdentityVersion {
		_ = uc.Sessions.Revoke(ctx, nil, session.ID, &now)
		return ActorContext{}, ErrSessionRevoked
	}
	roles, err := uc.Sessions.ListActiveRoleIDs(ctx, nil, session.ID)
	if err != nil {
		return ActorContext{}, ErrDependency
	}
	session.ActiveRoleIDs = roles
	idle := uc.IdleTimeout
	_ = uc.Sessions.Touch(ctx, nil, session.ID, now, now.Add(idle))
	return ActorContext{
		User:    user,
		Session: session,
		Actor: authorization.Actor{
			UserID:    user.ID,
			SessionID: session.ID,
			ExpiresAt: session.ExpiresAt,
		},
	}, nil
}

func (uc *SessionUsecase) List(ctx context.Context, actor ActorContext) ([]*Session, error) {
	sessions, err := uc.Sessions.ListByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	out := make([]*Session, 0, len(sessions))
	for _, s := range sessions {
		if s.Valid(now) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (uc *SessionUsecase) RevokeOwn(ctx context.Context, actor ActorContext, id string) error {
	s, err := uc.Sessions.Get(ctx, nil, id)
	if err != nil || s.UserID != actor.User.ID {
		return ErrResourceNotFound
	}
	now := uc.Clock.Now().UTC()
	if err := uc.Sessions.Revoke(ctx, nil, id, &now); err != nil {
		return ErrDependency
	}
	_ = uc.StepUp.Delete(ctx, id)
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "session_revoke", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return nil
}

func (uc *SessionUsecase) RevokeOthers(ctx context.Context, actor ActorContext) error {
	rows, err := uc.Sessions.ListByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	now := uc.Clock.Now().UTC()
	for _, s := range rows {
		if s.ID == actor.Session.ID || s.RevokedAt != nil {
			continue
		}
		if err := uc.Sessions.Revoke(ctx, nil, s.ID, &now); err != nil {
			return ErrDependency
		}
		_ = uc.StepUp.Delete(ctx, s.ID)
	}
	return nil
}

type SessionRole struct {
	ID      int64
	Code    string
	Name    string
	Active  bool
	Builtin bool
}

func (uc *SessionUsecase) Roles(ctx context.Context, actor ActorContext) ([]SessionRole, uint64, error) {
	assignments, err := uc.IAM.ListAssignmentsForUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, 0, ErrDependency
	}
	roles, err := uc.IAM.ListRoles(ctx, nil, RoleFilter{Status: RoleStatusActive})
	if err != nil {
		return nil, 0, ErrDependency
	}
	active, err := uc.Sessions.ListActiveRoleIDs(ctx, nil, actor.Session.ID)
	if err != nil {
		return nil, 0, ErrDependency
	}
	now := uc.Clock.Now()
	assigned := map[int64]bool{}
	for _, a := range assignments {
		if a.Active(now) {
			assigned[a.RoleID] = true
		}
	}
	out := make([]SessionRole, 0, len(roles))
	for _, r := range roles {
		if !assigned[r.ID] {
			continue
		}
		out = append(out, SessionRole{ID: r.ID, Code: r.Code, Name: r.Name, Active: slices.Contains(active, r.ID), Builtin: r.Builtin})
	}
	return out, actor.Session.Revision, nil
}

func (uc *SessionUsecase) PutRoles(ctx context.Context, actor ActorContext, roleIDs []int64, expectedRevision uint64) ([]SessionRole, uint64, error) {
	if expectedRevision != actor.Session.Revision {
		return nil, 0, ConflictRevision(actor.Session.Revision)
	}
	assignments, err := uc.IAM.ListAssignmentsForUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, 0, ErrDependency
	}
	now := uc.Clock.Now()
	assigned := map[int64]bool{}
	for _, a := range assignments {
		if a.Active(now) {
			assigned[a.RoleID] = true
		}
	}
	rolesAll, err := uc.IAM.ListRoles(ctx, nil, RoleFilter{})
	if err != nil {
		return nil, 0, ErrDependency
	}
	activeRole := map[int64]bool{}
	for _, r := range rolesAll {
		if r.Status == RoleStatusActive {
			activeRole[r.ID] = true
		}
	}
	unique := make([]int64, 0, len(roleIDs))
	for _, id := range roleIDs {
		if !assigned[id] || !activeRole[id] {
			return nil, 0, Validation("包含未分配或已停用的会话角色")
		}
		if !slices.Contains(unique, id) {
			unique = append(unique, id)
		}
	}
	constraints, err := uc.IAM.ListConstraints(ctx, nil)
	if err != nil {
		return nil, 0, ErrDependency
	}
	if err := CheckConstraints(unique, constraints); err != nil {
		return nil, 0, err
	}
	if err := uc.Sessions.SetActiveRoleIDs(ctx, nil, actor.Session.ID, unique); err != nil {
		return nil, 0, ErrDependency
	}
	actor.Session.ActiveRoleIDs = unique
	actor.Session.Revision++
	roles, revision, err := uc.Roles(ctx, actor)
	if err != nil {
		return nil, 0, err
	}
	return roles, revision, nil
}

// AuthorizedRead requires one of the supplied operations for a target user and
// returns the fresh decision. It is shared by self-service and admin reads.
func (s *Services) AuthorizedRead(ctx context.Context, actor ActorContext, operation string, targetUserID int64) error {
	d, err := s.Decide(ctx, actor, operation, targetUserID, false)
	if err != nil {
		return ErrAuthorizationDown
	}
	if !d.Allowed {
		return ErrPermissionDenied
	}
	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "Duplicate entry") || contains(msg, "UNIQUE constraint failed") || contains(msg, "duplicate key")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = errors.Is
var _ = time.Now

// Authorization returns the current session permission projection and menu
// keys. It is the authoritative source for the SPA; the client never infers
// permissions from role numbers.
func (uc *SessionUsecase) Authorization(ctx context.Context, actor ActorContext) ([]AuthorizationGrant, []string, uint64, uint64, error) {
	grants, policy, err := uc.EffectivePermissions(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	keys, err := uc.MenuKeysForGrants(ctx, grants)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	userRev, err := uc.Policy.UserRevision(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, nil, 0, 0, ErrDependency
	}
	return grants, keys, policy, userRev, nil
}
