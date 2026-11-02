package biz

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

type SessionFacts struct {
	SessionID       string
	UserID          int64
	ApplicationCode string
	Status          string
	IdentityVersion uint64
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// ValidateSession is the internal RPC entry point. It returns only the
// minimum facts a business system needs; credentials never cross the wire.
func (uc *IntegrationUsecase) ValidateSession(ctx context.Context, raw, applicationCode string) (*SessionFacts, *User, error) {
	s, err := uc.SessionUsecase().ValidateSession(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	if applicationCode != "" && applicationCode != ApplicationCode && applicationCode != "micro-one-api" {
		return nil, nil, ErrUnauthenticated
	}
	return &SessionFacts{
		SessionID: s.Session.ID, UserID: s.User.ID,
		ApplicationCode: applicationCode, Status: s.User.Status,
		IdentityVersion: s.User.IdentityVersion,
		IssuedAt:        s.Session.IssuedAt, ExpiresAt: s.Session.ExpiresAt,
	}, uc.minimalUser(s.User), nil
}

func (uc *IntegrationUsecase) SessionUsecase() *SessionUsecase {
	return &SessionUsecase{Services: uc.Services}
}

func (uc *IntegrationUsecase) minimalUser(u *User) *User {
	return &User{
		ID: u.ID, Username: u.Username, DisplayName: u.DisplayName,
		Status: u.Status, Revision: u.Revision, IdentityVersion: u.IdentityVersion,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

func (uc *IntegrationUsecase) ValidateSubject(ctx context.Context, userID int64) (bool, string, uint64, error) {
	u, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		return false, "", 0, ErrUserNotFound
	}
	return u.Status == UserStatusEnabled, u.Status, u.IdentityVersion, nil
}

func (uc *IntegrationUsecase) GetUser(ctx context.Context, userID int64) (*User, error) {
	u, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return uc.minimalUser(u), nil
}

func (uc *IntegrationUsecase) BatchGetUsers(ctx context.Context, userIDs []int64) ([]*User, error) {
	if len(userIDs) > 100 {
		return nil, Validation("单次最多查询 100 个用户")
	}
	out := make([]*User, 0, len(userIDs))
	for _, id := range userIDs {
		u, err := uc.Users.Get(ctx, nil, id)
		if err != nil {
			continue
		}
		out = append(out, uc.minimalUser(u))
	}
	return out, nil
}

func (uc *IntegrationUsecase) SessionAuthorization(ctx context.Context, raw, applicationCode string) ([]AuthorizationGrant, []string, uint64, error) {
	actor, err := uc.SessionUsecase().ValidateSession(ctx, raw)
	if err != nil {
		return nil, nil, 0, err
	}
	grants, policy, err := uc.EffectivePermissions(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return nil, nil, 0, ErrDependency
	}
	keys, err := uc.MenuKeysForGrants(ctx, grants)
	if err != nil {
		return nil, nil, 0, err
	}
	return grants, keys, policy, nil
}

// MenuKeysForGrants projects the enabled menu tree for a permission set. Menus
// are display projections; API authorization is always evaluated separately.
func (s *Services) MenuKeysForGrants(ctx context.Context, grants []AuthorizationGrant) ([]string, error) {
	allowed := map[string]bool{}
	for _, g := range grants {
		if g.Effect == string(authorization.Allow) {
			allowed[g.Operation] = true
		}
	}
	menus, err := s.IAM.ListMenus(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	var keys []string
	for _, m := range menus {
		if !m.Enabled {
			continue
		}
		ok := true
		for _, op := range m.RequiredAll {
			if !allowed[op] {
				ok = false
				break
			}
		}
		if ok && len(m.RequiredAny) > 0 {
			anyOK := false
			for _, op := range m.RequiredAny {
				if allowed[op] {
					anyOK = true
					break
				}
			}
			ok = anyOK
		}
		if ok {
			keys = append(keys, m.RouteKey)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

func (uc *IntegrationUsecase) ResourceAuthorization(ctx context.Context, raw, operation string, ownerUserID, resourceID int64) (bool, string, authorization.Scope, uint64, error) {
	actor, err := uc.SessionUsecase().ValidateSession(ctx, raw)
	if err != nil {
		return false, "SESSION_INVALID", authorization.Scope{}, 0, nil
	}
	if ownerUserID == 0 {
		ownerUserID = actor.User.ID
	}
	facts, err := uc.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return false, "AUTHORIZATION_UNAVAILABLE", authorization.Scope{}, 0, ErrDependency
	}
	d, err := uc.decideWithFacts(ctx, facts, actor, operation, ownerUserID, false)
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return false, "OPERATION_UNBOUND", authorization.Scope{}, facts.PolicyRevision, nil
		}
		return false, "AUTHORIZATION_UNAVAILABLE", authorization.Scope{}, 0, ErrDependency
	}
	scope := authorization.Scope{}
	for _, s := range d.Sources {
		if s.Effect == authorization.Allow && s.Active {
			scope = authorization.Intersect(s.RoleScope, s.Boundary)
			break
		}
	}
	_ = resourceID
	return d.Allowed, d.Reason, scope, facts.PolicyRevision, nil
}

func (uc *IntegrationUsecase) RevokeSession(ctx context.Context, sessionID, reason string) error {
	s, err := uc.Sessions.Get(ctx, nil, sessionID)
	if err != nil {
		return nil // idempotent
	}
	now := uc.Clock.Now().UTC()
	if err := uc.Sessions.Revoke(ctx, nil, sessionID, &now); err != nil {
		return ErrDependency
	}
	_ = uc.audit(ctx, nil, ActorContext{Actor: authorization.Actor{ServiceID: "integration"}}, "session.revoke", itoa(s.UserID), "{}", "{}", "{}", reason, "success")
	return nil
}
