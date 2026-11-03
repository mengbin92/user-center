package biz

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"

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
	if applicationCode == "" || applicationCode != s.Session.ApplicationCode {
		return nil, nil, ErrUnauthenticated
	}
	return &SessionFacts{
		SessionID: s.Session.ID, UserID: s.User.ID,
		ApplicationCode: s.Session.ApplicationCode, Status: s.User.Status,
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
		if IsNotFound(err) {
			return false, "", 0, ErrUserNotFound
		}
		return false, "", 0, ErrDependency
	}
	return u.Status == UserStatusEnabled, u.Status, u.IdentityVersion, nil
}

func (uc *IntegrationUsecase) GetUser(ctx context.Context, userID int64) (*User, error) {
	u, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, ErrDependency
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
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, ErrDependency
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
	if applicationCode == "" || applicationCode != actor.Session.ApplicationCode {
		return nil, nil, 0, ErrUnauthenticated
	}
	client, err := integrationClientFromContext(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	grants, policy, err := uc.EffectivePermissions(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return nil, nil, 0, ErrDependency
	}
	resources, err := uc.IAM.ListResources(ctx, nil)
	if err != nil {
		return nil, nil, 0, ErrDependency
	}
	owned := map[int64]bool{}
	for _, resource := range resources {
		if resource.Owner == client.ServiceOwner && resource.Enabled {
			owned[resource.ID] = true
		}
	}
	projected := grants[:0]
	for _, grant := range grants {
		permission, err := uc.IAM.GetPermissionByCode(ctx, nil, grant.Operation)
		if err != nil {
			return nil, nil, 0, ErrDependency
		}
		if owned[permission.ResourceID] {
			projected = append(projected, grant)
		}
	}
	grants = projected
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

func (uc *IntegrationUsecase) ResourceAuthorization(ctx context.Context, raw, executionPoint, operation string, ownerUserID, resourceID int64) (bool, string, authorization.Scope, uint64, *time.Time, error) {
	client, err := integrationClientFromContext(ctx)
	if err != nil {
		return false, "CALLER_INVALID", authorization.Scope{}, 0, nil, err
	}
	if executionPoint == "" || executionPoint != operation || ownerUserID <= 0 || resourceID <= 0 {
		return false, "INVALID_RESOURCE_FACTS", authorization.Scope{}, 0, nil, Validation("execution_point 必须匹配 operation，并提供真实 owner_user_id/resource_id")
	}
	permission, err := uc.IAM.GetPermissionByCode(ctx, nil, operation)
	if err != nil {
		return false, "OPERATION_UNBOUND", authorization.Scope{}, 0, nil, ErrPermissionDenied
	}
	resources, err := uc.IAM.ListResources(ctx, nil)
	if err != nil {
		return false, "AUTHORIZATION_UNAVAILABLE", authorization.Scope{}, 0, nil, ErrDependency
	}
	owned := false
	for _, resource := range resources {
		if resource.ID == permission.ResourceID && resource.Enabled && resource.Owner == client.ServiceOwner {
			owned = true
			break
		}
	}
	if !owned {
		return false, "RESOURCE_OWNER_MISMATCH", authorization.Scope{}, 0, nil, ErrPermissionDenied
	}
	actor, err := uc.SessionUsecase().ValidateSession(ctx, raw)
	if err != nil {
		return false, "SESSION_INVALID", authorization.Scope{}, 0, nil, err
	}
	facts, err := uc.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return false, "AUTHORIZATION_UNAVAILABLE", authorization.Scope{}, 0, nil, ErrDependency
	}
	d, err := uc.decideWithFacts(ctx, facts, actor, operation, ownerUserID, false)
	if err != nil {
		return false, "AUTHORIZATION_UNAVAILABLE", authorization.Scope{}, 0, nil, ErrDependency
	}
	scope := authorization.Scope{}
	if d.Allowed {
		scope.UserIDs = []int64{ownerUserID}
	}
	return d.Allowed, d.Reason, scope, facts.PolicyRevision, d.ValidUntil, nil
}

func (uc *IntegrationUsecase) RevokeSession(ctx context.Context, raw, sessionID, reason string) error {
	client, err := integrationClientFromContext(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	actor, err := uc.SessionUsecase().ValidateSession(ctx, raw)
	if err != nil {
		return err
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		s, err := uc.Sessions.Get(ctx, tx, sessionID)
		if errors.Is(err, ErrResourceNotFound) {
			return nil
		}
		if err != nil {
			return ErrDependency
		}
		if s.UserID != actor.User.ID || s.ApplicationCode != actor.Session.ApplicationCode {
			return ErrPermissionDenied
		}
		if s.RevokedAt != nil {
			return nil
		}
		now := uc.Clock.Now().UTC()
		if err := uc.Sessions.Revoke(ctx, tx, sessionID, &now); err != nil {
			return ErrDependency
		}
		actor.Actor.ServiceID = client.ClientID
		if err := uc.audit(ctx, tx, actor, "session.revoke", sessionID, "{}", "{}", "{}", reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]string{"user_id": itoa(s.UserID), "session_id": sessionID})
		return uc.emit(ctx, tx, "user", s.UserID, s.IdentityVersion, "session.revoked", string(payload))
	})
}
