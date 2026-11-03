package biz

import "context"

func (uc *UserUsecase) managementPolicy(ctx context.Context, tx Tx, actor ActorContext) error {
	if actor.ExpectedPolicyRevision == 0 {
		return Validation("expected_policy_revision 不能为空")
	}
	current, err := uc.Policy.PolicyRevision(ctx, tx)
	if err != nil {
		return ErrDependency
	}
	if current != actor.ExpectedPolicyRevision {
		return ConflictPolicy(current)
	}
	user, err := uc.Users.Get(ctx, tx, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	session, err := uc.Sessions.Get(ctx, tx, actor.Session.ID)
	if err != nil {
		return ErrUnauthenticated
	}
	if user.Status != UserStatusEnabled || !session.Valid(uc.Clock.Now()) || session.IdentityVersion != user.IdentityVersion {
		return ErrSessionRevoked
	}
	if session.Revision != actor.Session.Revision {
		return ConflictRevision(session.Revision)
	}
	return nil
}

func (uc *UserUsecase) managementTarget(ctx context.Context, tx Tx, actor ActorContext, id int64, lock bool) (*User, error) {
	if err := uc.managementPolicy(ctx, tx, actor); err != nil {
		return nil, err
	}
	if actor.ExpectedTargetRevision == 0 {
		return nil, Validation("expected_revision 不能为空")
	}
	u, err := uc.Users.Get(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := uc.governableTarget(ctx, tx, actor, id); err != nil {
		return nil, err
	}
	if u.Revision != actor.ExpectedTargetRevision {
		return nil, ConflictRevision(u.Revision)
	}
	if lock {
		return uc.Users.Update(ctx, tx, u, actor.ExpectedTargetRevision)
	}
	return u, nil
}

// Credential governance must not let an administrator take over a root account.
func (uc *UserUsecase) governableTarget(ctx context.Context, tx Tx, actor ActorContext, id int64) error {
	roles, err := uc.Users.RolesForUser(ctx, tx, id)
	if err != nil {
		return ErrDependency
	}
	rootTarget := false
	for _, role := range roles {
		if role.Code == "root" {
			rootTarget = true
			break
		}
	}
	if !rootTarget {
		return nil
	}
	ownRoles, err := uc.Users.RolesForUser(ctx, tx, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	for _, role := range ownRoles {
		if role.Code == "root" {
			for _, active := range actor.Session.ActiveRoleIDs {
				if role.ID == active {
					return nil
				}
			}
		}
	}
	return ErrProtectedAccount
}
