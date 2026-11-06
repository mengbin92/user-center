package biz

import (
	"context"
	"slices"

	"github.com/mengbin92/user-center/domain/authorization"
)

// listUserFilter builds the SQL filter for a user list and returns the policy
// snapshot it used, so the caller can reuse it for the per-row decisions
// instead of loading the same facts again.
//
// Apply both allow and deny predicates before counting or paginating. A page
// filtered after LIMIT can leak totals and produce a non-advancing cursor.
func (uc *UserUsecase) listUserFilter(ctx context.Context, actor ActorContext, operation string, filter UserFilter) (UserFilter, *AuthzFacts, error) {
	facts, err := uc.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return filter, nil, ErrAuthorizationDown
	}
	scope, err := uc.scopeWithFacts(ctx, facts, actor, operation)
	if err != nil {
		return filter, nil, err
	}
	filter.Scope, filter.ActorID = scope, actor.User.ID
	now := uc.Clock.Now()
	for _, source := range facts.Sources {
		if source.Operation != operation || source.Effect != authorization.Deny || !source.Validity.Contains(now) {
			continue
		}
		denied := authorization.IntersectForActor(source.RoleScope, source.Boundary, actor.User.ID)
		if denied.All {
			return filter, nil, ErrPermissionDenied
		}
		if denied.Self && !slices.Contains(denied.UserIDs, actor.User.ID) {
			denied.UserIDs = append(denied.UserIDs, actor.User.ID)
		}
		filter.ExcludedIDs = append(filter.ExcludedIDs, denied.UserIDs...)
	}
	contact, err := uc.decideWithFacts(ctx, facts, actor, "identity.user.contact.read", 0, true)
	if err != nil {
		return filter, nil, ErrAuthorizationDown
	}
	filter.SearchEmail = contact.Allowed
	return filter, facts, nil
}
