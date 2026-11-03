package biz

import (
	"context"
	"slices"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Apply both allow and deny predicates before counting or paginating. A page
// filtered after LIMIT can leak totals and produce a non-advancing cursor.
func (uc *UserUsecase) listUserFilter(ctx context.Context, actor ActorContext, operation string, filter UserFilter) (UserFilter, error) {
	scope, err := uc.ListScope(ctx, actor, operation)
	if err != nil {
		return filter, err
	}
	filter.Scope, filter.ActorID = scope, actor.User.ID
	facts, err := uc.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return filter, ErrAuthorizationDown
	}
	for _, source := range facts.Sources {
		if source.Operation != operation || source.Effect != authorization.Deny || !source.Validity.Contains(uc.Clock.Now()) {
			continue
		}
		denied := authorization.IntersectForActor(source.RoleScope, source.Boundary, actor.User.ID)
		if denied.All {
			return filter, ErrPermissionDenied
		}
		if denied.Self && !slices.Contains(denied.UserIDs, actor.User.ID) {
			denied.UserIDs = append(denied.UserIDs, actor.User.ID)
		}
		filter.ExcludedIDs = append(filter.ExcludedIDs, denied.UserIDs...)
	}
	contact, err := uc.Decide(ctx, actor, "identity.user.contact.read", 0, true)
	if err != nil {
		return filter, ErrAuthorizationDown
	}
	filter.SearchEmail = contact.Allowed
	return filter, nil
}
