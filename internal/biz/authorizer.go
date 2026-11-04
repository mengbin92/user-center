package biz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// AuthzFacts is the resolved policy snapshot for one actor in one context.
type AuthzFacts struct {
	PolicyRevision  uint64
	UserRevision    uint64
	Context         authorization.Context
	Roles           map[int64]*Role
	Assignments     []*Assignment
	ActiveRoleIDs   []int64
	Constraints     []*Constraint
	Sources         []authorization.GrantSource
	Permission      *Permission
	PermissionError error
}

func (f *AuthzFacts) role(id int64) *Role {
	if f == nil {
		return nil
	}
	return f.Roles[id]
}

func (s *Services) LoadAuthzFacts(ctx context.Context, userID int64, activeRoleIDs []int64) (*AuthzFacts, error) {
	return s.LoadAuthzFactsIn(ctx, authorization.Platform(), userID, activeRoleIDs)
}

// LoadAuthzFactsIn resolves policy facts for one context. Organization facts
// come exclusively from that tenant's roles and assignments, so neither side
// can widen the other's authority.
func (s *Services) LoadAuthzFactsIn(ctx context.Context, authCtx authorization.Context, userID int64, activeRoleIDs []int64) (*AuthzFacts, error) {
	authCtx = authCtx.Normalize()
	if err := authCtx.Validate(); err != nil {
		return nil, ErrAuthorizationDown
	}
	policyRev, err := s.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("policy revision: %w", err)
	}
	userRev, err := s.Policy.UserRevision(ctx, nil, userID)
	if err != nil {
		return nil, fmt.Errorf("user revision: %w", err)
	}
	var roles []*Role
	var assignments []*Assignment
	if authCtx.IsOrganization() {
		if s.OrgIAM == nil {
			return nil, ErrAuthorizationDown
		}
		roles, err = s.OrgIAM.ListRoles(ctx, nil, authCtx)
		if err != nil {
			return nil, fmt.Errorf("roles: %w", err)
		}
		items, err := s.OrgIAM.ListAssignments(ctx, nil, authCtx, userID)
		if err != nil {
			return nil, fmt.Errorf("assignments: %w", err)
		}
		for _, item := range items {
			if item.Assignment != nil {
				assignments = append(assignments, item.Assignment)
			}
		}
		// Organization assignments are active on their own: membership is the
		// tenant gate, and session role activation only applies to platform
		// roles, so the caller's platform role IDs must not be reused here.
		activeRoleIDs = []int64{}
		for _, a := range assignments {
			if !a.Revoked {
				activeRoleIDs = append(activeRoleIDs, a.RoleID)
			}
		}
	} else {
		roles, err = s.IAM.ListAllRolesWithGrants(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("roles: %w", err)
		}
		assignments, err = s.IAM.ListAssignmentsForUser(ctx, nil, userID)
		if err != nil {
			return nil, fmt.Errorf("assignments: %w", err)
		}
	}
	constraints, err := s.IAM.ListConstraints(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("constraints: %w", err)
	}
	f := &AuthzFacts{
		PolicyRevision: policyRev,
		UserRevision:   userRev,
		Context:        authCtx,
		Roles:          make(map[int64]*Role, len(roles)),
		Assignments:    assignments,
		ActiveRoleIDs:  activeRoleIDs,
		Constraints:    constraints,
	}
	for _, r := range roles {
		f.Roles[r.ID] = r
	}
	if err := f.resolveSources(s.Clock.Now()); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *AuthzFacts) resolveSources(now time.Time) error {
	f.Sources = nil
	edges := make(map[int64][]int64, len(f.Roles))
	for _, r := range f.Roles {
		edges[r.ID] = r.Inherits
	}
	if err := authorization.ValidateInheritance(edges); err != nil {
		return fmt.Errorf("role graph: %w", err)
	}
	// Disabled roles also break inheritance paths; an active grandparent must
	// not remain reachable through a disabled intermediate role.
	activeEdges := make(map[int64][]int64, len(edges))
	for id, inherited := range edges {
		if f.Roles[id].Status != RoleStatusActive {
			continue
		}
		for _, child := range inherited {
			if f.Roles[child] != nil && f.Roles[child].Status == RoleStatusActive {
				activeEdges[id] = append(activeEdges[id], child)
			}
		}
	}
	active := make(map[int64]bool, len(f.ActiveRoleIDs))
	for _, id := range f.ActiveRoleIDs {
		active[id] = true
	}
	for _, a := range f.Assignments {
		if a.Revoked || a.ExpiresAt != nil && !now.Before(*a.ExpiresAt) {
			continue
		}
		assignedRole := f.Roles[a.RoleID]
		if assignedRole == nil || assignedRole.Status != RoleStatusActive {
			continue
		}
		closure := authorization.ResolveInheritance(a.RoleID, activeEdges)
		for _, roleID := range closure {
			role := f.Roles[roleID]
			if role == nil || role.Status != RoleStatusActive {
				continue
			}
			for _, g := range role.Grants {
				f.Sources = append(f.Sources, authorization.GrantSource{
					RoleID:       role.ID,
					RoleCode:     role.Code,
					Operation:    g.Operation,
					Effect:       g.Effect,
					RoleScope:    g.Scope,
					Boundary:     a.Boundary,
					AssignmentID: a.ID,
					Inheritance:  closure,
					Validity: authorization.Interval{
						StartsAt:  a.StartsAt,
						ExpiresAt: a.ExpiresAt,
					},
					Active:  active[a.RoleID],
					Context: f.Context,
				})
			}
		}
	}
	return nil
}

func (s *Services) permission(ctx context.Context, operation string) (*Permission, error) {
	p, err := s.IAM.GetPermissionByCode(ctx, nil, operation)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Decide evaluates one platform operation for a verified actor. targetUserID
// is the account being read/changed; wholeObject covers tenant-wide queries.
func (s *Services) Decide(ctx context.Context, actor ActorContext, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	return s.DecideIn(ctx, actor, authorization.Platform(), operation, targetUserID, wholeObject)
}

// DecideIn evaluates one operation inside an authorization context. The same
// operation evaluated for a different context yields an independent decision.
func (s *Services) DecideIn(ctx context.Context, actor ActorContext, authCtx authorization.Context, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	facts, err := s.LoadAuthzFactsIn(ctx, authCtx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return authorization.Decision{}, err
	}
	return s.decideWithFacts(ctx, facts, actor, operation, targetUserID, wholeObject)
}

func (s *Services) decideWithFacts(ctx context.Context, facts *AuthzFacts, actor ActorContext, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	p, err := s.permission(ctx, operation)
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return authorization.Decision{Reason: "OPERATION_UNBOUND", Operation: operation}, nil
		}
		return authorization.Decision{}, err
	}
	now := s.Clock.Now()
	constraintsOK := CheckConstraints(facts.ActiveRoleIDs, facts.Constraints) == nil
	return authorization.Evaluate(authorization.Input{
		Actor:             actor.Actor,
		Now:               now,
		IdentityValid:     actor.User.Status == UserStatusEnabled,
		SessionValid:      actor.Session.Valid(now),
		Operation:         operation,
		OperationEnabled:  p.Status == PermissionStatusActive,
		OperationBound:    p.Binding == BindingBound,
		SupportedScopes:   p.ScopeKinds(),
		AllowedContexts:   p.ContextTypes,
		Context:           facts.Context,
		WholeObject:       wholeObject,
		TargetUserID:      targetUserID,
		Sources:           facts.Sources,
		ConstraintsPass:   constraintsOK,
		BusinessRulesPass: true,
	}), nil
}

// Authorize is the usecase guard for management writes. It returns the fresh
// decision so callers can echo versions and valid_until.
func (s *Services) Authorize(ctx context.Context, actor ActorContext, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	return s.AuthorizeIn(ctx, actor, authorization.Platform(), operation, targetUserID, wholeObject)
}

// AuthorizeIn is the context-scoped guard. Platform MFA policy is enforced on
// the platform path only; organization operations are gated by tenant
// membership, the tenant policy and step-up at the call site.
func (s *Services) AuthorizeIn(ctx context.Context, actor ActorContext, authCtx authorization.Context, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	d, err := s.DecideIn(ctx, actor, authCtx, operation, targetUserID, wholeObject)
	if err != nil {
		return d, ErrAuthorizationDown
	}
	if !d.Allowed {
		return d, ErrPermissionDenied
	}
	if !authCtx.Normalize().IsOrganization() {
		if err := s.requireAdminMFA(ctx, actor); err != nil {
			return d, err
		}
	}
	return d, nil
}

// requireAdminMFA enforces the configured policy at the authorization seam.
// A root/admin can still authenticate and enroll MFA, but management calls are
// refused until a second factor is active.
func (s *Services) requireAdminMFA(ctx context.Context, actor ActorContext) error {
	if actor.User == nil {
		return nil
	}
	isAdmin := false
	for _, r := range actor.User.Roles {
		if r.Code == "root" || r.Code == "admin" {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return nil
	}
	settings, err := s.Settings.GetAuth(ctx, nil)
	if err != nil {
		return ErrDependency
	}
	if !settings.MFARequiredForAdmins {
		return nil
	}
	if state, merr := s.MFA.Get(ctx, nil, actor.User.ID); merr == nil && state.Enabled() {
		return nil
	}
	return ErrMFAEnrollmentReq
}

func (s *Services) RequireStepUp(ctx context.Context, actor ActorContext) error {
	if actor.Session == nil {
		return ErrUnauthenticated
	}
	until, err := s.StepUp.Get(ctx, StepUpKey(actor.Session))
	if err != nil || until.IsZero() || !s.Clock.Now().Before(until) {
		return ErrStepUpRequired
	}
	return nil
}

func (s *Services) stepUpUntil(ctx context.Context, actor ActorContext) time.Time {
	if actor.Session == nil {
		return time.Time{}
	}
	until, err := s.StepUp.Get(ctx, StepUpKey(actor.Session))
	if err != nil || !s.Clock.Now().Before(until) {
		return time.Time{}
	}
	return until
}

// ScopeFor returns the union of allow scopes for an operation, used to push
// the coarse filter into SQL. Deny scopes and self predicates are still
// evaluated per item by Decide.
func (s *Services) ScopeFor(ctx context.Context, actor ActorContext, operation string) (authorization.Scope, error) {
	return s.ScopeForIn(ctx, actor, authorization.Platform(), operation)
}

func (s *Services) ScopeForIn(ctx context.Context, actor ActorContext, authCtx authorization.Context, operation string) (authorization.Scope, error) {
	facts, err := s.LoadAuthzFactsIn(ctx, authCtx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return authorization.Scope{}, err
	}
	return scopeForFacts(facts, actor, operation, s.Clock.Now()), nil
}

func scopeForFacts(facts *AuthzFacts, actor ActorContext, operation string, now time.Time) authorization.Scope {
	out := authorization.Scope{}
	for _, src := range facts.Sources {
		if src.Operation != operation || src.Effect != authorization.Allow || !src.Active {
			continue
		}
		if !src.Validity.Contains(now) {
			continue
		}
		effective := authorization.IntersectForActor(src.RoleScope, src.Boundary, actor.User.ID)
		if effective.All {
			return authorization.Scope{All: true}
		}
		if effective.Self && !slices.Contains(out.UserIDs, actor.User.ID) {
			out.UserIDs = append(out.UserIDs, actor.User.ID)
		}
		for _, id := range effective.UserIDs {
			if !slices.Contains(out.UserIDs, id) {
				out.UserIDs = append(out.UserIDs, id)
			}
		}
	}
	return out
}

func (s *Services) EffectivePermissions(ctx context.Context, userID int64, activeRoleIDs []int64) ([]AuthorizationGrant, uint64, error) {
	if activeRoleIDs == nil {
		assignments, err := s.IAM.ListAssignmentsForUser(ctx, nil, userID)
		if err != nil {
			return nil, 0, err
		}
		activeRoleIDs = []int64{}
		for _, a := range assignments {
			if a.Active(s.Clock.Now()) {
				activeRoleIDs = append(activeRoleIDs, a.RoleID)
			}
		}
	}
	facts, err := s.LoadAuthzFacts(ctx, userID, activeRoleIDs)
	if err != nil {
		return nil, 0, err
	}
	permissions, err := s.IAM.ListPermissions(ctx, nil, PermissionFilter{Status: PermissionStatusActive})
	if err != nil {
		return nil, 0, err
	}
	enabled := map[string]bool{}
	for _, p := range permissions {
		enabled[p.Code] = p.Binding == BindingBound
	}
	seen := map[string]bool{}
	var out []AuthorizationGrant
	for _, src := range facts.Sources {
		if !src.Validity.Contains(s.Clock.Now()) || !enabled[src.Operation] || src.Effect == authorization.Allow && !src.Active {
			continue
		}
		effective := authorization.IntersectForActor(src.RoleScope, src.Boundary, userID)
		if effective.Empty() {
			continue
		}
		scope := scopeString(src, userID)
		key := string(src.Effect) + "|" + src.Operation + "|" + src.RoleCode + "|" + scope
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, AuthorizationGrant{Operation: src.Operation, Effect: string(src.Effect), Scope: scope, RoleID: src.RoleID, RoleCode: src.RoleCode})
	}
	return out, facts.PolicyRevision, nil
}

type AuthorizationGrant struct {
	Operation string
	Effect    string
	Scope     string
	RoleID    int64
	RoleCode  string
}

func scopeString(src authorization.GrantSource, userID int64) string {
	eff := authorization.IntersectForActor(src.RoleScope, src.Boundary, userID)
	if eff.All {
		return "all"
	}
	if eff.Self {
		return "self"
	}
	parts := make([]string, 0, len(eff.UserIDs))
	for _, id := range eff.UserIDs {
		parts = append(parts, itoa(id))
	}
	return "users:" + strings.Join(parts, ",")
}

// CheckConstraints enforces static separation-of-duty and cardinality rules
// over a set of simultaneously active or assigned roles.
func CheckConstraints(roleIDs []int64, constraints []*Constraint) error {
	for _, c := range constraints {
		if !c.Enabled || len(c.RoleIDs) == 0 {
			continue
		}
		n := 0
		seen := map[int64]bool{}
		for _, id := range roleIDs {
			if !seen[id] && slices.Contains(c.RoleIDs, id) {
				seen[id] = true
				n++
			}
		}
		switch c.Kind {
		case "mutual_exclusion":
			if n > 1 {
				return fmt.Errorf("%w: %s", ErrRoleConstraint, c.Name)
			}
		case "max_roles":
			limit := c.MaxCount
			if limit <= 0 {
				limit = 1
			}
			if int64(n) > limit {
				return fmt.Errorf("%w: %s", ErrRoleConstraint, c.Name)
			}
		}
	}
	return nil
}

// checkDelegation requires either direct authority over both the assignment
// operation and the role capabilities, or a valid delegation with a matching
// grant ceiling. An assignment operation alone never implies grant authority.
func (s *Services) checkDelegation(ctx context.Context, actor ActorContext, targetUserID, targetRoleID int64, action string, boundary authorization.Scope, starts time.Time, expires *time.Time) error {
	currentActor, err := s.currentIAMActor(ctx, actor)
	if err != nil {
		return err
	}
	actor = currentActor
	operation := "iam.assignment.create"
	if action == "revoke" {
		operation = "iam.assignment.revoke"
	}
	scope, err := s.ScopeFor(ctx, actor, operation)
	if err != nil {
		return ErrAuthorizationDown
	}
	delegations, derr := s.IAM.ListDelegations(ctx, nil, DelegationFilter{Status: "active", TargetRoleID: targetRoleID})
	if derr != nil {
		return ErrDelegationRequired
	}
	roles, err := s.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return ErrAuthorizationDown
	}
	byID := map[int64]*Role{}
	edges := map[int64][]int64{}
	for _, r := range roles {
		byID[r.ID], edges[r.ID] = r, r.Inherits
	}
	assignments, err := s.IAM.ListAssignmentsForUser(ctx, nil, actor.User.ID)
	if err != nil {
		return ErrAuthorizationDown
	}
	managerRoleIDs := []int64{}
	for _, assignment := range assignments {
		role := byID[assignment.RoleID]
		if assignment.Active(s.Clock.Now()) && role != nil && role.Status == RoleStatusActive && slices.Contains(actor.Session.ActiveRoleIDs, assignment.RoleID) {
			managerRoleIDs = append(managerRoleIDs, assignment.RoleID)
		}
	}
	var targetGrants []Grant
	for _, id := range authorization.ResolveInheritance(targetRoleID, edges) {
		r := byID[id]
		if r == nil || r.Status != RoleStatusActive {
			continue
		}
		for _, g := range r.Grants {
			effective := authorization.IntersectForActor(g.Scope, boundary, targetUserID)
			if effective.Self {
				effective.Self = false
				if !slices.Contains(effective.UserIDs, targetUserID) {
					effective.UserIDs = append(effective.UserIDs, targetUserID)
				}
			}
			if !effective.Empty() {
				targetGrants = append(targetGrants, Grant{Operation: g.Operation, Effect: authorization.Allow, Scope: effective})
			}
		}
	}
	if scope.All && s.checkGrantAuthority(ctx, actor, targetGrants) == nil {
		return nil
	}
	for _, d := range delegations {
		if !delegationAllowsForActor([]*Delegation{d}, managerRoleIDs, actor.User.ID, targetUserID, targetRoleID, action, boundary, s.Clock.Now()) {
			continue
		}
		if action == "assign" && (starts.Before(d.StartsAt) || d.ExpiresAt != nil && (expires == nil || expires.After(*d.ExpiresAt))) {
			continue
		}
		covered := true
		for _, g := range targetGrants {
			found := false
			for _, ceiling := range d.GrantCeiling {
				ceilingScope := ceiling.Scope
				if ceilingScope.Self {
					ceilingScope.Self = false
					if !slices.Contains(ceilingScope.UserIDs, targetUserID) {
						ceilingScope.UserIDs = append(slices.Clone(ceilingScope.UserIDs), targetUserID)
					}
				}
				if ceiling.Operation == g.Operation && authorization.Covers(ceilingScope, g.Scope) {
					found = true
					break
				}
			}
			if !found {
				covered = false
				break
			}
		}

		if covered {
			return nil
		}
	}
	return ErrDelegationRequired
}

// DelegationAllows is the pure containment check used by assignment guards.
func DelegationAllows(delegations []*Delegation, activeRoleIDs []int64, targetUserID, targetRoleID int64, action string, boundary authorization.Scope, now time.Time) bool {
	return delegationAllowsForActor(delegations, activeRoleIDs, 0, targetUserID, targetRoleID, action, boundary, now)
}

func delegationAllowsForActor(delegations []*Delegation, activeRoleIDs []int64, actorID, targetUserID, targetRoleID int64, action string, boundary authorization.Scope, now time.Time) bool {
	resolveSelf := func(scope authorization.Scope, userID int64) authorization.Scope {
		if scope.Self {
			scope.Self = false
			if userID > 0 && !slices.Contains(scope.UserIDs, userID) {
				scope.UserIDs = append(slices.Clone(scope.UserIDs), userID)
			}
		}
		return scope
	}
	boundary = resolveSelf(boundary, targetUserID)
	for _, d := range delegations {
		if !slices.Contains(activeRoleIDs, d.ManagerRoleID) || !d.Active(now) {
			continue
		}
		if d.TargetRoleID != targetRoleID || !slices.Contains(d.Actions, action) {
			continue
		}
		targetScope := resolveSelf(d.TargetUserScope, actorID)
		if !authorization.Covers(targetScope, authorization.Scope{UserIDs: []int64{targetUserID}}) {
			continue
		}
		if !authorization.Covers(targetScope, boundary) {
			continue
		}
		return true
	}
	return false
}
