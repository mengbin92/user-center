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

// AuthzFacts is the resolved policy snapshot for one actor.
type AuthzFacts struct {
	PolicyRevision  uint64
	UserRevision    uint64
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
	policyRev, err := s.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("policy revision: %w", err)
	}
	userRev, err := s.Policy.UserRevision(ctx, nil, userID)
	if err != nil {
		return nil, fmt.Errorf("user revision: %w", err)
	}
	roles, err := s.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("roles: %w", err)
	}
	assignments, err := s.IAM.ListAssignmentsForUser(ctx, nil, userID)
	if err != nil {
		return nil, fmt.Errorf("assignments: %w", err)
	}
	constraints, err := s.IAM.ListConstraints(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("constraints: %w", err)
	}
	f := &AuthzFacts{
		PolicyRevision: policyRev,
		UserRevision:   userRev,
		Roles:          make(map[int64]*Role, len(roles)),
		Assignments:    assignments,
		ActiveRoleIDs:  activeRoleIDs,
		Constraints:    constraints,
	}
	edges := make(map[int64][]int64, len(roles))
	for _, r := range roles {
		f.Roles[r.ID] = r
		edges[r.ID] = r.Inherits
	}
	if err := authorization.ValidateInheritance(edges); err != nil {
		return nil, fmt.Errorf("role graph: %w", err)
	}
	active := make(map[int64]bool, len(activeRoleIDs))
	for _, id := range activeRoleIDs {
		active[id] = true
	}
	now := s.Clock.Now()
	for _, a := range assignments {
		if !a.Active(now) {
			continue
		}
		closure := authorization.ResolveInheritance(a.RoleID, edges)
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
					Active: active[roleID],
				})
			}
		}
	}
	return f, nil
}

func (s *Services) permission(ctx context.Context, operation string) (*Permission, error) {
	p, err := s.IAM.GetPermissionByCode(ctx, nil, operation)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Decide evaluates one operation for a verified actor. targetUserID is the
// account being read/changed; wholeObject covers tenant-wide queries.
func (s *Services) Decide(ctx context.Context, actor ActorContext, operation string, targetUserID int64, wholeObject bool) (authorization.Decision, error) {
	facts, err := s.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
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
	constraintsOK := CheckConstraints(actor.Session.ActiveRoleIDs, facts.Constraints) == nil
	return authorization.Evaluate(authorization.Input{
		Actor:             actor.Actor,
		Now:               now,
		IdentityValid:     actor.User.Status == UserStatusEnabled,
		SessionValid:      actor.Session.Valid(now),
		Operation:         operation,
		OperationEnabled:  p.Status == PermissionStatusActive,
		OperationBound:    p.Binding == BindingBound,
		SupportedScopes:   p.ScopeKinds(),
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
	d, err := s.Decide(ctx, actor, operation, targetUserID, wholeObject)
	if err != nil {
		return d, ErrAuthorizationDown
	}
	if !d.Allowed {
		return d, ErrPermissionDenied
	}
	if err := s.requireAdminMFA(ctx, actor); err != nil {
		return d, err
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
	until, err := s.StepUp.Get(ctx, actor.Session.ID)
	if err != nil || until.IsZero() || !s.Clock.Now().Before(until) {
		return ErrStepUpRequired
	}
	return nil
}

func (s *Services) stepUpUntil(ctx context.Context, actor ActorContext) time.Time {
	if actor.Session == nil {
		return time.Time{}
	}
	until, err := s.StepUp.Get(ctx, actor.Session.ID)
	if err != nil || !s.Clock.Now().Before(until) {
		return time.Time{}
	}
	return until
}

// ScopeFor returns the union of allow scopes for an operation, used to push
// the coarse filter into SQL. Deny scopes and self predicates are still
// evaluated per item by Decide.
func (s *Services) ScopeFor(ctx context.Context, actor ActorContext, operation string) (authorization.Scope, error) {
	facts, err := s.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
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
		effective := authorization.Intersect(src.RoleScope, src.Boundary)
		if effective.All {
			return authorization.Scope{All: true}
		}
		if effective.Self {
			out.Self = true
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
	facts, err := s.LoadAuthzFacts(ctx, userID, activeRoleIDs)
	if err != nil {
		return nil, 0, err
	}
	if len(activeRoleIDs) == 0 {
		for _, a := range facts.Assignments {
			if a.Active(s.Clock.Now()) {
				facts.ActiveRoleIDs = append(facts.ActiveRoleIDs, a.RoleID)
			}
		}
	}
	active := map[int64]bool{}
	for _, id := range facts.ActiveRoleIDs {
		active[id] = true
	}
	seen := map[string]bool{}
	var out []AuthorizationGrant
	for _, src := range facts.Sources {
		if !src.Active && !active[src.RoleID] {
			continue
		}
		if src.Effect == authorization.Deny {
			key := "deny|" + src.Operation + "|" + src.RoleCode
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, AuthorizationGrant{Operation: src.Operation, Effect: string(src.Effect), Scope: scopeString(src), RoleID: src.RoleID, RoleCode: src.RoleCode})
			continue
		}
		if !active[src.RoleID] {
			continue
		}
		key := "allow|" + src.Operation + "|" + src.RoleCode
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, AuthorizationGrant{Operation: src.Operation, Effect: string(src.Effect), Scope: scopeString(src), RoleID: src.RoleID, RoleCode: src.RoleCode})
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

func scopeString(src authorization.GrantSource) string {
	eff := authorization.Intersect(src.RoleScope, src.Boundary)
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
		for _, id := range roleIDs {
			if slices.Contains(c.RoleIDs, id) {
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

// checkDelegation requires an active delegation when the actor does not hold
// an all-scope grant for the assignment action. Delegations never grant
// permissions by themselves; they only authorize a bounded manager to act.
func (s *Services) checkDelegation(ctx context.Context, actor ActorContext, targetUserID, targetRoleID int64, action string, boundary authorization.Scope) error {
	operation := "iam.assignment.create"
	if action == "revoke" {
		operation = "iam.assignment.revoke"
	}
	scope, err := s.ScopeFor(ctx, actor, operation)
	if err == nil && scope.All {
		return nil
	}
	delegations, derr := s.IAM.ListDelegations(ctx, nil, DelegationFilter{Status: "active", TargetRoleID: targetRoleID})
	if derr != nil {
		return ErrDelegationRequired
	}
	if DelegationAllows(delegations, actor.Session.ActiveRoleIDs, targetUserID, targetRoleID, action, boundary, s.Clock.Now()) {
		return nil
	}
	return ErrDelegationRequired
}

// DelegationAllows is the pure containment check used by assignment guards.
func DelegationAllows(delegations []*Delegation, activeRoleIDs []int64, targetUserID, targetRoleID int64, action string, boundary authorization.Scope, now time.Time) bool {
	for _, d := range delegations {
		if !slices.Contains(activeRoleIDs, d.ManagerRoleID) || !d.Active(now) {
			continue
		}
		if d.TargetRoleID != targetRoleID || !slices.Contains(d.Actions, action) {
			continue
		}
		if !authorization.Covers(d.TargetUserScope, authorization.Scope{UserIDs: []int64{targetUserID}}) {
			continue
		}
		if !authorization.Covers(d.TargetUserScope, boundary) {
			continue
		}
		return true
	}
	return false
}
