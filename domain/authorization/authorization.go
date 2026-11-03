// Package authorization owns the storage-free authorization contract shared by
// the user-center usecases and its resource owners. It deliberately knows
// nothing about protobuf, GORM or HTTP.
//
// Model: a decision is the union of allow scopes minus any matching deny scope,
// after identity/session/operation/business gates pass. Every gate must be
// supplied by the caller from verified facts; a zero value denies.
package authorization

import (
	"errors"
	"slices"
	"time"
)

var (
	ErrScope    = errors.New("invalid or unsupported authorization scope")
	ErrContext  = errors.New("invalid authorization context")
	ErrInterval = errors.New("invalid authorization interval")
	ErrGraph    = errors.New("invalid role inheritance graph")
)

// Context is the authorization domain. V1 only enables the platform domain;
// organization support is intentionally rejected until V2.
type Context struct {
	Type           string `json:"type"`
	OrganizationID int64  `json:"organization_id,omitempty"`
	Key            string `json:"key"`
}

func Platform() Context { return Context{Type: "platform", Key: "platform"} }

func (c Context) Validate() error {
	if c == Platform() {
		return nil
	}
	return ErrContext
}

type Actor struct {
	UserID    int64
	SessionID string
	ServiceID string
	ExpiresAt time.Time
}

func (a Actor) Valid(now time.Time) bool {
	return a.UserID > 0 && a.SessionID != "" && !now.IsZero() && now.Before(a.ExpiresAt)
}

type ScopeKind string

const (
	All   ScopeKind = "all"
	Self  ScopeKind = "self"
	Users ScopeKind = "user_ids"
)

// Scope is a finite union. An empty scope matches nothing and is never
// interpreted as "all".
type Scope struct {
	All     bool    `json:"all,omitempty"`
	Self    bool    `json:"self,omitempty"`
	UserIDs []int64 `json:"user_ids,omitempty"`
}

func (s Scope) Empty() bool {
	return !s.All && !s.Self && len(s.UserIDs) == 0
}

// Validate rejects a scope whose kind is not supported by the operation. An
// operation with no explicit support only accepts all.
func (s Scope) Validate(supported []ScopeKind) error {
	if s.Empty() {
		return ErrScope
	}
	if len(supported) == 0 {
		supported = []ScopeKind{All}
	}
	if s.All && !slices.Contains(supported, All) {
		return ErrScope
	}
	if s.Self && !slices.Contains(supported, Self) {
		return ErrScope
	}
	if len(s.UserIDs) > 0 {
		if !slices.Contains(supported, Users) {
			return ErrScope
		}
		for _, id := range s.UserIDs {
			if id <= 0 {
				return ErrScope
			}
		}
	}
	return nil
}

// Matches reports whether the scope covers target. targetUserID is the
// verified resource owner or target account; zero means "no user dimension"
// (a whole-object decision such as a tenant-wide list).
func (s Scope) Matches(actorID, targetUserID int64, wholeObject bool) bool {
	if s.All {
		return true
	}
	if wholeObject {
		return false
	}
	if s.Self && actorID > 0 && targetUserID == actorID {
		return true
	}
	if targetUserID > 0 && slices.Contains(s.UserIDs, targetUserID) {
		return true
	}
	return false
}

// Covers reports whether outer contains every element of inner.
func Covers(outer, inner Scope) bool {
	if inner.Empty() {
		return false
	}
	if outer.All {
		return true
	}
	if inner.All || inner.Self && !outer.Self {
		return false
	}
	for _, id := range inner.UserIDs {
		if !slices.Contains(outer.UserIDs, id) {
			return false
		}
	}
	return true
}

// Intersect returns the part of the intersection that can be represented
// without knowing the actor. Use IntersectForActor for authorization decisions
// involving both self and explicit user IDs.
func Intersect(a, b Scope) Scope {
	if a.Empty() || b.Empty() {
		return Scope{}
	}
	if a.All {
		return b
	}
	if b.All {
		return a
	}
	out := Scope{Self: a.Self && b.Self}
	for _, id := range a.UserIDs {
		if slices.Contains(b.UserIDs, id) && !slices.Contains(out.UserIDs, id) {
			out.UserIDs = append(out.UserIDs, id)
		}
	}
	return out
}

// IntersectForActor computes the exact intersection of two scope unions. A
// self predicate is resolved against the subject whose grants are evaluated.
func IntersectForActor(a, b Scope, actorID int64) Scope {
	resolve := func(s Scope) Scope {
		if s.Self && actorID > 0 && !slices.Contains(s.UserIDs, actorID) {
			s.UserIDs = append(slices.Clone(s.UserIDs), actorID)
		}
		s.Self = false
		return s
	}
	// Preserve the useful self projection when no explicit IDs are involved.
	if len(a.UserIDs) == 0 && len(b.UserIDs) == 0 {
		return Intersect(a, b)
	}
	return Intersect(resolve(a), resolve(b))
}

func (s Scope) String() string {
	switch {
	case s.All:
		return "all"
	case s.Self:
		return "self"
	case len(s.UserIDs) > 0:
		return "user_ids"
	default:
		return "none"
	}
}

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type Interval struct {
	StartsAt  time.Time
	ExpiresAt *time.Time
}

func (i Interval) Validate() error {
	if i.StartsAt.IsZero() || (i.ExpiresAt != nil && !i.StartsAt.Before(*i.ExpiresAt)) {
		return ErrInterval
	}
	return nil
}

func (i Interval) Contains(now time.Time) bool {
	return i.Validate() == nil && !now.Before(i.StartsAt) && (i.ExpiresAt == nil || now.Before(*i.ExpiresAt))
}

// GrantSource is one flattened grant after role inheritance. Active is only
// meaningful for allow grants: a deny always applies while it is valid.
type GrantSource struct {
	RoleID       int64
	RoleCode     string
	Operation    string
	Effect       Effect
	RoleScope    Scope
	Boundary     Scope
	AssignmentID int64
	Inheritance  []int64
	Validity     Interval
	Active       bool
}

type Decision struct {
	Allowed    bool
	Reason     string
	Operation  string
	Sources    []GrantSource
	ValidUntil *time.Time
}

// Input contains only verified server facts.
type Input struct {
	Actor             Actor
	Now               time.Time
	IdentityValid     bool
	SessionValid      bool
	Operation         string
	OperationEnabled  bool
	OperationBound    bool
	SupportedScopes   []ScopeKind
	WholeObject       bool
	TargetUserID      int64
	Sources           []GrantSource
	ConstraintsPass   bool
	BusinessRulesPass bool
}

// Evaluate applies identity, operation, scope, constraint and business gates.
func Evaluate(in Input) Decision {
	d := Decision{Reason: "IDENTITY_INVALID", Operation: in.Operation}
	if !in.IdentityValid || !in.SessionValid || !in.Actor.Valid(in.Now) {
		return d
	}
	d.Reason = "OPERATION_UNBOUND"
	if !in.OperationBound {
		return d
	}
	d.Reason = "OPERATION_DISABLED"
	if !in.OperationEnabled {
		return d
	}
	d.Reason = "SCOPE_INVALID"
	if in.TargetUserID < 0 {
		return d
	}
	d.Reason = "CONSTRAINT_VIOLATION"
	if !in.ConstraintsPass {
		return d
	}
	until := in.Actor.ExpiresAt
	var allows, denies []Scope
	for _, s := range in.Sources {
		if s.Operation != in.Operation || s.Effect != Allow && s.Effect != Deny {
			continue
		}
		if s.Validity.Validate() != nil || s.RoleScope.Validate(in.SupportedScopes) != nil || s.Boundary.Validate(in.SupportedScopes) != nil {
			return Decision{Reason: "SCOPE_INVALID", Operation: in.Operation}
		}
		if s.Effect == Deny && in.Now.Before(s.Validity.StartsAt) && s.Validity.StartsAt.Before(until) {
			until = s.Validity.StartsAt
		}
		if !s.Validity.Contains(in.Now) {
			continue
		}
		if (s.Effect == Deny || s.Active) && s.Validity.ExpiresAt != nil && s.Validity.ExpiresAt.Before(until) {
			until = *s.Validity.ExpiresAt
		}
		effective := IntersectForActor(s.RoleScope, s.Boundary, in.Actor.UserID)
		if s.Effect == Deny {
			denies = append(denies, effective)
			d.Sources = append(d.Sources, s)
			continue
		}
		if s.Active {
			allows = append(allows, effective)
			d.Sources = append(d.Sources, s)
		}
	}
	d.ValidUntil = &until
	d.Reason = "ALLOW_MISSING"
	covered := false
	for _, s := range allows {
		if s.Matches(in.Actor.UserID, in.TargetUserID, in.WholeObject) {
			covered = true
			break
		}
	}
	if !covered {
		return d
	}
	d.Reason = "DENY_MATCHED"
	for _, s := range denies {
		if s.Matches(in.Actor.UserID, in.TargetUserID, in.WholeObject) {
			return d
		}
	}
	d.Reason = "BUSINESS_RULE_VIOLATION"
	if !in.BusinessRulesPass {
		return d
	}
	d.Allowed, d.Reason = true, "ALLOWED"
	return d
}

// ValidateInheritance checks a role inheritance graph for cycles and unknown
// edges. edges maps role -> directly inherited roles.
func ValidateInheritance(edges map[int64][]int64) error {
	state := make(map[int64]int, len(edges))
	var visit func(int64) error
	visit = func(id int64) error {
		switch state[id] {
		case 1:
			return ErrGraph
		case 2:
			return nil
		}
		state[id] = 1
		for _, next := range edges[id] {
			if _, exists := edges[next]; !exists || next == id {
				return ErrGraph
			}
			if err := visit(next); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range edges {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

// ResolveInheritance returns id plus every transitively inherited role.
func ResolveInheritance(id int64, edges map[int64][]int64) []int64 {
	seen := map[int64]bool{}
	var walk func(int64)
	walk = func(cur int64) {
		if seen[cur] {
			return
		}
		seen[cur] = true
		for _, next := range edges[cur] {
			walk(next)
		}
	}
	walk(id)
	out := make([]int64, 0, len(seen))
	for role := range seen {
		out = append(out, role)
	}
	slices.Sort(out)
	return out
}
