package biz

import "github.com/mengbin92/user-center/domain/authorization"

// ConstraintsForContext keeps only the constraints that belong to authCtx.
//
// This is the single place context filtering happens, and it exists because of
// a subtle property: roles live in one table with a global auto-increment id,
// so a platform constraint's role ids can never equal an organization role's
// ids. That is what makes "a platform constraint never matches inside a tenant"
// true today -- but it is an emergent property of the schema, not a guarantee
// of the algorithm. Filtering explicitly means the behaviour survives any later
// change to how role ids are allocated.
//
// Callers must apply this before evaluating, never instead of it: passing the
// whole table into CheckConstraints and hoping ids do not collide would make
// tenant isolation depend on an ID allocation accident.
func ConstraintsForContext(all []*Constraint, authCtx authorization.Context) []*Constraint {
	want := authCtx.Normalize()
	out := make([]*Constraint, 0, len(all))
	for _, c := range all {
		if c == nil {
			continue
		}
		if c.Context.Normalize() == want {
			out = append(out, c)
		}
	}
	return out
}

// DelegationsForContext mirrors ConstraintsForContext for delegations. A
// platform delegation must not be usable to grant an organization role, and an
// organization delegation must never leak into platform decisions.
func DelegationsForContext(all []*Delegation, authCtx authorization.Context) []*Delegation {
	want := authCtx.Normalize()
	out := make([]*Delegation, 0, len(all))
	for _, d := range all {
		if d == nil {
			continue
		}
		if d.Context.Normalize() == want {
			out = append(out, d)
		}
	}
	return out
}
