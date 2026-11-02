package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScopeValidateAndMatch(t *testing.T) {
	require.NoError(t, Scope{All: true}.Validate(nil))
	require.ErrorIs(t, Scope{}.Validate(nil), ErrScope)
	require.ErrorIs(t, Scope{Self: true}.Validate([]ScopeKind{All}), ErrScope)
	require.NoError(t, Scope{Self: true}.Validate([]ScopeKind{All, Self}))

	all := Scope{All: true}
	require.True(t, all.Matches(1, 99, false))
	require.True(t, all.Matches(1, 99, true))

	self := Scope{Self: true}
	require.True(t, self.Matches(7, 7, false))
	require.False(t, self.Matches(7, 8, false))

	users := Scope{UserIDs: []int64{3, 4}}
	require.True(t, users.Matches(7, 4, false))
	require.False(t, users.Matches(7, 5, false))
	require.False(t, users.Matches(7, 4, true))
}

func TestIntersect(t *testing.T) {
	require.Equal(t, Scope{UserIDs: []int64{2}}, Intersect(Scope{All: true}, Scope{UserIDs: []int64{2}}))
	require.Equal(t, Scope{Self: true}, Intersect(Scope{Self: true}, Scope{Self: true}))
	require.Equal(t, Scope{UserIDs: []int64{9}}, Intersect(Scope{Self: true}, Scope{UserIDs: []int64{9}}))
	require.Equal(t, Scope{UserIDs: []int64{2}}, Intersect(Scope{UserIDs: []int64{1, 2}}, Scope{UserIDs: []int64{2, 3}}))
	require.True(t, Intersect(Scope{UserIDs: []int64{1}}, Scope{UserIDs: []int64{2}}).Empty())
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	actor := Actor{UserID: 10, SessionID: "s1", ExpiresAt: now.Add(time.Hour)}
	end := now.Add(time.Hour * 24)
	base := Input{
		Actor: actor, Now: now, IdentityValid: true, SessionValid: true,
		Operation: "identity.user.read", OperationEnabled: true, OperationBound: true,
		SupportedScopes: []ScopeKind{All, Self, Users}, TargetUserID: 10,
		ConstraintsPass: true, BusinessRulesPass: true,
		Sources: []GrantSource{{
			RoleID: 1, RoleCode: "member", Operation: "identity.user.read", Effect: Allow,
			RoleScope: Scope{All: true}, Boundary: Scope{All: true},
			Validity: Interval{StartsAt: now.Add(-time.Hour), ExpiresAt: &end}, Active: true,
		}},
	}
	d := Evaluate(base)
	require.True(t, d.Allowed)
	require.Equal(t, "ALLOWED", d.Reason)
	require.NotNil(t, d.ValidUntil)

	inactive := base
	inactive.Sources = []GrantSource{base.Sources[0]}
	inactive.Sources[0].Active = false
	require.False(t, Evaluate(inactive).Allowed)

	denied := base
	denied.Sources = append(denied.Sources, GrantSource{
		RoleID: 2, Operation: "identity.user.read", Effect: Deny,
		RoleScope: Scope{All: true}, Boundary: Scope{All: true},
		Validity: Interval{StartsAt: now.Add(-time.Hour)}, Active: true,
	})
	require.False(t, Evaluate(denied).Allowed)
	require.Equal(t, "DENY_MATCHED", Evaluate(denied).Reason)

	expired := base
	expired.Sources[0].Validity.ExpiresAt = ptr(now.Add(-time.Minute))
	require.False(t, Evaluate(expired).Allowed)

	unbound := base
	unbound.OperationBound = false
	require.False(t, Evaluate(unbound).Allowed)

	whole := base
	whole.WholeObject = true
	whole.TargetUserID = 0
	whole.Sources[0].RoleScope = Scope{Self: true}
	require.False(t, Evaluate(whole).Allowed)
}

func TestInheritance(t *testing.T) {
	edges := map[int64][]int64{1: {2}, 2: {3}, 3: nil}
	require.NoError(t, ValidateInheritance(edges))
	require.Equal(t, []int64{1, 2, 3}, ResolveInheritance(1, edges))

	cycle := map[int64][]int64{1: {2}, 2: {1}}
	require.ErrorIs(t, ValidateInheritance(cycle), ErrGraph)
	require.ErrorIs(t, ValidateInheritance(map[int64][]int64{1: {1}}), ErrGraph)
}

func ptr[T any](v T) *T { return &v }
