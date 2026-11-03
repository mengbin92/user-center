package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestActorAwareIntersectionNeverExpandsSelf(t *testing.T) {
	for _, scope := range []Scope{{UserIDs: []int64{9}}, {Self: true, UserIDs: []int64{9}}} {
		result := IntersectForActor(Scope{Self: true}, scope, 7)
		require.False(t, result.Matches(7, 9, false))
	}
	require.True(t, IntersectForActor(Scope{Self: true}, Scope{UserIDs: []int64{7, 9}}, 7).Matches(7, 7, false))
	result := IntersectForActor(Scope{Self: true, UserIDs: []int64{9}}, Scope{UserIDs: []int64{7, 9, 10}}, 7)
	require.ElementsMatch(t, []int64{7, 9}, result.UserIDs)
	require.False(t, Covers(Scope{Self: true}, Scope{Self: true, UserIDs: []int64{9}}))
	require.ErrorIs(t, ValidateInheritance(map[int64][]int64{1: {2}}), ErrGraph)
}

func TestFutureDenyBoundsDecisionLifetime(t *testing.T) {
	now := time.Now().UTC()
	starts := now.Add(time.Minute)
	d := Evaluate(Input{
		Actor: Actor{UserID: 7, SessionID: "session", ExpiresAt: now.Add(time.Hour)}, Now: now,
		IdentityValid: true, SessionValid: true, Operation: "read", OperationEnabled: true, OperationBound: true,
		SupportedScopes: []ScopeKind{All}, TargetUserID: 9, ConstraintsPass: true, BusinessRulesPass: true,
		Sources: []GrantSource{
			{Operation: "read", Effect: Allow, RoleScope: Scope{All: true}, Boundary: Scope{All: true}, Active: true, Validity: Interval{StartsAt: now.Add(-time.Minute)}},
			{Operation: "read", Effect: Deny, RoleScope: Scope{All: true}, Boundary: Scope{All: true}, Validity: Interval{StartsAt: starts}},
		},
	})
	require.True(t, d.Allowed)
	require.Equal(t, starts, *d.ValidUntil)
}
