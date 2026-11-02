package biz

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
)

func TestDelegationAllows(t *testing.T) {
	now := time.Now().UTC()
	end := now.Add(time.Hour)
	scope := authorization.Scope{UserIDs: []int64{42}}
	d := &Delegation{
		ManagerRoleID: 5, TargetRoleID: 7, Actions: []string{"assign"},
		TargetUserScope: scope, StartsAt: now.Add(-time.Minute), ExpiresAt: &end,
	}
	roles := []int64{5}
	require.True(t, DelegationAllows([]*Delegation{d}, roles, 42, 7, "assign", scope, now))
	require.False(t, DelegationAllows([]*Delegation{d}, roles, 43, 7, "assign", scope, now))
	require.False(t, DelegationAllows([]*Delegation{d}, roles, 42, 8, "assign", scope, now))
	require.False(t, DelegationAllows([]*Delegation{d}, roles, 42, 7, "revoke", scope, now))
	require.False(t, DelegationAllows([]*Delegation{d}, roles, 42, 7, "assign", authorization.Scope{All: true}, now))
	require.False(t, DelegationAllows([]*Delegation{d}, []int64{6}, 42, 7, "assign", scope, now))

	expired := *d
	expired.ExpiresAt = ptrTime(now.Add(-time.Second))
	require.False(t, DelegationAllows([]*Delegation{&expired}, roles, 42, 7, "assign", scope, now))

	revokedAt := now
	revoked := *d
	revoked.RevokedAt = &revokedAt
	require.False(t, DelegationAllows([]*Delegation{&revoked}, roles, 42, 7, "assign", scope, now))
}
