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

// F1 regression lock. Platform constraints store platform role IDs and org
// decisions carry org role IDs, so the two sets never intersect: a platform
// mutual-exclusion over roles A/B must not reject an org grant of roles 101/102.
//
// This has to stay true. If someone "fixes" CheckConstraints to match across
// the two ID spaces, platform policy would start silently reshaping tenant
// decisions -- so pin the current behaviour explicitly rather than leaving it
// as an accident of ID allocation.
func TestPlatformConstraintsDoNotReachOrganizationDecisions(t *testing.T) {
	// Roles live in ONE table with a global AUTO_INCREMENT primary key, so a
	// platform role id and an organization role id can never be equal. That is
	// why a platform constraint never matches inside a tenant today -- and it is
	// also why this property needs an explicit lock: it depends on role ids
	// being globally unique, which is a schema detail nobody would notice
	// breaking.
	platformConstraint := &Constraint{
		Kind: ConstraintMutualExclusion, Name: "platform-sod",
		RoleIDs: []int64{10, 11}, Enabled: true,
		Context: authorization.Platform(),
	}
	orgRoles := []int64{900, 901}

	require.NoError(t, CheckConstraints(orgRoles, []*Constraint{platformConstraint}),
		"a platform constraint must never constrain organization roles")

	// The real contract is context filtering at load time: even if a caller
	// hands over every constraint in the database, the organization's facts must
	// contain only its own.
	orgConstraint := &Constraint{
		Kind: ConstraintMutualExclusion, Name: "org-sod",
		RoleIDs: []int64{900, 901}, Enabled: true,
		Context: authorization.Organization(7),
	}
	otherOrgConstraint := &Constraint{
		Kind: ConstraintMutualExclusion, Name: "other-org-sod",
		RoleIDs: []int64{900, 901}, Enabled: true,
		Context: authorization.Organization(8),
	}
	filtered := ConstraintsForContext(
		[]*Constraint{platformConstraint, orgConstraint, otherOrgConstraint},
		authorization.Organization(7),
	)
	require.Len(t, filtered, 1)
	require.Equal(t, "org-sod", filtered[0].Name)
	require.Error(t, CheckConstraints(orgRoles, filtered),
		"the organization's own constraint must still apply")
}

func TestConstraintsForContextFiltersByScope(t *testing.T) {
	all := []*Constraint{
		{ID: 1, Name: "platform", Context: authorization.Platform()},
		{ID: 2, Name: "org-7", Context: authorization.Organization(7)},
		{ID: 3, Name: "org-8", Context: authorization.Organization(8)},
		// A row written before 013 has no context at all; it must be treated as
		// platform policy rather than silently dropped.
		{ID: 4, Name: "legacy"},
	}

	platform := ConstraintsForContext(all, authorization.Platform())
	require.Len(t, platform, 2)
	require.Equal(t, "platform", platform[0].Name)
	require.Equal(t, "legacy", platform[1].Name)

	org7 := ConstraintsForContext(all, authorization.Organization(7))
	require.Len(t, org7, 1)
	require.Equal(t, "org-7", org7[0].Name)

	require.Empty(t, ConstraintsForContext(all, authorization.Organization(99)))
}

func TestDelegationsForContextFiltersByScope(t *testing.T) {
	all := []*Delegation{
		{ID: 1, Context: authorization.Platform()},
		{ID: 2, Context: authorization.Organization(7)},
	}
	require.Len(t, DelegationsForContext(all, authorization.Platform()), 1)
	require.Len(t, DelegationsForContext(all, authorization.Organization(7)), 1)
	require.Empty(t, DelegationsForContext(all, authorization.Organization(8)))
}

// max_roles is scoped by role_ids: it limits how many of the LISTED roles one
// member may hold at once, not "how many roles in total". An empty role_ids
// list is skipped entirely by CheckConstraints, so a constraint that lists
// nothing enforces nothing -- the API rejects that shape rather than storing a
// rule that silently does nothing.
func TestMaxRolesIsScopedByRoleIDs(t *testing.T) {
	constraint := &Constraint{
		Kind: ConstraintMaxRoles, Name: "cap", RoleIDs: []int64{900, 901},
		MaxCount: 1, Enabled: true,
		Context: authorization.Organization(7),
	}
	// Both listed roles at once exceeds the cap of 1.
	require.Error(t, CheckConstraints([]int64{900, 901}, []*Constraint{constraint}))
	// One listed role is fine.
	require.NoError(t, CheckConstraints([]int64{900}, []*Constraint{constraint}))
	// Roles outside the list do not consume the budget: the constraint is about
	// the listed pair, not about the account's total role count.
	require.NoError(t, CheckConstraints([]int64{900, 777, 778}, []*Constraint{constraint}))
	// A constraint with no roles is inert, which is why validateConstraint
	// refuses to create one.
	empty := &Constraint{Kind: ConstraintMaxRoles, Name: "inert", MaxCount: 1, Enabled: true}
	require.NoError(t, CheckConstraints([]int64{900, 901}, []*Constraint{empty}))
}

// validateConstraint is shared by the platform and organization paths, so the
// organization cannot store a rule the platform would reject.
func TestValidateConstraintSharedRules(t *testing.T) {
	require.Error(t, validateConstraint(&Constraint{
		Kind: ConstraintMaxRoles, Name: "zero", RoleIDs: []int64{1}, MaxCount: 0,
	}), "max_count=0 must be rejected: it would be silently read as 1")
	require.Error(t, validateConstraint(&Constraint{
		Kind: ConstraintMutualExclusion, Name: "one", RoleIDs: []int64{1},
	}), "mutual exclusion needs two roles")
	require.Error(t, validateConstraint(&Constraint{
		Kind: ConstraintMaxRoles, Name: "no-roles", RoleIDs: nil, MaxCount: 1,
	}), "a constraint that lists no roles enforces nothing")
	require.NoError(t, validateConstraint(&Constraint{
		Kind: ConstraintMaxRoles, Name: "ok", RoleIDs: []int64{1}, MaxCount: 2,
	}))
}
