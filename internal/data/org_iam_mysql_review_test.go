package data

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
)

// Two admins granting two mutually exclusive roles to the same member used to
// both succeed: each transaction locked a different role row, read the same
// pre-insert set, and passed its own exclusion check. The invariant belongs to
// the member's role *set*, so the lock has to be shared between the two paths --
// which is what AssignRole now takes first (the policy row, the same lock every
// constraint write already holds).
//
// This reproduces the critical section with the real repositories on MySQL.
// Without the policy lock the two goroutines interleave and both commit; with it
// they serialise and the second sees the first.
func TestMySQLOrgAssignmentSerialisesOnPolicyRevision(t *testing.T) {
	dsn := os.Getenv("USER_CENTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set USER_CENTER_MYSQL_TEST_DSN after applying migrations to an isolated database")
	}
	secret := "isolated-mysql-test-secret-at-least-32-bytes"
	d, cleanup, err := NewData(&conf.Data{Database: &conf.Database{Driver: "mysql", Source: dsn}}, &conf.Security{SessionSecret: secret, CsrfSecret: secret, MfaEncryptionKey: secret}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	ctx := context.Background()
	org := authorization.Organization(424242)
	orgIAM := NewOrgIAMRepo(d)
	iam := NewIAMRepo(d)
	policy := NewPolicyRepo(d)

	// A unique suffix keeps repeated runs against the same database
	// independent, including -count=N inside one test process (a PID would
	// not).
	suffix := IDs{}.NewID()
	mustRole := func(code string) int64 {
		role, err := orgIAM.CreateRole(ctx, nil, org, &biz.Role{
			Code: code + "-" + suffix, Name: code, Status: biz.RoleStatusActive,
		})
		require.NoError(t, err)
		return role.ID
	}
	roleX := mustRole("sod-x")
	roleY := mustRole("sod-y")

	// The member must be a real user row: ListAssignments joins users, so an
	// invented id makes every read return nothing and the test would pass or
	// fail for reasons unrelated to the lock.
	member, err := NewUserRepo(d).Create(ctx, nil, &biz.User{
		Username: "sod-" + suffix, UsernameNormalized: "sod-" + suffix,
		DisplayName: "sod", Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
	})
	require.NoError(t, err)
	userID := member.ID

	_, err = iam.CreateConstraint(ctx, nil, &biz.Constraint{
		Kind: biz.ConstraintMutualExclusion, Name: "mysql-sod-" + suffix,
		RoleIDs: []int64{roleX, roleY}, Enabled: true, Context: org,
	})
	require.NoError(t, err)

	// The critical section of AssignRole, twice, concurrently.
	assign := func(roleID int64) error {
		return d.InTx(ctx, func(ctx context.Context, tx biz.Tx) error {
			if _, err := policy.PolicyRevision(ctx, tx); err != nil {
				return err
			}
			if _, err := orgIAM.GetRoleForUpdate(ctx, tx, org, roleID); err != nil {
				return err
			}
			items, err := orgIAM.ListAssignments(ctx, tx, org, userID)
			if err != nil {
				return err
			}
			held := make([]int64, 0, len(items)+1)
			for _, item := range items {
				if item.Assignment != nil && !item.Assignment.Revoked {
					held = append(held, item.Assignment.RoleID)
				}
			}
			constraints, err := iam.ListConstraints(ctx, tx, org)
			if err != nil {
				return err
			}
			if err := biz.CheckConstraints(append(held, roleID), constraints); err != nil {
				return err
			}
			_, err = orgIAM.CreateAssignment(ctx, tx, org, &biz.Assignment{
				UserID: userID, RoleID: roleID, Boundary: authorization.Scope{All: true},
				Origin: biz.OriginExplicit,
			})
			return err
		})
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, roleID := range []int64{roleX, roleY} {
		wg.Go(func() { results <- assign(roleID) })
	}
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, biz.ErrRoleConstraint):
			rejected++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	require.Equal(t, 1, succeeded, "at most one of two mutually exclusive grants may commit")
	require.Equal(t, 1, rejected)

	// And the stored state must not contain the violating pair. Exactly one row
	// must be visible: a fixture whose join matches nothing would make the
	// concurrency assertions above meaningless.
	items, err := orgIAM.ListAssignments(ctx, nil, org, userID)
	require.NoError(t, err)
	require.Len(t, items, 1, "the assignment must be visible to the same query the usecase uses")
	held := make([]int64, 0, len(items))
	for _, item := range items {
		if item.Assignment != nil && !item.Assignment.Revoked {
			held = append(held, item.Assignment.RoleID)
		}
	}
	constraints, err := iam.ListConstraints(ctx, nil, org)
	require.NoError(t, err)
	require.NoError(t, biz.CheckConstraints(held, constraints))
}
