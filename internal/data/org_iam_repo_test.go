package data

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

func TestOrgIAMRepoIsolatesContexts(t *testing.T) {
	d := testData(t)
	repo := NewOrgIAMRepo(d)
	ctx := context.Background()
	orgA := authorization.Organization(11)
	orgB := authorization.Organization(22)

	roleA, err := repo.CreateRole(ctx, nil, orgA, &biz.Role{Code: "auditor", Name: "Auditor", Status: biz.RoleStatusActive})
	require.NoError(t, err)
	require.NotZero(t, roleA.ID)

	// The same code may exist in another tenant without collision.
	roleB, err := repo.CreateRole(ctx, nil, orgB, &biz.Role{Code: "auditor", Name: "Auditor", Status: biz.RoleStatusActive})
	require.NoError(t, err)
	require.NotEqual(t, roleA.ID, roleB.ID)

	rolesA, err := repo.ListRoles(ctx, nil, orgA)
	require.NoError(t, err)
	require.Len(t, rolesA, 1)
	require.Equal(t, roleA.ID, rolesA[0].ID)
	require.True(t, rolesA[0].Context.Equal(orgA))

	// Cross-tenant lookups fail closed.
	_, err = repo.GetRole(ctx, nil, orgB, roleA.ID)
	require.ErrorIs(t, err, biz.ErrResourceNotFound)
	_, err = repo.GetRole(ctx, nil, authorization.Platform(), roleA.ID)
	require.ErrorIs(t, err, biz.ErrResourceNotFound)

	// Grants and assignments stay in their context.
	revA, err := repo.PutRoleGrants(ctx, nil, orgA, roleA.ID, []biz.Grant{{
		Operation: biz.PermOrgAuditRead, Effect: authorization.Allow, Scope: authorization.Scope{All: true},
	}}, roleA.Revision)
	require.NoError(t, err)
	roleA.Revision = revA

	assignment, err := repo.CreateAssignment(ctx, nil, orgA, &biz.Assignment{
		UserID: 7, RoleID: roleA.ID, Boundary: authorization.Scope{All: true}, Origin: biz.OriginExplicit,
	})
	require.NoError(t, err)

	_, err = repo.GetAssignment(ctx, nil, orgB, assignment.ID)
	require.ErrorIs(t, err, biz.ErrResourceNotFound)

	itemsB, err := repo.ListAssignments(ctx, nil, orgB, 0)
	require.NoError(t, err)
	require.Empty(t, itemsB)

	// Revoking through another tenant must not affect the row.
	require.Error(t, repo.RevokeAssignment(ctx, nil, orgB, assignment.ID, assignment.Revision, 1))

	// Platform policy queries never see tenant roles.
	iam := NewIAMRepo(d)
	platformRoles, err := iam.ListAllRolesWithGrants(ctx, nil)
	require.NoError(t, err)
	for _, role := range platformRoles {
		require.NotEqual(t, roleA.ID, role.ID)
		require.NotEqual(t, roleB.ID, role.ID)
	}

	// Tenant-scoped updates carry the context in the WHERE clause.
	roleA.Name = "Auditor A"
	updated, err := repo.UpdateRole(ctx, nil, orgA, roleA, roleA.Revision)
	require.NoError(t, err)
	require.Equal(t, "Auditor A", updated.Name)
	_, err = repo.UpdateRole(ctx, nil, orgB, roleA, updated.Revision)
	require.Error(t, err, "another tenant must not be able to update the role")
}
