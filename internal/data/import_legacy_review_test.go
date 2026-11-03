package data

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

func legacyReviewSpec(t *testing.T) LegacyImportSpec {
	t.Helper()
	hash, err := biz.HashPassword("LegacyPass-123")
	require.NoError(t, err)
	return LegacyImportSpec{SourceCommit: "4116899a", Users: []LegacyUser{{ID: 42, Username: " Legacy.User ", Email: " LEGACY@example.com ", Status: "1", PasswordHash: hash, RoleCodes: []string{"member", "admin"}}}}
}

func TestLegacyCandidatesCannotActivateGovernanceRoles(t *testing.T) {
	d := testData(t)
	spec := legacyReviewSpec(t)
	result, err := ImportLegacy(context.Background(), d, spec, "review-candidates", true)
	require.NoError(t, err)
	require.Empty(t, result.Conflicts)
	require.True(t, result.Applied)
	var assignments []assignmentPO
	require.NoError(t, d.DB().Where("user_id = ?", 42).Find(&assignments).Error)
	require.Len(t, assignments, 2)
	for _, a := range assignments {
		var role rolePO
		require.NoError(t, d.DB().First(&role, a.RoleID).Error)
		var scope authorization.Scope
		require.NoError(t, jsonx.Unmarshal([]byte(a.Boundary), &scope))
		if role.Code == "member" {
			require.Equal(t, "active", a.Status)
			require.True(t, scope.Self)
		} else {
			require.Equal(t, "pending", a.Status)
			require.False(t, scope.All)
			require.False(t, scope.Self)
			require.Empty(t, scope.UserIDs)
		}
	}
	roles, err := NewUserRepo(d).RolesForUser(context.Background(), nil, 42)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	require.Equal(t, "member", roles[0].Code)
}

func TestLegacyDryRunDoesNotMutateSnapshotOrFingerprint(t *testing.T) {
	d := testData(t)
	spec := legacyReviewSpec(t)
	dry, err := ImportLegacy(context.Background(), d, spec, "dry", false)
	require.NoError(t, err)
	require.Empty(t, dry.Conflicts)
	require.Equal(t, " Legacy.User ", spec.Users[0].Username)
	require.Equal(t, " LEGACY@example.com ", spec.Users[0].Email)
	require.Equal(t, "1", spec.Users[0].Status)
	applied, err := ImportLegacy(context.Background(), d, spec, "apply", true)
	require.NoError(t, err)
	require.True(t, applied.Applied)
	require.Equal(t, dry.Fingerprint, applied.Fingerprint)
}

func TestLegacyImportRejectsUnusableIdentityData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LegacyUser)
	}{
		{"missing login credential", func(u *LegacyUser) { u.PasswordHash = "" }},
		{"fake bcrypt prefix", func(u *LegacyUser) { u.PasswordHash = "$2garbage" }},
		{"invalid bcrypt cost", func(u *LegacyUser) { u.PasswordHash = "$2a$99$" + strings.Repeat("a", 53) }},
		{"invalid email", func(u *LegacyUser) { u.Email = "not-an-email" }},
		{"verified empty email", func(u *LegacyUser) { u.Email = ""; u.EmailVerified = true }},
		{"oversized display name", func(u *LegacyUser) { u.DisplayName = strings.Repeat("a", 129) }},
		{"duplicate role", func(u *LegacyUser) { u.RoleCodes = []string{"member", "member"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testData(t)
			spec := legacyReviewSpec(t)
			tc.change(&spec.Users[0])
			result, err := ImportLegacy(context.Background(), d, spec, "rejected", true)
			require.NoError(t, err)
			require.False(t, result.Applied)
			require.NotEmpty(t, result.Conflicts)
			var count int64
			require.NoError(t, d.DB().Model(&userPO{}).Where("id = ?", 42).Count(&count).Error)
			require.Zero(t, count)
			require.NoError(t, d.DB().Model(&legacyImportBatchPO{}).Count(&count).Error)
			require.Zero(t, count)
		})
	}
}
