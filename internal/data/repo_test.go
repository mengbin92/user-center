package data

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
)

func testData(t *testing.T) *Data {
	t.Helper()
	sec := &conf.Security{SessionSecret: "test", CsrfSecret: "test", MfaEncryptionKey: "test"}
	dataConf := &conf.Data{Database: &conf.Database{
		Driver: "sqlite", Source: "file:" + filepath.Join(t.TempDir(), "repo.db") + "?_fk=1",
	}}
	d, cleanup, err := NewData(dataConf, sec, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.NoError(t, d.AutoMigrate())
	require.NoError(t, SeedCatalog(d.DB()))
	return d
}

func TestUserRepoUniquenessAndCAS(t *testing.T) {
	d := testData(t)
	repo := NewUserRepo(d)
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := repo.Create(ctx, nil, &biz.User{
		Username: "alice", UsernameNormalized: "alice", DisplayName: "Alice",
		Email: "alice@example.com", EmailNormalized: "alice@example.com",
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotZero(t, u.ID)

	// Duplicate normalized username is rejected by the unique index.
	_, err = repo.Create(ctx, nil, &biz.User{
		Username: "ALICE", UsernameNormalized: "alice", DisplayName: "Alice2",
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	require.Error(t, err)

	got, err := repo.GetByEmail(ctx, nil, "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)
	require.True(t, got.EmailVerified == false)

	got.DisplayName = "Alice Updated"
	updated, err := repo.Update(ctx, nil, got, got.Revision)
	require.NoError(t, err)
	require.Equal(t, "Alice Updated", updated.DisplayName)
	require.EqualValues(t, 2, updated.Revision)

	_, err = repo.Update(ctx, nil, got, 1)
	require.Error(t, err)

	users, total, err := repo.List(ctx, nil, biz.UserFilter{Scope: authorization.Scope{All: true}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.EqualValues(t, 1, total)

	scoped, total, err := repo.List(ctx, nil, biz.UserFilter{
		Scope: authorization.Scope{UserIDs: []int64{u.ID + 100}}, ActorID: u.ID, Limit: 10,
	})
	require.NoError(t, err)
	require.Empty(t, scoped)
	require.EqualValues(t, 0, total)

	version, err := repo.BumpIdentityVersion(ctx, nil, u.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, version)
}

func TestSessionAndCatalogRepos(t *testing.T) {
	d := testData(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	sessions := NewSessionRepo(d)
	iam := NewIAMRepo(d)
	policy := NewPolicyRepo(d)

	now := time.Now().UTC()
	u, err := users.Create(ctx, nil, &biz.User{
		Username: "bob", UsernameNormalized: "bob", DisplayName: "Bob",
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	role, err := iam.GetRoleByCode(ctx, nil, "member")
	require.NoError(t, err)
	require.NotEmpty(t, role.Grants)

	rev, err := policy.PolicyRevision(ctx, nil)
	require.NoError(t, err)
	next, err := policy.BumpPolicyRevision(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, rev+1, next)

	s := &biz.Session{
		ID: "sess-1", UserID: u.ID, ApplicationCode: biz.ApplicationCode,
		TokenHash: biz.HashToken("raw"), IssuedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		IdentityVersion: 1, Revision: 1, ActiveRoleIDs: []int64{role.ID},
	}
	require.NoError(t, sessions.Create(ctx, nil, s))
	found, err := sessions.GetByTokenHash(ctx, nil, biz.HashToken("raw"))
	require.NoError(t, err)
	require.Equal(t, "sess-1", found.ID)

	roles, err := sessions.ListActiveRoleIDs(ctx, nil, "sess-1")
	require.NoError(t, err)
	require.Equal(t, []int64{role.ID}, roles)

	require.NoError(t, sessions.SetActiveRoleIDs(ctx, nil, "sess-1", nil))
	roles, err = sessions.ListActiveRoleIDs(ctx, nil, "sess-1")
	require.NoError(t, err)
	require.Empty(t, roles)
	revoked := now
	require.NoError(t, sessions.Revoke(ctx, nil, "sess-1", &revoked))
	got, err := sessions.Get(ctx, nil, "sess-1")
	require.NoError(t, err)
	require.False(t, got.Valid(time.Now().UTC()))

	settings := NewSettingsRepo(d)
	auth, err := settings.GetAuth(ctx, nil)
	require.NoError(t, err)
	require.True(t, auth.RegistrationEnabled)
	auth.PasswordMinLength = 12
	saved, err := settings.SaveAuth(ctx, nil, auth, 0)
	require.NoError(t, err)
	require.EqualValues(t, 2, saved.Revision)
	_, err = settings.SaveAuth(ctx, nil, auth, 1)
	require.Error(t, err)
}

func TestSeedIsIdempotent(t *testing.T) {
	d := testData(t)
	require.NoError(t, SeedCatalog(d.DB()))
	iam := NewIAMRepo(d)
	roles, err := iam.ListRoles(context.Background(), nil, biz.RoleFilter{})
	require.NoError(t, err)
	require.Len(t, roles, 3)
}
