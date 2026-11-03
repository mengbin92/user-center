package data

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestMFACASRejectsConsumedStateAndInitialOverwrite(t *testing.T) {
	d := testData(t)
	ctx := context.Background()
	repo := NewMFARepo(d)
	state := &biz.MFAState{UserID: 1, Secret: "encrypted", RecoveryHashes: []string{"code-a", "code-b"}, Revision: 1}
	require.NoError(t, repo.Save(ctx, nil, state))
	stale, err := repo.Get(ctx, nil, 1)
	require.NoError(t, err)
	state.RecoveryHashes = []string{"code-b"}
	state.LastStep = 20
	state.Revision++
	require.NoError(t, repo.Save(ctx, nil, state))
	stale.RecoveryHashes = []string{"code-a"}
	stale.Revision++
	require.ErrorIs(t, repo.Save(ctx, nil, stale), biz.ErrRevisionConflict)
	require.ErrorIs(t, repo.Save(ctx, nil, &biz.MFAState{UserID: 1, Secret: "replaced", Revision: 1}), biz.ErrRevisionConflict)
	got, err := repo.Get(ctx, nil, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"code-b"}, got.RecoveryHashes)
	require.EqualValues(t, 20, got.LastStep)
}

func TestConcurrentMemoryRateLimitAndChallengeAttempts(t *testing.T) {
	d := testData(t)
	ctx := context.Background()
	limiter := NewRateLimiter(d)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := limiter.Allow(ctx, "concurrent", 5, time.Hour)
			if err == nil && ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 5, allowed.Load())
	challenges := NewChallengeStore(d)
	c := biz.Challenge{ID: "attempts", Purpose: "test", CodeHash: biz.HMACCode(d.challengeSecret(), "test", "123456"), ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, challenges.Put(ctx, c))
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := challenges.Verify(ctx, "test", "attempts", "wrong")
			require.ErrorIs(t, err, biz.ErrChallengeInvalid)
		}()
	}
	wg.Wait()
	_, err := challenges.Verify(ctx, "test", "attempts", "123456")
	require.ErrorIs(t, err, biz.ErrChallengeInvalid)
}

func TestCompletionRecordRejectsReplay(t *testing.T) {
	d := testData(t)
	repo := NewFlowCompletionRepo(d)
	ctx := context.Background()
	require.NoError(t, repo.Complete(ctx, nil, "challenge", "password_reset", 1, "reset"))
	require.ErrorIs(t, repo.Complete(ctx, nil, "challenge", "password_reset", 1, "reset"), biz.ErrChallengeInvalid)
}

func TestSessionRoleCASRollsBackStaleWrite(t *testing.T) {
	d := testData(t)
	repo := NewSessionRepo(d)
	ctx := context.Background()
	now := time.Now().UTC()
	s := &biz.Session{ID: "role-cas", UserID: 1, TokenHash: biz.HashToken("token"), IdentityVersion: 1, Revision: 1, IssuedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), ActiveRoleIDs: []int64{1}}
	require.NoError(t, repo.Create(ctx, nil, s))
	require.NoError(t, repo.SetActiveRoleIDs(ctx, nil, s.ID, []int64{2}, 1))
	require.ErrorIs(t, repo.SetActiveRoleIDs(ctx, nil, s.ID, []int64{3}, 1), biz.ErrRevisionConflict)
	ids, err := repo.ListActiveRoleIDs(ctx, nil, s.ID)
	require.NoError(t, err)
	require.Equal(t, []int64{2}, ids)
}

func TestMFAResetCannotReviveStaleFactor(t *testing.T) {
	d := testData(t)
	repo := NewMFARepo(d)
	ctx := context.Background()
	state := &biz.MFAState{UserID: 1, Secret: "old", Revision: 1}
	require.NoError(t, repo.Save(ctx, nil, state))
	stale, err := repo.Get(ctx, nil, 1)
	require.NoError(t, err)
	require.NoError(t, repo.Delete(ctx, nil, 1))
	current, err := repo.Get(ctx, nil, 1)
	require.NoError(t, err)
	require.False(t, current.Enabled())
	current.PendingSecret = "new"
	current.Revision++
	require.NoError(t, repo.Save(ctx, nil, current))
	stale.Secret = "revived"
	stale.Revision++
	require.ErrorIs(t, repo.Save(ctx, nil, stale), biz.ErrRevisionConflict)
	current, err = repo.Get(ctx, nil, 1)
	require.NoError(t, err)
	require.Empty(t, current.Secret)
	require.Equal(t, "new", current.PendingSecret)
}
