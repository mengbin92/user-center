package data

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestOIDCRepoPreservesConfigurationAndCAS(t *testing.T) {
	d := testData(t)
	r := NewOIDCClientRepo(d)
	ctx := context.Background()
	c, err := r.CreateOIDCClient(ctx, nil, &biz.OIDCClient{
		ClientID: "client", Name: "Client", ServiceOwner: "app", RequirePKCE: false,
		RedirectURIs: []string{"https://app.example.com/callback"}, Scopes: []string{"openid"},
	})
	require.NoError(t, err)
	require.False(t, c.RequirePKCE, "an explicit false must not become the GORM default")
	_, err = r.RotateOIDCClientSecret(ctx, nil, c.ID, "new-hash", c.Revision+1)
	require.ErrorIs(t, err, biz.ErrRevisionConflict)
	updated, err := r.RotateOIDCClientSecret(ctx, nil, c.ID, "new-hash", c.Revision)
	require.NoError(t, err)
	require.Equal(t, c.Revision+1, updated.Revision)
	require.ErrorIs(t, r.DisableOIDCClient(ctx, nil, c.ID, c.Revision), biz.ErrRevisionConflict)
	require.NoError(t, r.DisableOIDCClient(ctx, nil, c.ID, updated.Revision))
}

func TestOIDCRefreshReplayRevokesOnlyItsFamily(t *testing.T) {
	d := testData(t)
	r := NewOIDCCodeRepo(d)
	ctx := context.Background()
	now := time.Now().UTC()
	makeRefresh := func(hash, family, client string) {
		require.NoError(t, r.CreateOIDCRefreshToken(ctx, nil, &biz.OIDCRefreshToken{
			TokenHash: hash, FamilyID: family, ClientID: client, UserID: 1,
			IdentityVersion: 7, Scope: "openid offline_access", AuthTime: now, ExpiresAt: now.Add(time.Hour),
		}))
	}
	makeRefresh("parent", "family-1", "client")
	parent, err := r.ConsumeOIDCRefreshToken(ctx, nil, "parent", "client", now)
	require.NoError(t, err)
	require.Equal(t, uint64(7), parent.IdentityVersion)
	makeRefresh("child", "family-1", "client")
	makeRefresh("unrelated", "family-2", "client")
	// A different client cannot trigger another client's family revocation.
	_, err = r.ConsumeOIDCRefreshToken(ctx, nil, "parent", "other-client", now)
	require.ErrorIs(t, err, biz.ErrOIDCInvalidGrant)
	var active int64
	require.NoError(t, d.DB().Model(&oidcRefreshPO{}).Where("token_hash = ? AND revoked_at IS NULL", "child").Count(&active).Error)
	require.Equal(t, int64(1), active)
	var replay *biz.OIDCRefreshToken
	require.NoError(t, d.InTx(ctx, func(ctx context.Context, tx biz.Tx) error {
		var err error
		replay, err = r.ConsumeOIDCRefreshToken(ctx, tx, "parent", "client", now)
		require.ErrorIs(t, err, biz.ErrOIDCInvalidGrant)
		return nil
	}))
	require.NotNil(t, replay)
	_, err = r.ConsumeOIDCRefreshToken(ctx, nil, "child", "client", now)
	require.ErrorIs(t, err, biz.ErrOIDCInvalidGrant)
	_, err = r.ConsumeOIDCRefreshToken(ctx, nil, "unrelated", "client", now)
	require.NoError(t, err)
}

func TestOIDCAuthorizationCodeConsumedOnce(t *testing.T) {
	d := testData(t)
	sqlDB, err := d.DB().DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	r := NewOIDCCodeRepo(d)
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, r.CreateOIDCCode(ctx, nil, &biz.OIDCCode{
		CodeHash: "code", ClientID: "client", UserID: 1, IdentityVersion: 9,
		RedirectURI: "https://app.example.com/callback", Scope: "openid", AuthTime: now, ExpiresAt: now.Add(time.Minute),
	}))
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, err := r.ConsumeOIDCCode(ctx, nil, "code", "client", "https://app.example.com/callback", now)
			if err == nil && code.IdentityVersion != 9 {
				err = fmt.Errorf("identity version was lost")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, biz.ErrOIDCInvalidGrant)
		}
	}
	require.Equal(t, 1, successes)
}

func TestConsentUpsertAdvancesRevisionAndKeepsScopes(t *testing.T) {
	d := testData(t)
	repo := NewOIDCConsentRepo(d)
	ctx := context.Background()

	require.NoError(t, repo.UpsertConsent(ctx, nil, &biz.OIDCConsent{
		ClientID: "client", UserID: 7, Scopes: []string{"openid"},
	}))
	first, err := repo.GetConsent(ctx, nil, "client", 7)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Revision)

	// Approving a widened scope set updates the row and advances revision; it
	// must not stay pinned at 1 (lost-update detection depends on it).
	require.NoError(t, repo.UpsertConsent(ctx, nil, &biz.OIDCConsent{
		ClientID: "client", UserID: 7, Scopes: []string{"openid", "profile"},
	}))
	second, err := repo.GetConsent(ctx, nil, "client", 7)
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.Revision)
	require.ElementsMatch(t, []string{"openid", "profile"}, second.Scopes)
}
