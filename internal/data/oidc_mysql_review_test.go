package data

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOIDCMySQLExactRedirectAndSingleConsumption(t *testing.T) {
	dsn := os.Getenv("USER_CENTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set USER_CENTER_MYSQL_TEST_DSN after applying migrations to an isolated database")
	}
	secret := "isolated-mysql-test-secret-at-least-32-bytes"
	d, cleanup, err := NewData(&conf.Data{Database: &conf.Database{Driver: "mysql", Source: dsn}}, &conf.Security{SessionSecret: secret, CsrfSecret: secret, MfaEncryptionKey: secret}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	repo := NewOIDCCodeRepo(d)
	ctx := context.Background()
	now := time.Now().UTC()
	clients := NewOIDCClientRepo(d)
	client, err := clients.CreateOIDCClient(ctx, nil, &biz.OIDCClient{ClientID: "MySQLReview" + IDs{}.NewID(), Name: "Review", ServiceOwner: "review", Scopes: []string{"openid"}, RedirectURIs: []string{"https://app.example.com/Callback"}})
	require.NoError(t, err)
	_, err = clients.GetOIDCClientByClientID(ctx, nil, strings.ToLower(client.ClientID))
	require.ErrorIs(t, err, biz.ErrOIDCClientNotFound)
	code := &biz.OIDCCode{CodeHash: biz.HashToken(IDs{}.NewID()), ClientID: client.ClientID, UserID: 1, IdentityVersion: 7,
		RedirectURI: "https://app.example.com/Callback", Scope: "openid", AuthTime: now, ExpiresAt: now.Add(time.Minute)}
	require.NoError(t, repo.CreateOIDCCode(ctx, nil, code))
	_, err = repo.ConsumeOIDCCode(ctx, nil, code.CodeHash, code.ClientID, strings.ToLower(code.RedirectURI), now)
	require.ErrorIs(t, err, biz.ErrOIDCInvalidGrant, "case-insensitive MySQL collation must not relax redirect matching")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range cap(results) {
		wg.Go(func() {
			grant, err := repo.ConsumeOIDCCode(ctx, nil, code.CodeHash, code.ClientID, code.RedirectURI, now)
			if err == nil && grant.IdentityVersion != code.IdentityVersion {
				err = biz.ErrOIDCInvalidGrant
			}
			results <- err
		})
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
	require.Equal(t, 1, successes, "an authorization code must be consumed exactly once")
}
