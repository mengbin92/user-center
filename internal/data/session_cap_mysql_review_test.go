package data

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
)

// The per-user session cap is "count live sessions, revoke the excess, insert".
// With tx=nil those were three separate transactions: two concurrent logins read
// the same pre-insert count, both saw room, and both committed, leaving
// cap+1 live sessions. The fix is one transaction that locks the user row first.
//
// SQLite cannot host this test: it serialises writers with a file lock and
// returns "database is locked" instead of queueing, so the race cannot be
// reproduced there. MySQL is the deployment target and the only place the
// interleaving is observable.
func TestMySQLSessionCapSerialisesOnUserRow(t *testing.T) {
	dsn := os.Getenv("USER_CENTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set USER_CENTER_MYSQL_TEST_DSN after applying migrations to an isolated database")
	}
	secret := "isolated-mysql-test-secret-at-least-32-bytes"
	d, cleanup, err := NewData(&conf.Data{Database: &conf.Database{Driver: "mysql", Source: dsn}}, &conf.Security{SessionSecret: secret, CsrfSecret: secret, MfaEncryptionKey: secret}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	ctx := context.Background()
	users := NewUserRepo(d)
	sessions := NewSessionRepo(d)
	// Unique per test invocation so -count=N in one process stays isolated
	// against the shared database (a PID would repeat).
	suffix := IDs{}.NewID()
	user, err := users.Create(ctx, nil, &biz.User{
		Username: "cap-" + suffix, UsernameNormalized: "cap-" + suffix,
		DisplayName: "cap", Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
	})
	require.NoError(t, err)

	// The critical section of issueSessionLocked, twice, concurrently.
	const limit = 1
	login := func(n int) error {
		return d.InTx(ctx, func(ctx context.Context, tx biz.Tx) error {
			if err := users.LockUser(ctx, tx, user.ID); err != nil {
				return err
			}
			rows, err := sessions.ListByUser(ctx, tx, user.ID)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			live := make([]*biz.Session, 0, len(rows))
			for _, s := range rows {
				if s.Valid(now) {
					live = append(live, s)
				}
			}
			excess := len(live) + 1 - limit
			if excess > len(live) {
				excess = len(live)
			}
			for i := 0; i < excess; i++ {
				if err := sessions.Revoke(ctx, tx, live[i].ID, &now); err != nil {
					return err
				}
			}
			return sessions.Create(ctx, tx, &biz.Session{
				ID: fmt.Sprintf("cap-%s-%d", suffix, n), UserID: user.ID,
				ApplicationCode: biz.ApplicationCode, TokenHash: biz.HashToken(fmt.Sprintf("%s-%d", suffix, n)),
				UserAgent: "cap", IPMasked: "127.0.0.0/8",
				IssuedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
				IdleExpiresAt: now.Add(time.Hour), IdentityVersion: user.IdentityVersion, Revision: 1,
			})
		})
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := range 2 {
		wg.Go(func() { results <- login(i) })
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}

	rows, err := sessions.ListByUser(ctx, nil, user.ID)
	require.NoError(t, err)
	now := time.Now().UTC()
	live := 0
	for _, s := range rows {
		if s.Valid(now) {
			live++
		}
	}
	require.Equal(t, limit, live, "concurrent logins must not exceed the cap")
}
