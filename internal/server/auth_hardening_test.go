package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/data"
)

// changePassword drives the self-service change endpoint, which is the only
// path that both validates the policy and rewrites the credential.
func (h *harness) changePassword(current, next string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(http.MethodPost, "/api/v1/me/password:change",
		map[string]any{"current_password": current, "new_password": next}, "", true)
}

func (h *harness) setAuthSettings(mutate func(*biz.AuthSettings)) {
	h.t.Helper()
	ctx := context.Background()
	repo := data.NewSettingsRepo(h.d)
	settings, err := repo.GetAuth(ctx, nil)
	require.NoError(h.t, err)
	mutate(settings)
	_, err = repo.SaveAuth(ctx, nil, settings, settings.Revision)
	require.NoError(h.t, err)
}

func TestPasswordHistoryRejectsTheBootstrapPassword(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	rec := h.changePassword("ChangeMe-12345", "Plausible-999")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Rotating back to the original password must be refused: it is inside the
	// history window, which bootstrap seeded. Without the seed this would pass,
	// because "same as current" only covers the immediately previous value.
	rec = h.changePassword("Plausible-999", "ChangeMe-12345")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PASSWORD_POLICY_VIOLATION")

	// The rejected attempt must not have changed anything: the current password
	// is still the one set moments ago.
	require.Equal(t, http.StatusOK, h.login("root", "Plausible-999").Code)
}

func TestPasswordCompositionIsEnforcedOnChange(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	// 20 lowercase characters pass the length rule but satisfy only one class.
	rec := h.changePassword("ChangeMe-12345", "abcdefghijklmnopqrst")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PASSWORD_POLICY_VIOLATION")
	require.Contains(t, rec.Body.String(), "3 类字符")
}

func TestPasswordPolicyCanBeRelaxedAtRuntime(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	// Composition off and no history: the same weak value must now be accepted,
	// which proves the rule is settings-driven rather than hard-coded.
	h.setAuthSettings(func(s *biz.AuthSettings) {
		s.PasswordMinClasses = 0
		s.PasswordHistoryCount = 0
	})
	rec := h.changePassword("ChangeMe-12345", "abcdefghijklmnopqrst")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestSessionCapReclaimsLeastRecentlyUsed(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	ctx := context.Background()
	root, err := h.svc.Users.GetByUsername(ctx, nil, "root")
	require.NoError(t, err)

	// Start from a clean slate so only the logins below compete for the cap.
	require.NoError(t, h.svc.Sessions.RevokeAllForUser(ctx, nil, root.ID, nil))
	h.setAuthSettings(func(s *biz.AuthSettings) { s.MaxSessionsPerUser = 2 })

	for i := 0; i < 3; i++ {
		rec := h.login("root", "ChangeMe-12345")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var reply struct {
			RecycledSessions int32 `json:"recycled_sessions"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reply))
		if i < 2 {
			// The cap is not reached yet, so nothing may be reclaimed.
			require.Zero(t, reply.RecycledSessions, "login %d reclaimed a session below the cap", i+1)
			continue
		}
		// The third login is the first to exceed a cap of two.
		require.EqualValues(t, 1, reply.RecycledSessions,
			"the login reply must say a session was reclaimed")
	}

	rows, err := h.svc.Sessions.ListByUser(ctx, nil, root.ID)
	require.NoError(t, err)
	live := 0
	for _, s := range rows {
		if s.RevokedAt == nil {
			live++
		}
	}
	require.Equal(t, 2, live, "server-side sessions must be capped, not only hidden from the list")
}

// A per-user cap must never let one account evict another account's sessions.
func TestSessionCapIsPerUser(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	ctx := context.Background()
	other, err := h.svc.Users.Create(ctx, nil, &biz.User{
		Username: "cap-other", UsernameNormalized: "cap-other", DisplayName: "cap-other",
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, h.svc.Sessions.Create(ctx, nil, &biz.Session{
		ID: "cap-other-session", UserID: other.ID, ApplicationCode: biz.ApplicationCode,
		TokenHash: biz.HashToken("cap-other-token"), UserAgent: "bench", IPMasked: "127.0.0.0/8",
		IssuedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		IdentityVersion: 1, Revision: 1,
	}))

	h.setAuthSettings(func(s *biz.AuthSettings) { s.MaxSessionsPerUser = 1 })
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	}

	rows, err := h.svc.Sessions.ListByUser(ctx, nil, other.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Nil(t, rows[0].RevokedAt, "another account's session was collected by root's cap")
}

// Eviction must pick the least recently used session, not an arbitrary one.
// Backdating one session's last_seen_at makes the order observable; without
// this the test only proves "some session was reclaimed".
func TestSessionCapEvictsLeastRecentlyUsed(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	ctx := context.Background()
	root, err := h.svc.Users.GetByUsername(ctx, nil, "root")
	require.NoError(t, err)
	require.NoError(t, h.svc.Sessions.RevokeAllForUser(ctx, nil, root.ID, nil))

	now := time.Now().UTC()
	mk := func(id string, lastSeen time.Time) {
		require.NoError(t, h.svc.Sessions.Create(ctx, nil, &biz.Session{
			ID: id, UserID: root.ID, ApplicationCode: biz.ApplicationCode,
			TokenHash: biz.HashToken(id), UserAgent: "bench", IPMasked: "127.0.0.0/8",
			IssuedAt: lastSeen, LastSeenAt: lastSeen,
			ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
			IdentityVersion: 1, Revision: 1,
		}))
	}
	mk("stale-session", now.Add(-2*time.Hour))
	mk("fresh-session", now.Add(-1*time.Minute))

	// Cap of 2 with two existing sessions: the next login must reclaim exactly
	// one, and it must be the stale one.
	h.setAuthSettings(func(s *biz.AuthSettings) { s.MaxSessionsPerUser = 2 })
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	stale, err := h.svc.Sessions.Get(ctx, nil, "stale-session")
	require.NoError(t, err)
	require.NotNil(t, stale.RevokedAt, "the least recently used session must be the one reclaimed")

	fresh, err := h.svc.Sessions.Get(ctx, nil, "fresh-session")
	require.NoError(t, err)
	require.Nil(t, fresh.RevokedAt, "the recently used session must be kept")
}

// Revoking a session by id must be scoped to the caller: a valid id belonging
// to someone else has to look like a 404, not a 403 that confirms it exists.
func TestRevokeSessionCannotTouchAnotherUser(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	ctx := context.Background()
	other, err := h.svc.Users.Create(ctx, nil, &biz.User{
		Username: "revoke-other", UsernameNormalized: "revoke-other", DisplayName: "revoke-other",
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, h.svc.Sessions.Create(ctx, nil, &biz.Session{
		ID: "victim-session", UserID: other.ID, ApplicationCode: biz.ApplicationCode,
		TokenHash: biz.HashToken("victim-token"), UserAgent: "bench", IPMasked: "127.0.0.0/8",
		IssuedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		IdentityVersion: 1, Revision: 1,
	}))

	rec := h.do(http.MethodDelete, "/api/v1/me/sessions/victim-session", nil, "", true)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	victim, err := h.svc.Sessions.Get(ctx, nil, "victim-session")
	require.NoError(t, err)
	require.Nil(t, victim.RevokedAt, "another user's session must survive")
}

// revoke-others must produce a security event: it is the signal an incident
// review looks for after a suspected compromise.
func TestRevokeOtherSessionsRecordsSecurityEvent(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	ctx := context.Background()
	root, err := h.svc.Users.GetByUsername(ctx, nil, "root")
	require.NoError(t, err)
	countKind := func() int {
		events, _, err := h.svc.Events.ListByUser(ctx, nil, root.ID, 200, "")
		require.NoError(t, err)
		n := 0
		for _, e := range events {
			if e.Kind == "session_revoke_others" {
				n++
			}
		}
		return n
	}
	before := countKind()

	rec := h.do(http.MethodPost, "/api/v1/me/sessions:revoke-others", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Greater(t, countKind(), before, "expected a session_revoke_others security event")
}
