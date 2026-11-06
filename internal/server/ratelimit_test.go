package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/conf"
)

// fakeLimiter records what the middleware asked for and can be told to refuse.
type fakeLimiter struct {
	keys    []string
	limits  []int
	windows []time.Duration
	deny    bool
	err     error
}

func (f *fakeLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	f.keys = append(f.keys, key)
	f.limits = append(f.limits, limit)
	f.windows = append(f.windows, window)
	if f.err != nil {
		return false, f.err
	}
	return !f.deny, nil
}

func newTestLimiter(f *fakeLimiter) *WriteLimiter {
	return NewWriteLimiter(&conf.Server{RateLimit: &conf.RateLimit{
		Enabled: true, WritePerMinute: 60, HeavyPerMinute: 5,
	}}, f, nil)
}

func TestWriteLimiterScopeClassification(t *testing.T) {
	cases := []struct {
		method   string
		path     string
		wantKind string
		heavy    bool
	}{
		// The four heavy families from the roadmap.
		{http.MethodPost, "/api/v1/admin/users:export", "export", true},
		{http.MethodPost, "/api/v1/admin/audits:export", "export", true},
		{http.MethodPost, "/api/v1/orgs/7/audits:export", "export", true},
		{http.MethodPost, "/api/v1/admin/iam/assignments:batch-assign", "batch", true},
		{http.MethodPost, "/api/v1/orgs/7/invitations", "invite", true},
		// Ordinary writes.
		{http.MethodPost, "/api/v1/admin/iam/assignments", "write", false},
		{http.MethodPatch, "/api/v1/admin/settings/auth", "write", false},
		{http.MethodDelete, "/api/v1/orgs/7/iam/assignments/3", "write", false},
		// Reads are never limited, including a read of an invite list.
		{http.MethodGet, "/api/v1/orgs/7/invitations", "", false},
		{http.MethodGet, "/api/v1/admin/users:export", "", false},
		{http.MethodHead, "/api/v1/admin/users", "", false},
		// Authentication paths keep their existing, separate counters.
		{http.MethodPost, "/api/v1/auth/login", "", false},
		{http.MethodPost, "/api/v1/auth/password:reset", "", false},
	}
	for _, tc := range cases {
		scope, heavy := scopeFor(tc.method, tc.path)
		require.Equal(t, tc.wantKind, scope, "%s %s", tc.method, tc.path)
		require.Equal(t, tc.heavy, heavy, "%s %s heavy flag", tc.method, tc.path)
	}
}

func TestWriteLimiterAppliesHeavyBudget(t *testing.T) {
	f := &fakeLimiter{}
	w := newTestLimiter(f)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users:export", nil)
	allowed, scope := w.Allow(context.Background(), req)
	require.True(t, allowed)
	require.Equal(t, "export", scope)
	require.Equal(t, []int{5}, f.limits)
	require.Equal(t, []time.Duration{time.Minute}, f.windows)
	// Anonymous requests fall back to IP; the request was built without a
	// session so there is no actor to key by.
	require.Equal(t, []string{"rl:export:ip:192.0.2.1"}, f.keys)
}

func TestWriteLimiterSkipsReadsWithoutCounting(t *testing.T) {
	f := &fakeLimiter{}
	w := newTestLimiter(f)
	allowed, scope := w.Allow(context.Background(), httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil))
	require.True(t, allowed)
	require.Empty(t, scope)
	require.Empty(t, f.keys, "a read must not consume a write budget")
}

func TestWriteLimiterFailsOpenWhenBackendIsDown(t *testing.T) {
	f := &fakeLimiter{err: errors.New("redis down")}
	w := newTestLimiter(f)
	allowed, scope := w.Allow(context.Background(), httptest.NewRequest(http.MethodPost, "/api/v1/admin/iam/assignments", nil))
	require.True(t, allowed, "a limiter outage must not turn into an outage of the API")
	require.Equal(t, "write", scope)
}

func TestWriteLimiterRejectContract(t *testing.T) {
	f := &fakeLimiter{deny: true}
	w := newTestLimiter(f)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/iam/assignments", nil)
	allowed, _ := w.Allow(context.Background(), req)
	require.False(t, allowed)

	w.Reject(rec)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Contains(t, rec.Body.String(), "RATE_LIMITED")
	// Retry-After must be a positive integer: a zero or negative value makes
	// clients retry immediately and turns the limiter into a retry amplifier.
	raw := rec.Header().Get("Retry-After")
	require.NotEmpty(t, raw)
	secs, err := strconv.Atoi(raw)
	require.NoError(t, err)
	require.GreaterOrEqual(t, secs, 1)
	require.LessOrEqual(t, secs, 60)
}

func TestWriteLimiterDisabledNeverCounts(t *testing.T) {
	f := &fakeLimiter{}
	w := NewWriteLimiter(&conf.Server{RateLimit: &conf.RateLimit{Enabled: false}}, f, nil)
	allowed, _ := w.Allow(context.Background(), httptest.NewRequest(http.MethodPost, "/api/v1/admin/users:export", nil))
	require.True(t, allowed)
	require.Empty(t, f.keys)
}
