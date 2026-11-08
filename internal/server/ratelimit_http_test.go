package server_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/conf"
)

// The limiter is easy to get right in isolation and wrong in the chain: it must
// sit after authentication (so the budget is per user, not per IP) and before
// the handler (so a rejected call costs nothing). This drives real HTTP.
func TestWriteBudgetRejectsBurstButNotReads(t *testing.T) {
	h := newHarness(t, withRateLimit(&conf.RateLimit{
		Enabled: true, WritePerMinute: 3, HeavyPerMinute: 1,
	}))
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	// Wrong current password: the handler rejects these, but they still spend
	// budget, which is the point — a limiter that only counts successful calls
	// can be probed for free.
	for i := 0; i < 3; i++ {
		rec := h.changePassword("not-the-password", "Whatever-123")
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code, "write %d must fit the budget", i+1)
	}
	rec := h.changePassword("not-the-password", "Whatever-123")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "RATE_LIMITED")
	require.NotEmpty(t, rec.Header().Get("Retry-After"))

	// Reads share no budget with writes: a throttled admin must still be able
	// to look at the page that explains what happened.
	require.Equal(t, http.StatusOK,
		h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false).Code)
}

// Raw protocol routes are mounted through the same server as the protobuf ones,
// so the global filter chain already runs prepare() and the write limiter for
// them. Wrapping them in mw.Filter a second time (which the OIDC endpoints used
// to do) spent two units of budget per request, halving the configured limit.
func TestRawOIDCRouteSpendsOneBudgetUnitPerRequest(t *testing.T) {
	h := newHarness(t, withRateLimit(&conf.RateLimit{
		Enabled: true, WritePerMinute: 3, HeavyPerMinute: 2,
	}))

	// An anonymous /oidc/token POST is keyed by IP. The endpoint itself rejects
	// it (unknown client, so 401) -- irrelevant here: the assertion is that
	// three attempts fit a budget of three and the fourth is refused.
	form := url.Values{"grant_type": {"authorization_code"}}
	for i := 1; i <= 3; i++ {
		rec := h.doForm("/oidc/token", form, "client", "secret")
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code,
			"attempt %d must fit the configured budget of 3", i)
		require.Less(t, rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	rec := h.doForm("/oidc/token", form, "client", "secret")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "RATE_LIMITED")
}

func TestHeavyEndpointsHaveTheirOwnStricterBudget(t *testing.T) {
	h := newHarness(t, withRateLimit(&conf.RateLimit{
		Enabled: true, WritePerMinute: 100, HeavyPerMinute: 1,
	}))
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	body := map[string]any{"format": "csv"}
	first := h.do(http.MethodPost, "/api/v1/admin/users:export", body, "", true)
	require.NotEqual(t, http.StatusTooManyRequests, first.Code, first.Body.String())

	second := h.do(http.MethodPost, "/api/v1/admin/users:export", body, "", true)
	require.Equal(t, http.StatusTooManyRequests, second.Code, second.Body.String())

	// An ordinary write is still allowed: the heavy budget must not starve the
	// rest of the API when one export is retried.
	require.NotEqual(t, http.StatusTooManyRequests,
		h.changePassword("not-the-password", "Whatever-123").Code)
}
