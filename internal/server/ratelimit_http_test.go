package server_test

import (
	"net/http"
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
