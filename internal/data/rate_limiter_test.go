package data

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Allow is a fixed-window counter. Two properties matter for the middleware
// that depends on it: the window actually rolls over, and concurrent callers
// cannot exceed the limit.

func TestRateLimiterRejectsOverLimit(t *testing.T) {
	l := NewRateLimiter(testData(t))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ok, err := l.Allow(ctx, "test-basic", 3, time.Minute)
		require.NoError(t, err)
		require.True(t, ok, "call %d must be within the limit", i+1)
	}
	ok, err := l.Allow(ctx, "test-basic", 3, time.Minute)
	require.NoError(t, err)
	require.False(t, ok, "the fourth call must be rejected")
}

func TestRateLimiterWindowRollsOver(t *testing.T) {
	l := NewRateLimiter(testData(t))
	ctx := context.Background()
	window := 200 * time.Millisecond

	require.True(t, mustAllow(t, l, ctx, "test-rollover", 1, window))
	require.False(t, mustAllow(t, l, ctx, "test-rollover", 1, window),
		"the budget must be spent inside the window")

	// Wait for the next window. The bucket is derived from the Unix time
	// truncated to the window, so this is deterministic across the boundary.
	time.Sleep(window + 50*time.Millisecond)
	require.True(t, mustAllow(t, l, ctx, "test-rollover", 1, window),
		"a new window must restore the budget")
}

func TestRateLimiterIsAtomicUnderConcurrency(t *testing.T) {
	l := NewRateLimiter(testData(t))
	ctx := context.Background()

	const limit = 5
	const callers = 40
	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, err := l.Allow(ctx, "test-concurrent", limit, time.Minute); err == nil && ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// With Redis this comes from INCR's atomicity; with the in-memory fallback
	// from the mutex. Either way, exactly `limit` callers may pass — a "close
	// enough" result here means the limiter can be overshot under load.
	require.EqualValues(t, limit, allowed.Load())
}

func TestRateLimiterTreatsNonPositiveLimitAsUnlimited(t *testing.T) {
	l := NewRateLimiter(testData(t))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		require.True(t, mustAllow(t, l, ctx, "test-unlimited", 0, time.Minute))
	}
}

func mustAllow(t *testing.T, l interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}, ctx context.Context, key string, limit int, window time.Duration) bool {
	t.Helper()
	ok, err := l.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	return ok
}
