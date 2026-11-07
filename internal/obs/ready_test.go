package obs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// A live process that cannot reach MySQL must not be reported ready: traffic
// would be routed to an instance that fails every request, and the orchestrator
// would keep it in rotation because the liveness endpoint is fine.
func TestReadyFailsWhenDatabaseIsDown(t *testing.T) {
	probe := &fakeProbe{dbErr: errors.New("dial tcp 10.0.0.5:3306: connect: connection refused")}
	ready, checks := NewMetrics(probe).Ready(context.Background())

	require.False(t, ready)
	require.Contains(t, checks["mysql"], "connection refused")
}

// Redis down degrades rate limiting and step-up but leaves authentication
// working, so readiness stays true. Failing here would convert a cache blip into
// a full outage -- the opposite of the documented fail-open behaviour.
func TestReadyStaysTrueWhenOnlyCacheIsDown(t *testing.T) {
	probe := &fakeProbe{cacheErr: errors.New("redis: connection refused")}
	ready, checks := NewMetrics(probe).Ready(context.Background())

	require.True(t, ready)
	require.Contains(t, checks["redis"], "connection refused")
	require.Equal(t, "ok", checks["mysql"])
}

// With no probe configured (unit tests, CLI paths) there is nothing to verify;
// answering "not ready" would make every such caller see a permanent 503.
func TestReadyWithoutProbeIsTrue(t *testing.T) {
	ready, checks := NewMetrics(nil).Ready(context.Background())
	require.True(t, ready)
	require.Equal(t, "ok", checks["mysql"])

	var nilMetrics *Metrics
	ready, _ = nilMetrics.Ready(context.Background())
	require.True(t, ready, "a nil Metrics must not panic or claim unreadiness")
}
