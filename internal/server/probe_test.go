package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The two probes answer different questions, and the deployment depends on the
// difference. The S13 restore drill found /healthz being used as the container
// health check: it returned 200 with the database dropped, so the orchestrator
// kept an instance in rotation that could not serve a single request.
//
// These tests pin the split so a future "simplification" cannot merge them back
// into one endpoint that checks nothing.
func TestHealthzIsLivenessOnly(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/healthz", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"status":"ok"`)
}

// Readiness needs the database, so with a working fixture it must be 200.
func TestReadyzReportsDependencyState(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/readyz", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"status":"ok"`)
	require.Contains(t, rec.Body.String(), `"mysql":"ok"`)
}

// The wiring test the previous version was missing: it injected a nil probe,
// which answers "ready" without touching anything, so a green /readyz proved
// nothing. Dropping the sentinel table is the S13 failure in its smallest form,
// and it must fail readiness while liveness stays green.
func TestReadyzFailsWhenTheSchemaIsGone(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/readyz", nil, "", false).Code)

	require.NoError(t, h.d.DB().Exec("DROP TABLE users").Error)

	rec := h.do(http.MethodGet, "/readyz", nil, "", false)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"status":"unavailable"`)
	require.NotContains(t, rec.Body.String(), `"mysql":"ok"`)

	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/healthz", nil, "", false).Code,
		"liveness must not depend on the database")
}

// Neither probe may require authentication or a CSRF token: they are polled by
// infrastructure that has no session, and a 401 here would make every orchestrator
// mark the instance unhealthy.
func TestProbesAreUnauthenticated(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := h.do(http.MethodGet, path, nil, "", false)
		require.Equal(t, http.StatusOK, rec.Code, "%s must not require auth", path)
	}
}
