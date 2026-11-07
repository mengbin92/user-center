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

// Readiness needs the database, so with a working fixture it must be 200. The
// failing branch is covered in internal/obs (a fake probe), because breaking the
// real database from an HTTP test would be a much slower way to assert the same
// thing.
func TestReadyzReportsDependencyState(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/readyz", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"status":"ok"`)
	require.Contains(t, rec.Body.String(), `"mysql":"ok"`)
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
