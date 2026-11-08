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

// The metric label must come from the server's own route table, so this asserts
// the table is actually populated by construction: the protobuf routes come from
// WalkRoute, the raw handlers (probes, OIDC, provider callbacks, artifact
// downloads) are registered explicitly, and anything else is "unknown".
//
// Without this wiring the matcher would be empty and every request would quietly
// label itself "unknown" -- correct-looking, useless, and impossible to notice.
func TestServerRouteTableClassifiesRequests(t *testing.T) {
	h := newHarness(t)
	require.Greater(t, h.metrics.Routes().Len(), 100, "the protobuf route table must be walked")

	for _, tc := range []struct{ method, path, want string }{
		// Protobuf route, with an action suffix and a numeric identifier.
		{http.MethodPost, "/api/v1/admin/users/4242:archive", "/api/v1/admin/users/{id}:archive"},
		// The same path under a different method resolves to its own template.
		{http.MethodGet, "/api/v1/admin/users/4242", "/api/v1/admin/users/{id}"},
		// Raw handlers must be in the table too.
		{http.MethodGet, "/readyz", "/readyz"},
		{http.MethodGet, "/healthz", "/healthz"},
		{http.MethodPost, "/oidc/token", "/oidc/token"},
		{http.MethodGet, "/api/v1/auth/providers/github/callback", "/api/v1/auth/providers/{provider}/callback"},
		// SPA history routes collapse into one label; invented API paths do not
		// become labels at all.
		{http.MethodGet, "/admin/users", "spa"},
		{http.MethodGet, "/api/v1/unknown-tenant-1", "unknown"},
	} {
		require.Equal(t, tc.want, h.metrics.RouteLabel(tc.method, tc.path),
			"%s %s", tc.method, tc.path)
	}
}
