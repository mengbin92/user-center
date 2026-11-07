package obs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v3/transport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// stubTransport satisfies transport.Transporter so the template branch of
// RouteLabel can be exercised without a live router.
type stubTransport struct {
	template string
}

func (s stubTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (s stubTransport) Endpoint() string                { return "" }
func (s stubTransport) Operation() string               { return s.template }
func (s stubTransport) RequestHeader() transport.Header { return nil }
func (s stubTransport) ReplyHeader() transport.Header   { return nil }
func (s stubTransport) PathTemplate() string            { return s.template }

func withTemplate(ctx context.Context, template string) context.Context {
	return transport.NewServerContext(ctx, stubTransport{template: template})
}

func TestRouteLabelMasksIdentifiers(t *testing.T) {
	// Raw-path fallback: the auth filter sits outside the router, so most
	// requests arrive here without a template.
	for _, path := range []string{
		"/api/v1/admin/users/42",
		"/api/v1/admin/users/31337",
	} {
		require.Equal(t, "/api/v1/admin/users/{id}", RouteLabel(context.Background(), path))
	}
	// A router template is used verbatim.
	ctx := withTemplate(context.Background(), "/api/v1/orgs/{id}/audits")
	require.Equal(t, "/api/v1/orgs/{id}/audits", RouteLabel(ctx, "/api/v1/orgs/7/audits"))
}

func TestRouteLabelCollapsesForeignPaths(t *testing.T) {
	cases := map[string]string{
		"/admin/users/42":      "spa",
		"/assets/index-abc.js": "spa",
		"/":                    "/",
		"/healthz":             "/healthz",
	}
	for path, want := range cases {
		require.Equal(t, want, RouteLabel(context.Background(), path), "path %s", path)
	}
	// HandlePrefix("/") hands every SPA path the template "/".
	ctx := withTemplate(context.Background(), "/")
	require.Equal(t, "spa", RouteLabel(ctx, "/admin/users/42"))
	require.Equal(t, "/", RouteLabel(ctx, "/"))
}

func TestRouteLabelTruncatesLongPaths(t *testing.T) {
	path := "/api/v1/admin/users/1/2/3/4/5/6/7/8/9/10/11"
	label := RouteLabel(context.Background(), path)
	require.True(t, strings.HasSuffix(label, "/**"), "label = %s", label)
	require.LessOrEqual(t, strings.Count(label, "/"), maxRouteSegments+1)
	// Two different over-long URLs must not produce two labels.
	require.Equal(t, label, RouteLabel(context.Background(), path+"2"))
}

func TestHTTPRecordsStatusAndRoute(t *testing.T) {
	m := NewMetrics(nil)
	next := m.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for range 2 {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	}
	require.Equal(t, float64(2), testutil.ToFloat64(
		m.requests.WithLabelValues("/api/v1/auth/login", http.MethodPost, "401")))
	require.Equal(t, float64(2), sampleCount(t, m.duration.WithLabelValues("/api/v1/auth/login", http.MethodPost)))
}

func TestHTTPRecordsServerErrorsUnderOneRoute(t *testing.T) {
	m := NewMetrics(nil)
	next := m.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/orgs/9/members", nil))
	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/orgs/11/members", nil))

	// Both organisation IDs land on the same route label.
	require.Equal(t, float64(2), testutil.ToFloat64(
		m.requests.WithLabelValues("/api/v1/orgs/{id}/members", http.MethodGet, "500")))
}

func TestRefreshSetsGaugesAndKeepsValuesOnError(t *testing.T) {
	probe := &fakeProbe{
		backlog:   map[string]int64{"pending": 3, "delivered": 7, "cancelled": 1, "weird": 2},
		applied:   21,
		dbErr:     nil,
		cacheErr:  errors.New("redis down"),
		poolOpen:  5,
		poolInUse: 3,
		poolMax:   20,
		poolWaits: 12,
	}
	m := NewMetrics(probe)
	m.Refresh(context.Background())

	require.Equal(t, float64(3), testutil.ToFloat64(m.deliveries.WithLabelValues("pending")))
	require.Equal(t, float64(7), testutil.ToFloat64(m.deliveries.WithLabelValues("delivered")))
	require.Equal(t, float64(0), testutil.ToFloat64(m.deliveries.WithLabelValues("retrying")))
	require.Equal(t, float64(2), testutil.ToFloat64(m.deliveries.WithLabelValues("other")))
	require.Equal(t, float64(21), testutil.ToFloat64(m.migrations))
	require.Equal(t, float64(1), testutil.ToFloat64(m.dependency.WithLabelValues("mysql")))
	require.Equal(t, float64(0), testutil.ToFloat64(m.dependency.WithLabelValues("redis")))
	require.Equal(t, float64(5), testutil.ToFloat64(m.pool.WithLabelValues("open")))
	require.Equal(t, float64(3), testutil.ToFloat64(m.pool.WithLabelValues("in_use")))
	require.Equal(t, float64(20), testutil.ToFloat64(m.pool.WithLabelValues("max")))
	require.Equal(t, float64(12), testutil.ToFloat64(m.poolWaits))

	// A failing query must not zero the last known value.
	probe.backlogErr = errors.New("db down")
	probe.dbErr = errors.New("db down")
	m.Refresh(context.Background())
	require.Equal(t, float64(3), testutil.ToFloat64(m.deliveries.WithLabelValues("pending")))
	require.Equal(t, float64(21), testutil.ToFloat64(m.migrations))
	require.Equal(t, float64(0), testutil.ToFloat64(m.dependency.WithLabelValues("mysql")))
}

func TestHandlerExposesCoreSeriesWithoutIdentifiers(t *testing.T) {
	m := NewMetrics(nil)
	next := m.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/4242", nil))
	m.Refresh(context.Background())

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, body, "usercenter_http_requests_total")
	require.Contains(t, body, "usercenter_schema_migrations_applied")
	require.Contains(t, body, "usercenter_dependency_up")
	require.NotContains(t, body, "4242", "user identifiers must never reach the scrape body")
	require.NotContains(t, body, "admin@example.com")
}

func TestRunStopsOnContextCancel(t *testing.T) {
	m := NewMetrics(&fakeProbe{backlog: map[string]int64{}, applied: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx, 10*time.Millisecond)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

type fakeProbe struct {
	backlog    map[string]int64
	applied    int64
	poolOpen   int
	poolInUse  int
	poolMax    int
	poolWaits  int64
	backlogErr error
	appliedErr error
	dbErr      error
	cacheErr   error
	poolErr    error
}

func (p *fakeProbe) OutboxBacklog(context.Context) (map[string]int64, error) {
	return p.backlog, p.backlogErr
}

func (p *fakeProbe) SchemaMigrationsApplied(context.Context) (int64, error) {
	return p.applied, p.appliedErr
}

func (p *fakeProbe) PingDatabase(context.Context) error { return p.dbErr }
func (p *fakeProbe) PingCache(context.Context) error    { return p.cacheErr }

func (p *fakeProbe) DBPoolStats(context.Context) (int, int, int, int64, error) {
	return p.poolOpen, p.poolInUse, p.poolMax, p.poolWaits, p.poolErr
}

func sampleCount(t *testing.T, obs prometheus.Observer) float64 {
	t.Helper()
	hist, ok := obs.(prometheus.Histogram)
	require.True(t, ok)
	var metric dto.Metric
	require.NoError(t, hist.Write(&metric))
	return float64(metric.GetHistogram().GetSampleCount())
}

// Rejected requests never reach the handler, so they only appear here. The
// scope label is what makes "exports are being hammered" distinguishable from
// "someone is clicking save too fast".
func TestRateLimitHitsAreLabeledByScope(t *testing.T) {
	m := NewMetrics(&fakeProbe{})
	m.RateLimited("export")
	m.RateLimited("export")
	m.RateLimited("write")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="export"} 2`)
	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="write"} 1`)
}

// A nil Metrics is the "metrics disabled" path; counting must be a no-op
// instead of a panic in the request path.
func TestRateLimitedIsNilSafe(t *testing.T) {
	var m *Metrics
	require.NotPanics(t, func() { m.RateLimited("write") })
}

// A fresh process that has never rejected a request must still expose every
// documented scope at zero. Before this was fixed, CounterVec had no series at
// all and rate()/increase() expressions returned an empty vector, while
// absent() fired on a perfectly healthy instance. This is the regression lock.
func TestRateLimitScopesAreSeededAtZeroOnFreshMetrics(t *testing.T) {
	m := NewMetrics(&fakeProbe{})

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	require.Contains(t, body, "# TYPE usercenter_rate_limit_hits_total counter")
	for _, scope := range RateLimitScopes {
		require.Contains(t, body, fmt.Sprintf(`usercenter_rate_limit_hits_total{scope="%s"} 0`, scope),
			"scope %q must be present with value 0 in a fresh scrape", scope)
	}
	require.Len(t, RateLimitScopes, 4)
}

// Seeding must not distort counting: an actual rejection still increments from
// zero, and the other scopes stay at zero rather than being bumped.
func TestRateLimitedIncrementsFromSeededZero(t *testing.T) {
	m := NewMetrics(&fakeProbe{})
	m.RateLimited(RateLimitScopeExport)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="export"} 1`)
	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="write"} 0`)
	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="batch"} 0`)
	require.Contains(t, body, `usercenter_rate_limit_hits_total{scope="invite"} 0`)
}
