// Package obs holds the Prometheus instrumentation for the user center.
//
// It deliberately depends on nothing but the standard library, the Prometheus
// client and the gorilla/mux matcher the HTTP router already uses: the
// repository queries that feed the gauges are injected as a probe interface so
// storage knowledge stays in internal/data.
package obs

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Rate-limit scope labels. These live in obs rather than in the HTTP layer so
// the scrape can expose the complete label set from startup without obs having
// to import server (which would invert the dependency).
//
// A CounterVec emits a series only after WithLabelValues is called for that
// label. Without seeding, a service that has never rejected a request exposes
// no usercenter_rate_limit_hits_total series at all: not "0", but absent. Any
// rate()/increase() expression then returns an empty vector, and an absent()
// alert fires on a perfectly healthy instance. Defining the set here makes the
// seeding and the writer agree on the same labels.
const (
	RateLimitScopeWrite  = "write"
	RateLimitScopeExport = "export"
	RateLimitScopeBatch  = "batch"
	RateLimitScopeInvite = "invite"
)

// RateLimitScopes is the complete, stable set of scope labels. Operators can
// rely on every one of these being present in a fresh scrape with value 0.
var RateLimitScopes = []string{
	RateLimitScopeWrite,
	RateLimitScopeExport,
	RateLimitScopeBatch,
	RateLimitScopeInvite,
}

// MetricsProbe supplies the storage facts behind the gauges. Implementations
// live in internal/data; every method must be cheap enough to run on a timer
// and must not panic when the dependency is down.
type MetricsProbe interface {
	OutboxBacklog(ctx context.Context) (map[string]int64, error)
	SchemaMigrationsApplied(ctx context.Context) (int64, error)
	PingDatabase(ctx context.Context) error
	PingCache(ctx context.Context) error
	// DBPoolStats reports the sql.DB pool. Exhausted pools are a real outage
	// mode: the dev profile's max_open_conns=1 cost 3.5x throughput, and the
	// same shape (in_use == max) is invisible without these numbers.
	DBPoolStats(ctx context.Context) (open, inUse, maxConnections int, waitTotal int64, err error)
}

// DefaultRefreshInterval is how often the gauges are recomputed.
const DefaultRefreshInterval = 30 * time.Second

type Metrics struct {
	registry *prometheus.Registry
	probe    MetricsProbe
	routes   *RouteSet

	requests   *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	deliveries *prometheus.GaugeVec
	migrations prometheus.Gauge
	dependency *prometheus.GaugeVec
	pool       *prometheus.GaugeVec
	poolWaits  prometheus.Gauge
	throttled  *prometheus.CounterVec
}

func NewMetrics(probe MetricsProbe) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		probe:    probe,
		// Always non-nil: an unconfigured set matches nothing and collapses
		// every request into "unknown"/"spa", which is the safe default.
		routes: NewRouteSet(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "usercenter_http_requests_total",
			Help: "HTTP requests by route template, method and status code.",
		}, []string{"route", "method", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "usercenter_http_request_duration_seconds",
			Help:    "HTTP request latency by route template and method.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"route", "method"}),
		deliveries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "usercenter_event_deliveries",
			Help: "Outbox delivery rows by status.",
		}, []string{"status"}),
		migrations: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "usercenter_schema_migrations_applied",
			Help: "Number of recorded schema migration steps.",
		}),
		dependency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "usercenter_dependency_up",
			Help: "1 when the dependency answered its last probe, 0 otherwise.",
		}, []string{"dependency"}),
		pool: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "usercenter_db_pool_connections",
			Help: "sql.DB pool occupancy: open, in_use, max.",
		}, []string{"state"}),
		poolWaits: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "usercenter_db_pool_wait_total",
			Help: "Cumulative count of connections waited for: non-zero growth means the pool is too small.",
		}),
		throttled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "usercenter_rate_limit_hits_total",
			Help: "Requests rejected by the write rate limiter, by scope.",
		}, []string{"scope"}),
	}
	m.registry.MustRegister(
		m.requests, m.duration, m.deliveries, m.migrations, m.dependency, m.pool, m.poolWaits, m.throttled,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	// Register the label sets up front so panels do not start blank. Both the
	// dependency gauges and the rate-limit counter must be seeded: a counter
	// with no series is invisible to rate()/increase(), not zero.
	for _, dep := range []string{"mysql", "redis"} {
		m.dependency.WithLabelValues(dep).Set(0)
	}
	for _, scope := range RateLimitScopes {
		// Add(0) creates the series without changing its value. Using
		// WithLabelValues alone also works but reads as an accident; the
		// explicit zero makes the intent obvious to the next reader.
		m.throttled.WithLabelValues(scope).Add(0)
	}
	return m
}

// Handler serves the scrape endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

// HTTP records one observation per completed request. It must sit outside the
// auth middleware so 401/403 short-circuits are counted too.
func (m *Metrics) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := m.RouteLabel(r.Method, r.URL.Path)
		method := MethodLabel(r.Method)
		status := strconv.Itoa(rec.status)
		m.requests.WithLabelValues(route, method, status).Inc()
		m.duration.WithLabelValues(route, method).Observe(time.Since(start).Seconds())
	})
}

// Routes is the template table this instance classifies requests against. The
// server fills it during construction (protobuf routes via WalkRoute, raw
// handlers explicitly) and then stops writing to it.
func (m *Metrics) Routes() *RouteSet {
	if m == nil {
		return nil
	}
	return m.routes
}

// Refresh recomputes the gauges once. Probe errors leave the previous value in
// place instead of zeroing it: a scrape must never claim the database is gone
// just because one query timed out.
func (m *Metrics) Refresh(ctx context.Context) {
	if m.probe == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if backlog, err := m.probe.OutboxBacklog(ctx); err == nil {
		// Fold unknown statuses into "other" here as well: the label set is
		// this package's contract, and a stray value from a future writer must
		// not widen it.
		totals := make(map[string]float64, len(backlog))
		for status, n := range backlog {
			if !knownDeliveryStatus(status) {
				status = "other"
			}
			totals[status] += float64(n)
		}
		for _, status := range deliveryStatuses {
			m.deliveries.WithLabelValues(status).Set(totals[status])
		}
	}
	if applied, err := m.probe.SchemaMigrationsApplied(ctx); err == nil {
		m.migrations.Set(float64(applied))
	}
	if open, inUse, maxConns, waitTotal, err := m.probe.DBPoolStats(ctx); err == nil {
		m.pool.WithLabelValues("open").Set(float64(open))
		m.pool.WithLabelValues("in_use").Set(float64(inUse))
		m.pool.WithLabelValues("max").Set(float64(maxConns))
		m.poolWaits.Set(float64(waitTotal))
	}
	m.dependency.WithLabelValues("mysql").Set(boolGauge(m.probe.PingDatabase(ctx)))
	m.dependency.WithLabelValues("redis").Set(boolGauge(m.probe.PingCache(ctx)))
}

// Run refreshes the gauges until ctx is done.
func (m *Metrics) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	m.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Refresh(ctx)
		}
	}
}

// deliveryStatuses mirrors the values written by the outbox repository plus the
// catch-all bucket for anything unrecognised.
var deliveryStatuses = []string{"pending", "retrying", "delivering", "delivered", "cancelled", "other"}

func knownDeliveryStatus(status string) bool {
	for _, known := range deliveryStatuses {
		if status == known {
			return true
		}
	}
	return false
}

func boolGauge(err error) float64 {
	if err == nil {
		return 1
	}
	return 0
}

// Ready reports whether the service can serve requests right now, and why not
// if it cannot.
//
// This is separate from a liveness check on purpose. Liveness answers "should
// the orchestrator restart me" -- a process that is up but cannot reach MySQL
// must NOT be restarted, because restarting does not bring the database back
// and a restart loop loses the logs that explain the outage. Readiness answers
// "should traffic come here", and for that the database is mandatory.
//
// Redis is reported but not fatal: without it step-up and rate limiting degrade
// (documented in docs/security.md as fail-open), while authentication still
// works against MySQL. Failing readiness on Redis would turn a cache outage
// into a full outage.
func (m *Metrics) Ready(ctx context.Context) (ready bool, checks map[string]string) {
	checks = map[string]string{"mysql": "ok", "redis": "ok"}
	if m == nil || m.probe == nil {
		// No probe configured (unit tests, CLI paths): nothing to verify, so the
		// honest answer is "ready" rather than a permanent 503.
		return true, checks
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ready = true
	if err := m.probe.PingDatabase(ctx); err != nil {
		checks["mysql"] = err.Error()
		ready = false
	}
	if err := m.probe.PingCache(ctx); err != nil {
		checks["redis"] = err.Error()
	}
	return ready, checks
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	// A handler that writes without an explicit WriteHeader implies 200; the
	// default in the struct already covers it, but mark the header as written
	// so a later WriteHeader cannot rewrite the status after body bytes.
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

// RouteLabel returns the low-cardinality route key for a request path.
//
// The label comes from the registered template table and nowhere else. A path
// that is not a registered route becomes one of two constants:
//
//	"spa"     a client-side history route or asset, served by the SPA catch-all
//	"unknown" anything else, including invented /api/v1/... URLs
//
// Deriving the label from the request URL (even with numeric segments masked)
// is not acceptable: `/api/v1/admin/users/alice:archive` and
// `/api/v1/unknown-tenant-1` would each become their own series, so an
// unauthenticated caller controls the process's memory and the scrape size.
func (m *Metrics) RouteLabel(method, rawPath string) string {
	if m == nil {
		return ClassifyPath(nil, method, rawPath)
	}
	return ClassifyPath(m.routes, method, rawPath)
}

// ClassifyPath is the single decision point behind every route label: the
// request counter, the latency histogram and the slow-request log all call it,
// so they cannot drift apart. See Metrics.RouteLabel for why the request URL is
// never used as the label itself.
func ClassifyPath(routes *RouteSet, method, rawPath string) string {
	if template, ok := routes.Match(method, rawPath); ok {
		return template
	}
	if isSPAPath(rawPath) {
		return "spa"
	}
	return "unknown"
}

// MethodLabel maps the request method onto a closed set. The raw method is
// attacker-controlled in the same way the path is: arbitrary tokens would each
// create a series.
func MethodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "other"
	}
}

// isSPAPath reports whether the path can only be the single-page app: it is
// outside every API family, so the SPA catch-all handles it (or would, when
// built). Collapsing them is correct because the SPA has no per-url semantics
// the operator can act on.
func isSPAPath(rawPath string) bool {
	if rawPath == "" || rawPath == "/" {
		return true
	}
	return !hasAnyPrefix(rawPath, instrumentedPrefixes)
}

// instrumentedPrefixes are the families that belong to the server's own API
// surface. A path outside them is SPA traffic; inside them but unmatched is an
// unknown endpoint.
var instrumentedPrefixes = []string{"/api/", "/oidc/", "/.well-known/", "/healthz", "/readyz"}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// RateLimited counts a rejection so the 429 can be alerted on per scope. A
// rejected request never reaches the handler, so it also never appears in the
// status-labelled request counter.
func (m *Metrics) RateLimited(scope string) {
	if m == nil {
		return
	}
	m.throttled.WithLabelValues(scope).Inc()
}
