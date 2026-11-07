package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/obs"
)

// WriteLimiter bounds how fast one subject can call non-safe endpoints.
//
// It deliberately covers only methods that change state: a read-only dashboard
// polling every second must never be throttled by a security control, and
// throttling reads would push clients into retry storms. The authentication
// endpoints are excluded as well — they already have per-IP and per-account
// counters in the business layer, and running both would either double-count
// (one request consuming two budgets) or, worse, let a caller pick the looser
// path. One counter per concern, and this middleware is not one of them.
type WriteLimiter struct {
	limiter biz.RateLimiter
	metrics *obs.Metrics
	enabled bool
	write   int
	heavy   int
	window  time.Duration
	now     func() time.Time
}

// Default budgets. Exposed as defaults rather than hard-coded so tests and
// operators can reason about them in one place.
const (
	DefaultWritePerMinute = 120
	DefaultHeavyPerMinute = 10
)

func NewWriteLimiter(cfg *conf.Server, limiter biz.RateLimiter, metrics *obs.Metrics) *WriteLimiter {
	w := &WriteLimiter{
		limiter: limiter,
		metrics: metrics,
		enabled: true,
		write:   DefaultWritePerMinute,
		heavy:   DefaultHeavyPerMinute,
		window:  time.Minute,
		now:     func() time.Time { return time.Now().UTC() },
	}
	if cfg != nil && cfg.RateLimit != nil {
		w.enabled = cfg.RateLimit.Enabled
		if cfg.RateLimit.WritePerMinute > 0 {
			w.write = int(cfg.RateLimit.WritePerMinute)
		}
		if cfg.RateLimit.HeavyPerMinute > 0 {
			w.heavy = int(cfg.RateLimit.HeavyPerMinute)
		}
	}
	return w
}

// heavyScopes maps a request to a stricter budget. Matching is on the raw path
// because the route template is not available at this point in the chain; the
// suffixes below are stable API shapes, not resource identifiers.
var heavyScopes = []struct {
	scope string
	match func(string) bool
}{
	{obs.RateLimitScopeExport, func(p string) bool { return strings.HasSuffix(p, ":export") }},
	{obs.RateLimitScopeBatch, func(p string) bool {
		return strings.HasSuffix(p, ":batch-assign") || strings.HasSuffix(p, ":batch-preview")
	}},
	{obs.RateLimitScopeInvite, func(p string) bool { return strings.HasSuffix(p, "/invitations") }},
}

// scopeFor returns the metric scope and whether the request is subject to a
// heavy budget. An empty scope means "not limited by this middleware".
func scopeFor(method, path string) (string, bool) {
	if isSafeMethod(method) {
		return "", false
	}
	// Existing per-endpoint limits own these paths; see the type comment.
	if strings.HasPrefix(path, "/api/v1/auth/") || strings.HasPrefix(path, "/api/v1/me/oidc-requests/") {
		return "", false
	}
	for _, h := range heavyScopes {
		if h.match(path) {
			return h.scope, true
		}
	}
	return obs.RateLimitScopeWrite, false
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// subjectKey identifies who is being limited. An authenticated caller is keyed
// by user id, an integration caller by client id, and only genuinely anonymous
// writes fall back to IP — so one user behind a shared NAT never consumes
// another user's budget.
func subjectKey(ctx context.Context, r *http.Request) string {
	if actor, ok := biz.ActorFromContext(ctx); ok {
		if actor.Actor.ServiceID != "" {
			return "c:" + actor.Actor.ServiceID
		}
		if actor.User != nil && actor.User.ID != 0 {
			return "u:" + strconv.FormatInt(actor.User.ID, 10)
		}
	}
	return "ip:" + clientIP(r, false)
}

// Allow reports whether the request may proceed. The bool is "limited at all",
// which keeps the caller from needing to duplicate the scope logic.
func (w *WriteLimiter) Allow(ctx context.Context, r *http.Request) (bool, string) {
	if w == nil || !w.enabled || w.limiter == nil {
		return true, ""
	}
	scope, heavy := scopeFor(r.Method, r.URL.Path)
	if scope == "" {
		return true, ""
	}
	limit := w.write
	if heavy {
		limit = w.heavy
	}
	key := "rl:" + scope + ":" + subjectKey(ctx, r)
	ok, err := w.limiter.Allow(ctx, key, limit, w.window)
	if err != nil {
		// A limiter outage must not take the API down: failing open keeps writes
		// working and the dependency gauge already reports the broken backend.
		return true, scope
	}
	if ok {
		return true, scope
	}
	w.metrics.RateLimited(scope)
	return false, scope
}

// Reject writes the 429 contract in one place: status, stable reason, wait hint
// and a body shaped like every other API error so clients do not need a special
// case. Kept separate from the middleware so it can be asserted directly.
func (w *WriteLimiter) Reject(rec http.ResponseWriter) {
	rec.Header().Set("Retry-After", strconv.Itoa(w.retryAfterSeconds()))
	writeError(rec, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁，请稍后再试")
}

// retryAfterSeconds returns how long the caller should wait before the current
// fixed window rolls over. A fixed window can be optimistic by design, but the
// advertised wait is never longer than the window itself.
func (w *WriteLimiter) retryAfterSeconds() int {
	window := w.window
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now().UTC()
	if w.now != nil {
		now = w.now()
	}
	remaining := window - time.Duration(now.UnixNano()%int64(window))
	secs := int(remaining / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}
