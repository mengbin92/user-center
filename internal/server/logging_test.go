package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
)

func testMiddleware(t *testing.T, thresholdMS string) (*Middleware, *observer.ObservedLogs) {
	t.Helper()
	t.Setenv("SLOW_REQUEST_THRESHOLD_MS", thresholdMS)
	core, logs := observer.New(zapcore.WarnLevel)
	return NewMiddleware(nil, &conf.Security{}, zap.New(core)), logs
}

func TestSlowRequestLogsRouteAndDurationButNoBody(t *testing.T) {
	mw, logs := testMiddleware(t, "1")

	const secret = "SuperSecret-Passw0rd"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A handler that reads the body and a request that carries a password:
		// neither the secret nor any body content may reach the log.
		buf := make([]byte, 256)
		_, _ = r.Body.Read(buf)
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	// A public path: an authenticated one would be rejected in prepare before
	// reaching the handler, and the test would not exercise a slow request.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/context", strings.NewReader(secret))
	req.Header.Set("X-Request-ID", "req-abc-123")
	mw.Filter(handler).ServeHTTP(httptest.NewRecorder(), req)

	entries := logs.All()
	require.Len(t, entries, 1, "a slow request must produce exactly one log line")
	entry := entries[0]
	require.Equal(t, "slow request", entry.Message)

	fields := entry.ContextMap()
	require.Equal(t, "req-abc-123", fields["request_id"])
	require.Equal(t, "/api/v1/auth/context", fields["route"])
	require.Equal(t, http.MethodGet, fields["method"])
	require.Equal(t, int64(http.StatusOK), fields["status"])
	require.GreaterOrEqual(t, fields["duration_ms"].(float64), 1.0)

	// No body content may appear in any string field. Only strings are checked:
	// duration_ms and status are numbers and a coincidental match there is noise.
	for key, value := range fields {
		if text, ok := value.(string); ok {
			require.NotContains(t, text, secret, "field %s leaked the request body", key)
		}
	}

	// Field whitelist: adding a field to this log line is a decision, not an
	// accident. Anything new must be reviewed for personal data.
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	require.ElementsMatch(t,
		[]string{"request_id", "route", "method", "status", "duration_ms"}, keys)
}

func TestFastRequestIsNotLogged(t *testing.T) {
	mw, logs := testMiddleware(t, "60000")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw.Filter(handler).ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/auth/context", nil))
	require.Empty(t, logs.All(), "requests under the threshold must not be logged")
}

func TestRequestIDIsGeneratedWhenAbsentAndCappedWhenTooLong(t *testing.T) {
	mw, logs := testMiddleware(t, "1")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
	})

	// Absent header: the middleware must still put an id in the context so the
	// audit row and the log line agree.
	var seen string
	mw.Filter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = biz.RequestID(r.Context())
		time.Sleep(2 * time.Millisecond)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/auth/context", nil))
	require.NotEmpty(t, seen)
	require.LessOrEqual(t, len(seen), 64)
	require.Equal(t, seen, logs.All()[0].ContextMap()["request_id"])

	// An oversized header is replaced, not truncated: truncating would let two
	// different callers collide on the same id.
	long := strings.Repeat("x", 65)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/context", nil)
	req.Header.Set("X-Request-ID", long)
	logs.TakeAll()
	mw.Filter(handler).ServeHTTP(httptest.NewRecorder(), req)
	require.NotEqual(t, long, logs.All()[0].ContextMap()["request_id"])
}

func TestRequireRejectsWithoutActor(t *testing.T) {
	mw, _ := testMiddleware(t, "60000")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run without an actor")
	})
	rec := httptest.NewRecorder()
	// No session cookie and a nil session usecase: prepare must not touch it.
	mw.Require(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/exports/1/download", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
