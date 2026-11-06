package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/obs"
)

func TestNewMetricsServerDefaultsToLoopback(t *testing.T) {
	s := NewMetricsServer(&conf.Server{}, obs.NewMetrics(nil), zap.NewNop())
	require.Equal(t, "127.0.0.1:9091", s.addr)
	require.Equal(t, obs.DefaultRefreshInterval, s.interval)
}

func TestMetricsServerDisabledReturnsImmediately(t *testing.T) {
	// An empty address cannot express "disabled": proto3 cannot tell an unset
	// string from an empty one, so it falls back to the loopback default.
	for _, addr := range []string{"off", "OFF", "none", "disabled"} {
		s := NewMetricsServer(&conf.Server{Metrics: &conf.Metrics{Addr: addr}}, obs.NewMetrics(nil), zap.NewNop())
		done := make(chan error, 1)
		go func() { done <- s.Start(context.Background()) }()
		select {
		case err := <-done:
			require.NoError(t, err, "addr %q", addr)
		case <-time.After(2 * time.Second):
			t.Fatalf("addr %q did not disable the listener", addr)
		}
	}
}

func TestMetricsServerServesScrape(t *testing.T) {
	addr := freeLoopbackAddr(t)
	s := NewMetricsServer(&conf.Server{
		Metrics: &conf.Metrics{Addr: addr, RefreshSeconds: 1},
	}, obs.NewMetrics(nil), zap.NewNop())

	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background()) }()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		// Check the families that exist before any traffic: a CounterVec emits
		// nothing until its first label set is observed.
		return containsAll(string(body),
			"usercenter_schema_migrations_applied",
			"usercenter_dependency_up",
			"go_goroutines")
	}, 5*time.Second, 20*time.Millisecond)

	require.NoError(t, s.Stop(context.Background()))
	require.NoError(t, <-done)
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
