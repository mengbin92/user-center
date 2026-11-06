package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/obs"
)

// MetricsServer serves /metrics on its own listener. It is separate from the
// API listener on purpose: the scrape endpoint needs no session, no CSRF and
// no tenant context, and must not be reachable from the public host unless the
// address is widened deliberately.
type MetricsServer struct {
	addr     string
	interval time.Duration
	metrics  *obs.Metrics
	log      *zap.Logger
	srv      *http.Server
}

func NewMetricsServer(cfg *conf.Server, metrics *obs.Metrics, log *zap.Logger) *MetricsServer {
	addr := "127.0.0.1:9091"
	interval := obs.DefaultRefreshInterval
	if cfg != nil && cfg.Metrics != nil {
		if cfg.Metrics.Addr != "" {
			addr = cfg.Metrics.Addr
		}
		if cfg.Metrics.RefreshSeconds > 0 {
			interval = time.Duration(cfg.Metrics.RefreshSeconds) * time.Second
		}
	}
	return &MetricsServer{addr: addr, interval: interval, metrics: metrics, log: log}
}

// Start blocks until the listener stops, matching the kratos transport.Server
// contract.
func (s *MetricsServer) Start(ctx context.Context) error {
	if s.disabled() {
		s.log.Info("metrics listener disabled")
		return nil
	}
	go s.metrics.Run(ctx, s.interval)

	mux := http.NewServeMux()
	mux.Handle("/metrics", s.metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.log.Info("metrics listener started", zap.String("addr", s.addr))
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *MetricsServer) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *MetricsServer) disabled() bool {
	switch strings.ToLower(strings.TrimSpace(s.addr)) {
	case "", "off", "none", "disabled":
		return true
	default:
		return false
	}
}
