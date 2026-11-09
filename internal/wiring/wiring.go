package wiring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v3"
	"github.com/google/wire"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/obs"
	"github.com/mengbin92/user-center/internal/server"
	"github.com/mengbin92/user-center/internal/service"
)

func NewLogger() *zap.Logger {
	log, _ := zap.NewProduction()
	return log
}

func ProvideServer(b *conf.Bootstrap) *conf.Server {
	if b.Server == nil {
		return &conf.Server{Http: &conf.HTTP{Addr: ":8080"}, Grpc: &conf.GRPC{Addr: ":9090"}, Metrics: defaultMetrics(), RateLimit: defaultRateLimit()}
	}
	if b.Server.Http == nil {
		b.Server.Http = &conf.HTTP{Addr: ":8080"}
	}
	if b.Server.Grpc == nil {
		b.Server.Grpc = &conf.GRPC{Addr: ":9090"}
	}
	if b.Server.Metrics == nil {
		b.Server.Metrics = defaultMetrics()
	}
	if b.Server.RateLimit == nil {
		b.Server.RateLimit = defaultRateLimit()
	}
	return b.Server
}

// defaultRateLimit enables write-path limiting. The config proto cannot express
// "enabled unless explicitly false", so the default is materialised here: an
// operator upgrading into this version gets protection without editing config,
// and can still switch it off with rate_limit.enabled=false.
func defaultRateLimit() *conf.RateLimit {
	return &conf.RateLimit{Enabled: true, WritePerMinute: 120, HeavyPerMinute: 10}
}

// defaultMetrics binds the scrape listener to loopback: exposing it must be an
// explicit decision, never a side effect of upgrading.
func defaultMetrics() *conf.Metrics {
	return &conf.Metrics{Addr: "127.0.0.1:9091"}
}

func ProvideData(b *conf.Bootstrap) *conf.Data {
	if b.Data == nil {
		return &conf.Data{Database: &conf.Database{Driver: "mysql"}, Redis: &conf.Redis{}}
	}
	if b.Data.Database == nil {
		b.Data.Database = &conf.Database{Driver: "mysql"}
	}
	if b.Data.Redis == nil {
		b.Data.Redis = &conf.Redis{}
	}
	return b.Data
}

func ProvideSecurity(b *conf.Bootstrap) *conf.Security {
	if b.Security == nil {
		return &conf.Security{}
	}
	return b.Security
}

func ProvideMail(b *conf.Bootstrap) *conf.Mail {
	if b.Mail == nil {
		return &conf.Mail{Driver: "console"}
	}
	return b.Mail
}

func NewRuntimeConfig(b *conf.Bootstrap) (*biz.RuntimeConfig, error) {
	sec := ProvideSecurity(b)
	srv := ProvideServer(b)
	cfg := &biz.RuntimeConfig{
		SessionTTL:       durationMinutes(sec.SessionTtlMinutes, 12*time.Hour),
		IdleTimeout:      durationMinutes(sec.IdleTimeoutMinutes, time.Hour),
		StepUpTTL:        durationMinutes(sec.StepUpTtlMinutes, 5*time.Minute),
		ChallengeTTL:     10 * time.Minute,
		ResetTTL:         30 * time.Minute,
		ActivationTTL:    24 * time.Hour,
		ArtifactDir:      envOr("ARTIFACT_DIR", "artifacts"),
		PublicBaseURL:    srv.Http.PublicBaseUrl,
		CodeSecret:       sec.SessionSecret,
		MaxLoginAttempts: 10,
		OIDCIssuer:       envOr("OIDC_ISSUER", srv.Http.PublicBaseUrl),
		OIDCAccessTTL:    15 * time.Minute,
		OIDCRefreshTTL:   24 * time.Hour,
		OrgInvitationTTL: 72 * time.Hour,
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "http://localhost:5173"
	}
	if cfg.OIDCIssuer == "" {
		cfg.OIDCIssuer = cfg.PublicBaseURL
	}
	cfg.OIDCIssuer = strings.TrimRight(cfg.OIDCIssuer, "/")
	u, err := url.Parse(cfg.OIDCIssuer)
	dataConfig := ProvideData(b)
	development := dataConfig.Database != nil && (dataConfig.Database.Driver == "sqlite" || dataConfig.Database.Driver == "sqlite3") && !sec.CookieSecure
	loopback := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(cfg.OIDCIssuer, "?#") ||
		(u.Scheme != "https" && !(development && loopback && u.Scheme == "http")) {
		return nil, errors.New("OIDC_ISSUER must be an HTTPS URL without user info, query or fragment (HTTP loopback is allowed only in development)")
	}
	if raw := os.Getenv("ORG_INVITATION_TTL_HOURS"); raw != "" {
		hours, err := strconv.Atoi(raw)
		if err != nil || hours < 1 || hours > 720 {
			return nil, errors.New("ORG_INVITATION_TTL_HOURS must be an integer from 1 to 720")
		}
		cfg.OrgInvitationTTL = time.Duration(hours) * time.Hour
	}
	for _, field := range []struct {
		name     string
		min, max int
		target   *time.Duration
	}{
		{"OIDC_ACCESS_TTL_SECONDS", 60, 86400, &cfg.OIDCAccessTTL},
		{"OIDC_REFRESH_TTL_SECONDS", 300, 2592000, &cfg.OIDCRefreshTTL},
	} {
		if raw := os.Getenv(field.name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < field.min || n > field.max {
				return nil, fmt.Errorf("%s must be an integer from %d to %d", field.name, field.min, field.max)
			}
			*field.target = time.Duration(n) * time.Second
		}
	}
	return cfg, nil
}

func durationMinutes(v int32, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return time.Duration(v) * time.Minute
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// App owns the transports, the metrics listener and the one-time bootstrap hook.
type App struct {
	http      *server.HTTPServer
	grpc      *server.GRPCServer
	metrics   *server.MetricsServer
	svc       *biz.Services
	worker    *biz.IntegrationAdminUsecase
	directory *biz.DirectoryUsecase
	log       *zap.Logger
}

func NewApp(httpSrv *server.HTTPServer, grpcSrv *server.GRPCServer, metricsSrv *server.MetricsServer, svc *biz.Services, worker *biz.IntegrationAdminUsecase, directory *biz.DirectoryUsecase, log *zap.Logger) *App {
	return &App{http: httpSrv, grpc: grpcSrv, metrics: metricsSrv, svc: svc, worker: worker, directory: directory, log: log}
}

func (a *App) Run() error {
	opts := []kratos.Option{
		kratos.Name("user-center"),
		kratos.Version("0.6.1"),
		kratos.Logger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))),
		kratos.Server(a.http.Server, a.grpc.Server, a.metrics),
		kratos.BeforeStart(a.bootstrap),
		kratos.BeforeStart(func(ctx context.Context) error {
			go a.worker.StartWorker(ctx)
			return nil
		}),
		kratos.BeforeStart(func(ctx context.Context) error {
			go a.directory.StartWorker(ctx)
			return nil
		}),
	}
	return kratos.New(opts...).Run()
}

func (a *App) bootstrap(ctx context.Context) error {
	username := strings.TrimSpace(os.Getenv("USER_CENTER_BOOTSTRAP_USERNAME"))
	password := os.Getenv("USER_CENTER_BOOTSTRAP_PASSWORD")
	if username == "" || password == "" {
		return nil
	}
	email := os.Getenv("USER_CENTER_BOOTSTRAP_EMAIL")
	user, err := a.svc.BootstrapRoot(ctx, username, email, password)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			a.log.Info("bootstrap root already exists; skipping", zap.String("username", username))
			return nil
		}
		return fmt.Errorf("bootstrap root: %w", err)
	}
	a.log.Info("bootstrap root created", zap.Int64("user_id", user.ID), zap.String("username", user.Username))
	return nil
}

// BuildServices assembles the usecase graph for CLI tools (migrate/rescue)
// without Wire. It reuses the exact production repositories.
func BuildServices(d *data.Data, b *conf.Bootstrap) *biz.Services {
	sec := ProvideSecurity(b)
	return biz.NewServices(
		data.NewUserRepo(d), data.NewCredentialRepo(d), data.NewExternalIdentityRepo(d),
		data.NewMFARepo(d), data.NewSessionRepo(d), data.NewSecurityEventRepo(d),
		data.NewFlowCompletionRepo(d), data.NewChallengeStore(d), data.NewRateLimiter(d),
		data.NewStepUpStore(d), data.NewMailSender(d, zap.NewNop(), ProvideMail(b)),
		data.NewAuditRepo(d), data.NewPolicyRepo(d), data.NewIAMRepo(d), data.NewOutboxRepo(d),
		data.NewSettingsRepo(d), data.NewExportRepo(d), data.NewIntegrationClientRepo(d),
		data.NewOIDCClientRepo(d), data.NewOIDCCodeRepo(d), data.NewOIDCConsentRepo(d), nil, data.NewWebAuthnRepo(d),
		data.NewOrganizationRepo(d), data.NewOrgIAMRepo(d), d,
		data.Clock{}, data.IDs{}, data.NewSecretBox(sec),
		map[string]biz.OAuthProvider{}, nil,
	)
}

// ProviderSet is consumed by cmd/user-center/wire.go.
var ProviderSet = wire.NewSet(
	data.ProviderSet,
	biz.ProviderSet,
	service.ProviderSet,
	server.ProviderSet,
	ProvideServer,
	ProvideData,
	ProvideSecurity,
	ProvideMail,
	NewRuntimeConfig,
	NewLogger,
	NewApp,
	obs.NewMetrics,
	server.NewMetricsServer,
	// *data.Data owns the queries behind the gauges; internal/obs only sees
	// the probe interface.
	wire.Bind(new(obs.MetricsProbe), new(*data.Data)),
)
