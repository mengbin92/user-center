package wiring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v3"
	"github.com/google/wire"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/server"
	"github.com/mengbin92/user-center/internal/service"
)

func NewLogger() *zap.Logger {
	log, _ := zap.NewProduction()
	return log
}

func ProvideServer(b *conf.Bootstrap) *conf.Server {
	if b.Server == nil {
		return &conf.Server{Http: &conf.HTTP{Addr: ":8080"}, Grpc: &conf.GRPC{Addr: ":9090"}}
	}
	if b.Server.Http == nil {
		b.Server.Http = &conf.HTTP{Addr: ":8080"}
	}
	if b.Server.Grpc == nil {
		b.Server.Grpc = &conf.GRPC{Addr: ":9090"}
	}
	return b.Server
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

func NewRuntimeConfig(b *conf.Bootstrap) *biz.RuntimeConfig {
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
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "http://localhost:5173"
	}
	return cfg
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

// App owns the two transports and the one-time bootstrap hook.
type App struct {
	http *server.HTTPServer
	grpc *server.GRPCServer
	svc  *biz.Services
	log  *zap.Logger
}

func NewApp(httpSrv *server.HTTPServer, grpcSrv *server.GRPCServer, svc *biz.Services, log *zap.Logger) *App {
	return &App{http: httpSrv, grpc: grpcSrv, svc: svc, log: log}
}

func (a *App) Run() error {
	opts := []kratos.Option{
		kratos.Name("user-center"),
		kratos.Version("0.1.0"),
		kratos.Logger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))),
		kratos.Server(a.http.Server, a.grpc.Server),
		kratos.BeforeStart(a.bootstrap),
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
	cfg := NewRuntimeConfig(b)
	sec := ProvideSecurity(b)
	return biz.NewServices(
		data.NewUserRepo(d), data.NewCredentialRepo(d), data.NewExternalIdentityRepo(d),
		data.NewMFARepo(d), data.NewSessionRepo(d), data.NewSecurityEventRepo(d),
		data.NewFlowCompletionRepo(d), data.NewChallengeStore(d), data.NewRateLimiter(d),
		data.NewStepUpStore(d), data.NewMailSender(d, zap.NewNop(), ProvideMail(b)),
		data.NewAuditRepo(d), data.NewPolicyRepo(d), data.NewIAMRepo(d), data.NewOutboxRepo(d),
		data.NewSettingsRepo(d), data.NewExportRepo(d), d,
		data.Clock{}, data.IDs{}, data.NewSecretBox(sec), cfg,
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
)

var _ = errors.New
