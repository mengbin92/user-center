package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	kconfig "github.com/go-kratos/kratos/v3/config"
	"github.com/go-kratos/kratos/v3/config/file"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/wiring"
)

func Load(path string) (*conf.Bootstrap, error) {
	source := file.NewSource(path)
	cfg := kconfig.New(kconfig.WithSource(source), kconfig.WithResolveActualTypes(true))
	defer cfg.Close()
	if err := cfg.Load(); err != nil {
		return nil, err
	}
	var b conf.Bootstrap
	if err := cfg.Scan(&b); err != nil {
		return nil, err
	}
	if err := applyEnv(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// applyEnv keeps secrets out of config files and docker images.
func applyEnv(b *conf.Bootstrap) error {
	srv := wiring.ProvideServer(b)
	dataConf := wiring.ProvideData(b)
	sec := wiring.ProvideSecurity(b)
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		srv.Http.Addr = v
	}
	if v := os.Getenv("GRPC_ADDR"); v != "" {
		srv.Grpc.Addr = v
	}
	if v := strings.TrimSpace(os.Getenv("METRICS_ADDR")); v != "" {
		srv.Metrics.Addr = v
	}
	if v := os.Getenv("PUBLIC_BASE_URL"); v != "" {
		srv.Http.PublicBaseUrl = v
	}
	// Write-path limiting is on by default; RATE_LIMIT_ENABLED=false is the
	// escape hatch for a deployment that fronts the API with its own limiter and
	// does not want two counters.
	if v := os.Getenv("DB_DRIVER"); v != "" {
		dataConf.Database.Driver = v
	}
	if v := os.Getenv("DB_DSN"); v != "" {
		dataConf.Database.Source = v
	}
	// Tenant schema isolation is opt-in. Enabling it in config without running
	// cmd/tenant-schema first leaves tenant databases missing, so the CLI is
	// part of the rollout rather than an optional extra.
	if dataConf.Tenancy == nil {
		dataConf.Tenancy = &conf.Tenancy{}
	}
	if v := os.Getenv("TENANT_SCHEMA_PREFIX"); v != "" {
		dataConf.Tenancy.SchemaPrefix = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		dataConf.Redis.Addr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		dataConf.Redis.Password = v
	}
	if v := os.Getenv("SESSION_SECRET"); v != "" {
		sec.SessionSecret = v
	}
	if v := os.Getenv("CSRF_SECRET"); v != "" {
		sec.CsrfSecret = v
	}
	if v := os.Getenv("MFA_ENCRYPTION_KEY"); v != "" {
		sec.MfaEncryptionKey = v
	}
	if v := os.Getenv("COOKIE_DOMAIN"); v != "" {
		sec.CookieDomain = v
	}
	for _, setting := range []struct {
		name   string
		target *bool
	}{
		{"RATE_LIMIT_ENABLED", &srv.RateLimit.Enabled},
		{"TENANT_SCHEMA_ISOLATION", &dataConf.Tenancy.SchemaIsolation},
		{"COOKIE_SECURE", &sec.CookieSecure},
		{"TRUST_PROXY_HEADERS", &sec.TrustProxyHeaders},
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(setting.name))) {
		case "":
		case "1", "true", "yes", "on":
			*setting.target = true
		case "0", "false", "no", "off":
			*setting.target = false
		default:
			return fmt.Errorf("%s must be a boolean", setting.name)
		}
	}
	for _, setting := range []struct {
		name   string
		target *int32
		min    int64
	}{
		{"RATE_LIMIT_WRITE_PER_MINUTE", &srv.RateLimit.WritePerMinute, 1},
		{"RATE_LIMIT_HEAVY_PER_MINUTE", &srv.RateLimit.HeavyPerMinute, 1},
		{"REDIS_DB", &dataConf.Redis.Db, 0},
	} {
		if raw := strings.TrimSpace(os.Getenv(setting.name)); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 32)
			if err != nil || value < setting.min {
				return fmt.Errorf("%s must be an integer between %d and 2147483647", setting.name, setting.min)
			}
			*setting.target = int32(value)
		}
	}
	return nil
}
