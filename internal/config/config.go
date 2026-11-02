package config

import (
	"os"
	"strconv"

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
	applyEnv(&b)
	return &b, nil
}

// applyEnv keeps secrets out of config files and docker images.
func applyEnv(b *conf.Bootstrap) {
	srv := wiring.ProvideServer(b)
	dataConf := wiring.ProvideData(b)
	sec := wiring.ProvideSecurity(b)
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		srv.Http.Addr = v
	}
	if v := os.Getenv("GRPC_ADDR"); v != "" {
		srv.Grpc.Addr = v
	}
	if v := os.Getenv("PUBLIC_BASE_URL"); v != "" {
		srv.Http.PublicBaseUrl = v
	}
	if v := os.Getenv("DB_DRIVER"); v != "" {
		dataConf.Database.Driver = v
	}
	if v := os.Getenv("DB_DSN"); v != "" {
		dataConf.Database.Source = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		dataConf.Redis.Addr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		dataConf.Redis.Password = v
	}
	if v := os.Getenv("REDIS_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			dataConf.Redis.Db = int32(n)
		}
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
	if v := os.Getenv("COOKIE_SECURE"); v != "" {
		sec.CookieSecure = v == "1" || v == "true"
	}
	if v := os.Getenv("COOKIE_DOMAIN"); v != "" {
		sec.CookieDomain = v
	}
	if v := os.Getenv("TRUST_PROXY_HEADERS"); v != "" {
		sec.TrustProxyHeaders = v == "1" || v == "true"
	}
}
