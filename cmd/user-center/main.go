package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/config"
)

func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "path to config yaml")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	if err := validateSecrets(bootstrap); err != nil {
		log.Fatal("insecure configuration", zap.Error(err))
	}
	app, cleanup, err := wireApp(bootstrap)
	if err != nil {
		log.Fatal("wire app", zap.Error(err))
	}
	if cleanup != nil {
		defer cleanup()
	}
	if err := app.Run(); err != nil {
		log.Fatal("run app", zap.Error(err))
	}
}

func validateSecrets(b *conf.Bootstrap) error {
	if os.Getenv("ALLOW_INSECURE_DEV") == "1" {
		return nil
	}
	if b.Security == nil {
		return errors.New("security configuration is required")
	}
	weak := func(name, v string) error {
		if v == "" || strings.HasPrefix(v, "sample-") || strings.HasPrefix(v, "change-me") {
			return fmt.Errorf("%s must be set to a random secret (or ALLOW_INSECURE_DEV=1 for local use)", name)
		}
		return nil
	}
	if err := weak("SESSION_SECRET", b.Security.SessionSecret); err != nil {
		return err
	}
	if err := weak("CSRF_SECRET", b.Security.CsrfSecret); err != nil {
		return err
	}
	return weak("MFA_ENCRYPTION_KEY", b.Security.MfaEncryptionKey)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
