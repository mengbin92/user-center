package main

import (
	"context"
	"flag"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
)

// admin-rescue is the offline recovery tool. It requires host/database access,
// never exposes an HTTP bypass, and every action is audited by the services.
func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "config path")
	action := flag.String("action", "bootstrap", "bootstrap | reset")
	username := flag.String("username", "root", "root username")
	password := flag.String("password", "", "new password (required)")
	email := flag.String("email", "", "root email (bootstrap only)")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	if *password == "" {
		log.Fatal("-password is required")
	}
	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	d, cleanup, err := data.NewData(wiring.ProvideData(bootstrap), wiring.ProvideSecurity(bootstrap), log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()
	services := wiring.BuildServices(d, bootstrap)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch *action {
	case "bootstrap":
		user, err := services.BootstrapRoot(ctx, *username, *email, *password)
		if err != nil {
			log.Fatal("bootstrap root", zap.Error(err))
		}
		log.Info("root bootstrapped", zap.Int64("user_id", user.ID), zap.String("username", user.Username))
	case "reset":
		if err := services.ResetRoot(ctx, *username, *password); err != nil {
			log.Fatal("reset root", zap.Error(err))
		}
		log.Info("root credential reset", zap.String("username", *username))
	default:
		log.Fatal("unknown action", zap.String("action", *action))
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
