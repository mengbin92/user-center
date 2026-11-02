package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
)

func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "config path")
	file := flag.String("file", "", "legacy snapshot JSON")
	batchID := flag.String("batch", "", "batch id (default generated)")
	apply := flag.Bool("apply", false, "write changes; without it only validate")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	if *file == "" {
		log.Fatal("-file is required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal("read snapshot", zap.Error(err))
	}
	var spec data.LegacyImportSpec
	if err := jsonx.Unmarshal(raw, &spec); err != nil {
		log.Fatal("parse snapshot", zap.Error(err))
	}
	conf, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	d, cleanup, err := data.NewData(wiring.ProvideData(conf), wiring.ProvideSecurity(conf), log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := data.ImportLegacy(ctx, d, spec, *batchID, *apply)
	if err != nil {
		log.Fatal("import", zap.Error(err))
	}
	out, _ := jsonx.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	if len(result.Conflicts) > 0 {
		os.Exit(2)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
