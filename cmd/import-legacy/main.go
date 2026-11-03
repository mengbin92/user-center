package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"io"
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
	snapshot, err := os.Open(*file)
	if err != nil {
		log.Fatal("open snapshot", zap.Error(err))
	}
	defer snapshot.Close()
	raw, err := io.ReadAll(io.LimitReader(snapshot, (4<<20)+1))
	if err != nil {
		log.Fatal("read snapshot", zap.Error(err))
	}
	spec, err := decodeSnapshot(raw)
	if err != nil {
		// JSON decoder errors may quote password hashes from the input.
		log.Fatal("parse snapshot: invalid, oversized, duplicate or unknown JSON fields")
	}
	conf, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	dataConf := wiring.ProvideData(conf)
	// Offline import only needs the database and must work before Redis starts.
	dataConf.Redis = nil
	d, cleanup, err := data.NewData(dataConf, wiring.ProvideSecurity(conf), log)
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

// decodeSnapshot refuses silently dropped MFA/external-identity fields and
// ambiguous duplicate keys; its errors never reproduce credential material.
func decodeSnapshot(raw []byte) (data.LegacyImportSpec, error) {
	var spec data.LegacyImportSpec
	if err := jsonx.ValidateUnique(raw); err != nil {
		return spec, fmt.Errorf("invalid snapshot JSON")
	}
	decoder := jsonx.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return spec, fmt.Errorf("invalid snapshot fields")
	}
	return spec, nil
}
