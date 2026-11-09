// Command tenant-schema prepares one physical MySQL schema (database) per
// organization for opt-in tenant isolation. Static SQL migrations cannot
// express "create a schema for every organization", so this CLI is the DDL
// orchestration step and must run BEFORE enabling schema isolation in config.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "config path")
	orgID := flag.Int64("org", 0, "prepare the schema for one organization id")
	all := flag.Bool("all", false, "prepare schemas for every active organization")
	list := flag.Bool("list", false, "list schemas opened on this instance")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	dataConf := wiring.ProvideData(bootstrap)
	// Schema preparation has no Redis dependency.
	dataConf.Redis = nil
	d, cleanup, err := data.NewData(dataConf, wiring.ProvideSecurity(bootstrap), log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()

	if !d.IsolationEnabled() {
		log.Warn("schema isolation is disabled in configuration; nothing to prepare",
			zap.String("hint", "set TENANT_SCHEMA_ISOLATION=1 or data.tenancy.schema_isolation"))
		return
	}
	if *list {
		for _, name := range d.TenantSchemas() {
			fmt.Println(name)
		}
		return
	}
	ids := []int64{}
	if *orgID > 0 {
		ids = append(ids, *orgID)
	}
	if *all {
		var found []int64
		if err := d.DB().WithContext(context.Background()).Table("organizations").
			Where("status = ?", "active").Pluck("id", &found).Error; err != nil {
			log.Fatal("list organizations", zap.Error(err))
		}
		for _, id := range found {
			if id != *orgID {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		log.Fatal("set -org <id> or -all")
	}
	for _, id := range ids {
		name, err := d.EnsureTenantSchema(context.Background(), id)
		if err != nil {
			log.Fatal("prepare tenant schema", zap.Int64("organization_id", id), zap.Error(err))
		}
		log.Info("tenant schema ready", zap.Int64("organization_id", id), zap.String("schema", name))
		fmt.Printf("%d\t%s\n", id, name)
	}
}
