package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
)

func main() {
	confPath := flag.String("config", envOr("CONF_PATH", "configs/config.yaml"), "config path")
	migrationsDir := flag.String("dir", "migrations/mysql", "SQL migration directory")
	flag.Parse()
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	dataConf := wiring.ProvideData(bootstrap)
	sec := wiring.ProvideSecurity(bootstrap)
	d, cleanup, err := data.NewData(dataConf, sec, log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()

	driver := "mysql"
	if dataConf.Database != nil && dataConf.Database.Driver != "" {
		driver = dataConf.Database.Driver
	}
	if driver == "sqlite" || driver == "sqlite3" {
		if err := d.AutoMigrate(); err != nil {
			log.Fatal("auto migrate", zap.Error(err))
		}
	} else {
		if err := runSQLMigrations(d.DB(), *migrationsDir, log); err != nil {
			log.Fatal("run migrations", zap.Error(err))
		}
	}
	if err := data.SeedCatalog(d.DB()); err != nil {
		log.Fatal("seed catalog", zap.Error(err))
	}
	log.Info("migrations complete", zap.String("driver", driver))
}

func runSQLMigrations(db *gorm.DB, dir string, log *zap.Logger) error {
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(191) NOT NULL PRIMARY KEY,
		applied_at DATETIME(3) NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`).Error; err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, name := range files {
		version := strings.TrimSuffix(name, filepath.Ext(name))
		var count int64
		if err := db.Table("schema_migrations").Where("version = ?", version).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		statements := splitStatements(string(raw))
		err = db.Transaction(func(tx *gorm.DB) error {
			for _, stmt := range statements {
				if strings.TrimSpace(stmt) == "" {
					continue
				}
				if err := tx.Exec(stmt).Error; err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
			return tx.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, UTC_TIMESTAMP(3))", version).Error
		})
		if err != nil {
			return err
		}
		log.Info("migration applied", zap.String("version", version))
	}
	return nil
}

func splitStatements(raw string) []string {
	var out []string
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			out = append(out, b.String())
			b.Reset()
		}
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, b.String())
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var _ = conf.Bootstrap{}
