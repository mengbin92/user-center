// Command retention runs the personal-data cleanup job. It is dry-run by
// default and requires two explicit confirmations before writing anything,
// because anonymization is irreversible.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/config"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/wiring"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

const acknowledgePhrase = "I_HAVE_BACKED_UP"

func envInt(key string, def int) int {
	if raw := os.Getenv(key); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func main() {
	confPath := flag.String("config", "configs/config.yaml", "bootstrap config path")
	apply := flag.Bool("apply", false, "actually anonymize (default is dry-run)")
	ack := flag.String("acknowledge", "", "type "+acknowledgePhrase+" to confirm a backup exists")
	days := flag.Int("retention-days", envInt("RETENTION_DAYS", biz.DefaultRetentionDays), "retention period after archival")
	limit := flag.Int("limit", 100, "max accounts per run")
	holdUser := flag.String("hold-user", "", "add a legal hold for this user id")
	holdReason := flag.String("hold-reason", "", "reason for the legal hold")
	releaseUser := flag.String("release-user", "", "release the legal hold for this user id")
	releaseReason := flag.String("release-reason", "", "reason for releasing the hold")
	flag.Parse()

	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	if *apply && *ack != acknowledgePhrase {
		log.Fatal("refusing to write: pass -acknowledge=" + acknowledgePhrase + " after taking a database backup")
	}
	bootstrap, err := config.Load(*confPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	dataConf := wiring.ProvideData(bootstrap)
	dataConf.Redis = nil
	sec := wiring.ProvideSecurity(bootstrap)
	d, cleanup, err := data.NewData(dataConf, sec, log)
	if err != nil {
		log.Fatal("open database", zap.Error(err))
	}
	defer cleanup()
	ctx := biz.WithRequestID(context.Background(), uuid.NewString())
	uc := biz.NewRetentionUsecase(wiring.BuildServices(d, bootstrap), data.NewRetentionRepo(d))

	if *holdUser != "" {
		id, err := biz.ParseID(*holdUser, "hold-user")
		if err != nil {
			log.Fatal("invalid hold user", zap.Error(err))
		}
		if err := uc.Hold(ctx, id, strings.TrimSpace(*holdReason)); err != nil {
			log.Fatal("add legal hold", zap.Error(err))
		}
		fmt.Printf("legal hold added for user %d\n", id)
		return
	}
	if *releaseUser != "" {
		id, err := biz.ParseID(*releaseUser, "release-user")
		if err != nil {
			log.Fatal("invalid release user", zap.Error(err))
		}
		if err := uc.Release(ctx, id, strings.TrimSpace(*releaseReason)); err != nil {
			log.Fatal("release legal hold", zap.Error(err))
		}
		fmt.Printf("legal hold released for user %d\n", id)
		return
	}

	report, err := uc.Run(ctx, biz.RetentionOptions{
		DryRun: !*apply, RetentionDays: *days, Limit: *limit,
	})
	if err != nil {
		log.Fatal("retention run", zap.Error(err))
	}
	raw, _ := jsonx.Marshal(report)
	fmt.Println(string(raw))
	log.Info("retention completed",
		zap.Bool("dry_run", report.DryRun),
		zap.Int("scanned", report.Scanned),
		zap.Int("cleaned", report.Cleaned),
		zap.Int("skipped_legal_hold", report.SkippedHold),
		zap.Int("failed", report.Failed))
}
