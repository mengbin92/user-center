package data

import (
	"context"
	"time"
)

// MetricsProbe implementations. They live here so internal/obs never learns a
// table name; the interface is satisfied implicitly.

const probeTimeout = 2 * time.Second

// knownDeliveryStatuses mirrors the values the outbox repository writes.
var knownDeliveryStatuses = map[string]struct{}{
	"pending": {}, "retrying": {}, "delivering": {}, "delivered": {}, "cancelled": {},
}

// OutboxBacklog counts delivery rows per status. Unrecognised values fold into
// "other" so a future writer cannot grow the metric's label set.
func (d *Data) OutboxBacklog(ctx context.Context) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var rows []struct {
		Status string
		Total  int64
	}
	if err := d.db.WithContext(ctx).Model(&deliveryPO{}).
		Select("status, COUNT(*) AS total").Group("status").Scan(&rows).Error; err != nil {
		return nil, err
	}
	backlog := make(map[string]int64, len(rows))
	for _, row := range rows {
		if _, ok := knownDeliveryStatuses[row.Status]; ok {
			backlog[row.Status] = row.Total
			continue
		}
		backlog["other"] += row.Total
	}
	return backlog, nil
}

// SchemaMigrationsApplied counts recorded migration steps. Steps are recorded
// per statement, so the number is larger than the file count; it is meant to
// detect "this instance is behind", not to identify a version.
func (d *Data) SchemaMigrationsApplied(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var applied int64
	err := d.db.WithContext(ctx).Table("schema_migrations").Count(&applied).Error
	return applied, err
}

func (d *Data) PingDatabase(ctx context.Context) error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return sqlDB.PingContext(ctx)
}

// PingCache reports nil when Redis is not configured: the gauge means "this
// instance is broken", and an unconfigured cache is a deliberate mode (the
// in-memory fallback), not an outage.
func (d *Data) PingCache(ctx context.Context) error {
	if d.redis == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return d.redis.Ping(ctx).Err()
}
