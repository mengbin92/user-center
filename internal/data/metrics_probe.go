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

// PingDatabase answers "can this instance actually serve requests", not "is
// there a TCP connection to MySQL".
//
// database/sql's PingContext sends COM_PING, which the server answers even when
// the schema this process depends on is gone -- the S13 restore drill dropped
// the database and /readyz still returned 200. A readiness check that passes
// against an empty server is worse than no check, because it keeps the instance
// in rotation. So this runs a real query against a table the migrator creates;
// a missing schema now fails the probe.
//
// schema_migrations is the sentinel because it is created by the migrate step
// itself: if it is absent, this release never ran here.
func (d *Data) PingDatabase(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var n int64
	return d.db.WithContext(ctx).Table("schema_migrations").Count(&n).Error
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

// DBPoolStats reads sql.DB's own counters. They are in-memory and free, so the
// refresh timer can call this as often as it likes.
func (d *Data) DBPoolStats(context.Context) (int, int, int, int64, error) {
	sqlDB, err := d.db.DB()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	stats := sqlDB.Stats()
	return stats.OpenConnections, stats.InUse, stats.MaxOpenConnections, int64(stats.WaitCount), nil
}
