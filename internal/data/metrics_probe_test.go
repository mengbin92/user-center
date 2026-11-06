package data

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The pool gauges drive an alert that distinguishes "pool is too small" from
// "database is slow", so the probe must reflect sql.DB's own numbers rather
// than a configured constant.
func TestDBPoolStatsReportsConfiguredMax(t *testing.T) {
	d := testData(t)
	open, inUse, maxConns, waits, err := d.DBPoolStats(context.Background())
	require.NoError(t, err)
	require.Greater(t, maxConns, 0, "max_open_conns must be visible to the alert")
	require.GreaterOrEqual(t, open, 0)
	require.GreaterOrEqual(t, inUse, 0)
	require.GreaterOrEqual(t, waits, int64(0))
}

func TestOutboxBacklogFoldsUnknownStatus(t *testing.T) {
	d := testData(t)
	now := time.Now().UTC()
	rows := []deliveryPO{
		{EventID: "e1", SubscriberID: "s1", Status: "pending", NextRetryAt: now},
		{EventID: "e2", SubscriberID: "s1", Status: "delivered", NextRetryAt: now},
		{EventID: "e3", SubscriberID: "s1", Status: "not-a-status", NextRetryAt: now},
	}
	for _, row := range rows {
		require.NoError(t, d.db.Create(&row).Error)
	}

	backlog, err := d.OutboxBacklog(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), backlog["pending"])
	require.Equal(t, int64(1), backlog["delivered"])
	require.Equal(t, int64(1), backlog["other"], "an unknown status must not become its own label")
}
