package data

import (
	"context"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestOutboxLeaseRecoveryAndSubscriptionRemoval(t *testing.T) {
	d := testData(t)
	ctx := context.Background()
	repo, clients := NewOutboxRepo(d), NewIntegrationClientRepo(d)
	client, err := clients.Create(ctx, nil, &biz.IntegrationClient{ClientID: "lease-client", Code: "lease-client", ServiceOwner: "billing", Status: "active", AllowedMethods: []string{"GetUser"}, EventSubscriptions: []string{"review.event"}, CallbackURL: "https://example.com/events"})
	require.NoError(t, err)
	now := time.Now().UTC()
	for _, id := range []string{"lease-event", "removed-subscription"} {
		require.NoError(t, repo.Append(ctx, nil, &biz.Event{EventID: id, EventType: "review.event", AggregateType: "user", AggregateID: 1, Payload: "{}", OccurredAt: now}))
	}
	require.NoError(t, repo.EnsureDelivery(ctx, nil, "lease-event", client.ClientID, now))
	claimed, err := repo.DueDeliveries(ctx, nil, now, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	busy, err := repo.DueDeliveries(ctx, nil, now, 10)
	require.NoError(t, err)
	require.Empty(t, busy, "a live lease must not be claimed by another worker")
	recovered, err := repo.DueDeliveries(ctx, nil, now.Add(2*time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, 2, recovered[0].Attempts)
	require.NoError(t, repo.MarkDelivered(ctx, "lease-event", client.ClientID, now))
	require.NoError(t, repo.MarkRetry(ctx, "lease-event", client.ClientID, now, "stale worker"))
	_, delivered, err := repo.ListDeliveries(ctx, nil, "delivered", 0, 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, delivered, "late failure must not overwrite successful delivery")
	require.NoError(t, repo.EnsureDelivery(ctx, nil, "removed-subscription", client.ClientID, now))
	client.EventSubscriptions = []string{}
	_, err = clients.Update(ctx, nil, client, client.Revision)
	require.NoError(t, err)
	removed, err := repo.DueDeliveries(ctx, nil, now, 10)
	require.NoError(t, err)
	require.Empty(t, removed, "queued events must respect current subscriptions")
	_, cancelled, err := repo.ListDeliveries(ctx, nil, "cancelled", 0, 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, cancelled)
}
