package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestOutboxRejectsWeakSigningKeysBeforeSending(t *testing.T) {
	h := newHarness(t)
	var bodies [][]byte
	var signatures []string
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		signatures = append(signatures, r.Header.Get("X-UserCenter-Signature"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	client, err := h.svc.IntegrationClients.Create(context.Background(), nil, &biz.IntegrationClient{
		ClientID: "signing-review", Code: "signing-review", ServiceOwner: "billing", Status: "active",
		AllowedMethods: []string{"GetUser"}, EventSubscriptions: []string{"review.signing"}, CallbackURL: webhook.URL,
	})
	require.NoError(t, err)
	require.NoError(t, h.svc.Outbox.Append(context.Background(), nil, &biz.Event{
		EventID: "signing-review-event", EventType: "review.signing", AggregateType: "user", AggregateID: 1,
		Payload: "{}", OccurredAt: client.CreatedAt.Add(time.Millisecond),
	}))
	worker := biz.NewIntegrationAdminUsecase(h.svc)
	for _, key := range []string{"", "weak-key", strings.Repeat(" ", 32)} {
		t.Setenv("OUTBOX_SIGNING_SECRET", key)
		require.Error(t, worker.Dispatch(context.Background()), "weak keys must stop delivery")
		require.Empty(t, bodies)
	}
	key := strings.Repeat("valid-test-key", 3)
	t.Setenv("OUTBOX_SIGNING_SECRET", key)
	require.NoError(t, worker.Dispatch(context.Background()))
	require.Len(t, bodies, 1)
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(bodies[0])
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), signatures[0])
}
