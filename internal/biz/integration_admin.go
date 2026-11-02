package biz

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

type ClientCredential struct {
	Client     *IntegrationClient
	Credential string
}

func (uc *IntegrationAdminUsecase) Clients(ctx context.Context, actor ActorContext) ([]*IntegrationClient, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.client.read", 0, true); err != nil {
		return nil, err
	}
	return uc.IntegrationClients.List(ctx, nil)
}

func validateClient(c *IntegrationClient) error {
	c.Code = strings.TrimSpace(c.Code)
	c.ServiceOwner = strings.TrimSpace(c.ServiceOwner)
	if c.Code == "" || c.ServiceOwner == "" {
		return Validation("code 和 service_owner 不能为空")
	}
	if len(c.AllowedMethods) == 0 {
		return Validation("至少需要允许一个 gRPC 方法")
	}
	for _, m := range c.AllowedMethods {
		if !strings.HasPrefix(m, "/api.usercenter.v1.IntegrationService/") && !isIntegrationMethod(m) {
			return Validation("不允许的方法: " + m)
		}
	}
	if c.CallbackURL != "" {
		u, err := url.Parse(c.CallbackURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return Validation("callback_url 不合法")
		}
	}
	return nil
}

func isIntegrationMethod(m string) bool {
	switch m {
	case "ValidateSession", "ValidateSubject", "GetUser", "BatchGetUsers", "GetSessionAuthorization", "GetResourceAuthorization", "RevokeSession":
		return true
	default:
		return false
	}
}

func normalizeMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if strings.HasPrefix(m, "/") {
			out = append(out, m)
		} else {
			out = append(out, "/api.usercenter.v1.IntegrationService/"+m)
		}
	}
	return out
}

func (uc *IntegrationAdminUsecase) CreateClient(ctx context.Context, actor ActorContext, c *IntegrationClient, reason string) (*ClientCredential, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	c.AllowedMethods = normalizeMethods(c.AllowedMethods)
	if err := validateClient(c); err != nil {
		return nil, err
	}
	public, err := newToken(12)
	if err != nil {
		return nil, ErrDependency
	}
	secret, err := newToken(32)
	if err != nil {
		return nil, ErrDependency
	}
	c.ClientID = "uc_" + public
	c.CredentialHash = HashToken(secret)
	c.Status = "active"
	var created *IntegrationClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.IntegrationClients.Create(ctx, tx, c)
		if err != nil {
			return err
		}
		created = row
		return uc.audit(ctx, tx, actor, "integration.client.create", row.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return &ClientCredential{Client: created, Credential: created.ClientID + "." + secret}, nil
}

func (uc *IntegrationAdminUsecase) UpdateClient(ctx context.Context, actor ActorContext, c *IntegrationClient, expected uint64, reason string) (*IntegrationClient, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	existing, err := uc.IntegrationClients.Get(ctx, nil, c.ID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	existing.AllowedMethods = c.AllowedMethods
	existing.EventSubscriptions = c.EventSubscriptions
	existing.CallbackURL = c.CallbackURL
	existing.AllowedMethods = normalizeMethods(existing.AllowedMethods)
	if err := validateClient(existing); err != nil {
		return nil, err
	}
	var updated *IntegrationClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.IntegrationClients.Update(ctx, tx, existing, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "integration.client.update", row.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IntegrationAdminUsecase) Rotate(ctx context.Context, actor ActorContext, id int64, reason string) (*ClientCredential, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	existing, err := uc.IntegrationClients.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	secret, err := newToken(32)
	if err != nil {
		return nil, ErrDependency
	}
	var updated *IntegrationClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.IntegrationClients.RotateCredential(ctx, tx, id, HashToken(secret), existing.CredentialVersion+1)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "integration.client.rotate", row.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return &ClientCredential{Client: updated, Credential: updated.ClientID + "." + secret}, nil
}

func (uc *IntegrationAdminUsecase) Disable(ctx context.Context, actor ActorContext, id int64, reason string) (*IntegrationClient, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	var out *IntegrationClient
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		existing, err := uc.IntegrationClients.Get(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if err := uc.IntegrationClients.Disable(ctx, tx, id); err != nil {
			return err
		}
		out = existing
		out.Status = "disabled"
		out.Revision++
		return uc.audit(ctx, tx, actor, "integration.client.disable", existing.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticateClient resolves a machine credential presented to the internal
// gRPC server. The plaintext secret is never stored or logged.
func (uc *IntegrationUsecase) AuthenticateClient(ctx context.Context, token string) (*IntegrationClient, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrUnauthenticated
	}
	client, err := uc.IntegrationClients.GetByClientID(ctx, nil, parts[0])
	if err != nil || client.Status != "active" {
		return nil, ErrUnauthenticated
	}
	if client.ExpiresAt != nil && !uc.Clock.Now().Before(*client.ExpiresAt) {
		return nil, ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare([]byte(client.CredentialHash), []byte(HashToken(parts[1]))) != 1 {
		return nil, ErrUnauthenticated
	}
	return client, nil
}

func (uc *IntegrationUsecase) AllowedMethod(client *IntegrationClient, fullMethod string) bool {
	for _, m := range client.AllowedMethods {
		if m == fullMethod || (!strings.HasPrefix(m, "/") && strings.HasSuffix(fullMethod, "/"+m)) {
			return true
		}
	}
	return false
}

func (uc *IntegrationAdminUsecase) Deliveries(ctx context.Context, actor ActorContext, status string, offset, limit int) ([]*Delivery, int64, error) {
	if _, err := uc.Authorize(ctx, actor, "integration.delivery.read", 0, true); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	return uc.Outbox.ListDeliveries(ctx, nil, status, offset, limit)
}

func (uc *IntegrationAdminUsecase) RetryDelivery(ctx context.Context, actor ActorContext, eventID, subscriberID, reason string) error {
	if _, err := uc.Authorize(ctx, actor, "integration.delivery.update", 0, true); err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	if eventID == "" || subscriberID == "" {
		return Validation("event_id 和 subscriber_id 不能为空")
	}
	if err := uc.Outbox.RetryDelivery(ctx, nil, eventID, subscriberID); err != nil {
		return ErrResourceNotFound
	}
	return uc.audit(ctx, nil, actor, "integration.delivery.retry", eventID+"/"+subscriberID, "{}", "{}", "{}", reason, "success")
}

// Dispatch fans events out to subscribed clients and delivers due webhooks with
// at-least-once semantics. Consumers deduplicate by event_id.
func (uc *IntegrationAdminUsecase) Dispatch(ctx context.Context) error {
	clients, err := uc.IntegrationClients.List(ctx, nil)
	if err != nil {
		return err
	}
	var subscribers []*IntegrationClient
	for _, c := range clients {
		if c.Status == "active" && c.CallbackURL != "" && len(c.EventSubscriptions) > 0 {
			subscribers = append(subscribers, c)
		}
	}
	if len(subscribers) == 0 {
		return nil
	}
	events, err := uc.Outbox.ListRecentEvents(ctx, nil, 200)
	if err != nil {
		return err
	}
	now := uc.Clock.Now().UTC()
	for _, e := range events {
		for _, c := range subscribers {
			if e.OccurredAt.Before(c.CreatedAt) {
				continue
			}
			if !eventSubscribed(c.EventSubscriptions, e.EventType) {
				continue
			}
			if err := uc.Outbox.EnsureDelivery(ctx, nil, e.EventID, c.ClientID, now); err != nil {
				return err
			}
		}
	}
	due, err := uc.Outbox.DueDeliveries(ctx, nil, now, 50)
	if err != nil {
		return err
	}
	for _, d := range due {
		if err := uc.deliver(ctx, d); err != nil {
			attempts := d.Attempts + 1
			delay := time.Duration(1<<minInt(attempts, 7)) * 30 * time.Second
			if attempts >= 8 {
				delay = 6 * time.Hour
			}
			_ = uc.Outbox.MarkRetry(ctx, d.EventID, d.SubscriberID, now.Add(delay), truncateError(err.Error()))
			continue
		}
		_ = uc.Outbox.MarkDelivered(ctx, d.EventID, d.SubscriberID, now)
	}
	return nil
}

func eventSubscribed(subs []string, eventType string) bool {
	for _, s := range subs {
		if s == eventType || s == "*" {
			return true
		}
	}
	return false
}

func (uc *IntegrationAdminUsecase) deliver(ctx context.Context, d *Delivery) error {
	payload := jsonx.RawMessage(d.Payload)
	body, err := jsonx.Marshal(map[string]any{
		"event_id": d.EventID, "event_type": d.EventType,
		"aggregate_type": d.AggregateType, "aggregate_id": d.AggregateID,
		"schema_version": d.SchemaVersion, "occurred_at": d.OccurredAt.Format(time.RFC3339),
		"payload": payload,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UserCenter-Event", d.EventType)
	secret := os.Getenv("OUTBOX_SIGNING_SECRET")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-UserCenter-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func (uc *IntegrationAdminUsecase) StartWorker(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = uc.Dispatch(ctx)
		case <-ticker.C:
			_ = uc.Dispatch(ctx)
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateError(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

var _ = errors.New
