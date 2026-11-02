package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type integrationClientRepo struct{ d *Data }

func NewIntegrationClientRepo(d *Data) biz.IntegrationClientRepo {
	return &integrationClientRepo{d: d}
}

func integrationClientToBiz(p *integrationClientPO) *biz.IntegrationClient {
	var methods, events []string
	_ = jsonx.Unmarshal([]byte(p.AllowedMethods), &methods)
	_ = jsonx.Unmarshal([]byte(p.EventSubscriptions), &events)
	return &biz.IntegrationClient{
		ID: p.ID, ClientID: p.ClientID, Code: p.Code, ServiceOwner: p.ServiceOwner,
		Status: p.Status, CredentialHash: p.CredentialHash, CredentialVersion: p.CredentialVersion,
		AllowedMethods: methods, EventSubscriptions: events, CallbackURL: p.CallbackURL,
		ExpiresAt: p.ExpiresAt, Revision: p.Revision, CreatedAt: p.CreatedAt.UTC(),
	}
}

func (r *integrationClientRepo) List(ctx context.Context, tx biz.Tx) ([]*biz.IntegrationClient, error) {
	var rows []integrationClientPO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.IntegrationClient, 0, len(rows))
	for i := range rows {
		out = append(out, integrationClientToBiz(&rows[i]))
	}
	return out, nil
}

func (r *integrationClientRepo) Get(ctx context.Context, tx biz.Tx, id int64) (*biz.IntegrationClient, error) {
	var p integrationClientPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return integrationClientToBiz(&p), nil
}

func (r *integrationClientRepo) GetByClientID(ctx context.Context, tx biz.Tx, clientID string) (*biz.IntegrationClient, error) {
	var p integrationClientPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("client_id = ?", clientID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return integrationClientToBiz(&p), nil
}

func (r *integrationClientRepo) Create(ctx context.Context, tx biz.Tx, c *biz.IntegrationClient) (*biz.IntegrationClient, error) {
	now := time.Now().UTC()
	methods, _ := jsonx.Marshal(c.AllowedMethods)
	events, _ := jsonx.Marshal(c.EventSubscriptions)
	p := &integrationClientPO{
		ClientID: c.ClientID, Code: c.Code, ServiceOwner: c.ServiceOwner, Status: c.Status,
		CredentialHash: c.CredentialHash, CredentialVersion: 1,
		AllowedMethods: string(methods), EventSubscriptions: string(events),
		CallbackURL: c.CallbackURL, ExpiresAt: c.ExpiresAt, Revision: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if p.Status == "" {
		p.Status = "active"
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return integrationClientToBiz(p), nil
}

func (r *integrationClientRepo) Update(ctx context.Context, tx biz.Tx, c *biz.IntegrationClient, expected uint64) (*biz.IntegrationClient, error) {
	methods, _ := jsonx.Marshal(c.AllowedMethods)
	events, _ := jsonx.Marshal(c.EventSubscriptions)
	res := r.d.dbOr(tx).WithContext(ctx).Model(&integrationClientPO{}).Where("id = ? AND revision = ?", c.ID, expected).Updates(map[string]any{
		"allowed_methods": string(methods), "event_subscriptions": string(events),
		"callback_url": c.CallbackURL, "revision": expected + 1, "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.Get(ctx, tx, c.ID)
}

func (r *integrationClientRepo) RotateCredential(ctx context.Context, tx biz.Tx, id int64, hash string, version int) (*biz.IntegrationClient, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&integrationClientPO{}).Where("id = ?", id).Updates(map[string]any{
		"credential_hash": hash, "credential_version": version, "updated_at": time.Now().UTC(),
		"revision": gorm.Expr("revision + 1"),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrResourceNotFound
	}
	return r.Get(ctx, tx, id)
}

func (r *integrationClientRepo) Disable(ctx context.Context, tx biz.Tx, id int64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&integrationClientPO{}).Where("id = ?", id).Updates(map[string]any{
		"status": "disabled", "updated_at": time.Now().UTC(), "revision": gorm.Expr("revision + 1"),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ErrResourceNotFound
	}
	return nil
}
