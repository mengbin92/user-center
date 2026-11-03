package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type oidcRepo struct{ d *Data }

func NewOIDCClientRepo(d *Data) biz.OIDCClientRepo { return &oidcRepo{d: d} }
func NewOIDCCodeRepo(d *Data) biz.OIDCCodeRepo     { return &oidcRepo{d: d} }

func oidcClientToBiz(p *oidcClientPO) *biz.OIDCClient {
	var redirects, scopes []string
	_ = jsonx.Unmarshal([]byte(p.RedirectURIs), &redirects)
	_ = jsonx.Unmarshal([]byte(p.Scopes), &scopes)
	return &biz.OIDCClient{
		ID: p.ID, ClientID: p.ClientID, Name: p.Name, ServiceOwner: p.ServiceOwner,
		Status: p.Status, SecretHash: p.SecretHash, RedirectURIs: redirects, Scopes: scopes,
		Public: p.Public, RequirePKCE: p.RequirePKCE, AccessTTL: p.AccessTTL,
		RefreshTTL: p.RefreshTTL, Revision: p.Revision, CreatedAt: p.CreatedAt.UTC(),
	}
}

func (r *oidcRepo) ListOIDCClients(ctx context.Context, tx biz.Tx) ([]*biz.OIDCClient, error) {
	var rows []oidcClientPO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.OIDCClient, 0, len(rows))
	for i := range rows {
		out = append(out, oidcClientToBiz(&rows[i]))
	}
	return out, nil
}

func (r *oidcRepo) GetOIDCClient(ctx context.Context, tx biz.Tx, id int64) (*biz.OIDCClient, error) {
	var p oidcClientPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return oidcClientToBiz(&p), nil
}

func (r *oidcRepo) GetOIDCClientByClientID(ctx context.Context, tx biz.Tx, clientID string) (*biz.OIDCClient, error) {
	var p oidcClientPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("client_id = ?", clientID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return oidcClientToBiz(&p), nil
}

func (r *oidcRepo) CreateOIDCClient(ctx context.Context, tx biz.Tx, c *biz.OIDCClient) (*biz.OIDCClient, error) {
	redirects, _ := jsonx.Marshal(c.RedirectURIs)
	scopes, _ := jsonx.Marshal(c.Scopes)
	now := time.Now().UTC()
	p := &oidcClientPO{
		ClientID: c.ClientID, Name: c.Name, ServiceOwner: c.ServiceOwner, Status: "active",
		SecretHash: c.SecretHash, RedirectURIs: string(redirects), Scopes: string(scopes),
		Public: c.Public, RequirePKCE: c.RequirePKCE, AccessTTL: c.AccessTTL,
		RefreshTTL: c.RefreshTTL, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if p.AccessTTL <= 0 {
		p.AccessTTL = 900
	}
	if p.RefreshTTL <= 0 {
		p.RefreshTTL = 86400
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return oidcClientToBiz(p), nil
}

func (r *oidcRepo) UpdateOIDCClient(ctx context.Context, tx biz.Tx, c *biz.OIDCClient, expected uint64) (*biz.OIDCClient, error) {
	redirects, _ := jsonx.Marshal(c.RedirectURIs)
	scopes, _ := jsonx.Marshal(c.Scopes)
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ? AND revision = ?", c.ID, expected).Updates(map[string]any{
		"name": c.Name, "redirect_uris": string(redirects), "scopes": string(scopes),
		"public": c.Public, "require_pkce": c.RequirePKCE,
		"access_token_ttl_seconds": c.AccessTTL, "refresh_token_ttl_seconds": c.RefreshTTL,
		"revision": expected + 1, "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetOIDCClient(ctx, tx, c.ID)
}

func (r *oidcRepo) RotateOIDCClientSecret(ctx context.Context, tx biz.Tx, id int64, hash string) (*biz.OIDCClient, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ?", id).Updates(map[string]any{
		"secret_hash": hash, "revision": gorm.Expr("revision + 1"), "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrOIDCClientNotFound
	}
	return r.GetOIDCClient(ctx, tx, id)
}

func (r *oidcRepo) DisableOIDCClient(ctx context.Context, tx biz.Tx, id int64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ?", id).Updates(map[string]any{
		"status": "disabled", "revision": gorm.Expr("revision + 1"), "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ErrOIDCClientNotFound
	}
	return nil
}

func (r *oidcRepo) CreateOIDCCode(ctx context.Context, tx biz.Tx, c *biz.OIDCCode) error {
	now := time.Now().UTC()
	p := &oidcCodePO{
		CodeHash: c.CodeHash, ClientID: c.ClientID, UserID: c.UserID,
		RedirectURI: c.RedirectURI, Scope: c.Scope, Nonce: c.Nonce,
		CodeChallenge: c.CodeChallenge, CodeChallengeMethod: c.CodeChallengeMethod,
		AuthTime: c.AuthTime, ExpiresAt: c.ExpiresAt, CreatedAt: now,
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *oidcRepo) ConsumeOIDCCode(ctx context.Context, tx biz.Tx, hash, clientID, redirectURI string, now time.Time) (*biz.OIDCCode, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var p oidcCodePO
	err := db.Where("code_hash = ? AND client_id = ? AND redirect_uri = ? AND consumed_at IS NULL AND expires_at > ?",
		hash, clientID, redirectURI, now).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	res := db.Model(&oidcCodePO{}).Where("code_hash = ? AND consumed_at IS NULL", hash).Update("consumed_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrOIDCInvalidGrant
	}
	return &biz.OIDCCode{
		CodeHash: p.CodeHash, ClientID: p.ClientID, UserID: p.UserID,
		RedirectURI: p.RedirectURI, Scope: p.Scope, Nonce: p.Nonce,
		CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod,
		AuthTime: p.AuthTime.UTC(), ExpiresAt: p.ExpiresAt.UTC(),
	}, nil
}

func (r *oidcRepo) CreateOIDCRefreshToken(ctx context.Context, tx biz.Tx, t *biz.OIDCRefreshToken) error {
	p := &oidcRefreshPO{
		TokenHash: t.TokenHash, ClientID: t.ClientID, UserID: t.UserID,
		Scope: t.Scope, AuthTime: t.AuthTime, ExpiresAt: t.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *oidcRepo) ConsumeOIDCRefreshToken(ctx context.Context, tx biz.Tx, hash, clientID string, now time.Time) (*biz.OIDCRefreshToken, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var p oidcRefreshPO
	err := db.Where("token_hash = ? AND client_id = ? AND revoked_at IS NULL AND expires_at > ?", hash, clientID, now).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	res := db.Model(&oidcRefreshPO{}).Where("token_hash = ? AND revoked_at IS NULL", hash).Update("revoked_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrOIDCInvalidGrant
	}
	return &biz.OIDCRefreshToken{
		TokenHash: p.TokenHash, ClientID: p.ClientID, UserID: p.UserID,
		Scope: p.Scope, AuthTime: p.AuthTime.UTC(), ExpiresAt: p.ExpiresAt.UTC(),
	}, nil
}
