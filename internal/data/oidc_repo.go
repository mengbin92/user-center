package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type oidcRepo struct{ d *Data }

func NewOIDCClientRepo(d *Data) biz.OIDCClientRepo   { return &oidcRepo{d: d} }
func NewOIDCCodeRepo(d *Data) biz.OIDCCodeRepo       { return &oidcRepo{d: d} }
func NewOIDCConsentRepo(d *Data) biz.OIDCConsentRepo { return &oidcRepo{d: d} }

func oidcClientToBiz(p *oidcClientPO) *biz.OIDCClient {
	var redirects, scopes, postLogout []string
	_ = jsonx.Unmarshal([]byte(p.RedirectURIs), &redirects)
	_ = jsonx.Unmarshal([]byte(p.Scopes), &scopes)
	if p.PostLogoutRedirectURIs != "" {
		_ = jsonx.Unmarshal([]byte(p.PostLogoutRedirectURIs), &postLogout)
	}
	return &biz.OIDCClient{
		ID: p.ID, ClientID: p.ClientID, Name: p.Name, ServiceOwner: p.ServiceOwner,
		Status: p.Status, SecretHash: p.SecretHash, RedirectURIs: redirects, Scopes: scopes,
		PostLogoutRedirectURIs: postLogout,
		Public:                 p.Public, RequirePKCE: p.RequirePKCE, AccessTTL: p.AccessTTL,
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
	db := r.d.dbOr(tx).WithContext(ctx)
	if tx != nil {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := db.Where("id = ?", id).First(&p).Error
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
	db := r.d.dbOr(tx).WithContext(ctx)
	if tx != nil {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := db.Where("client_id = ?", clientID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCClientNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.ClientID != clientID {
		return nil, biz.ErrOIDCClientNotFound
	}
	return oidcClientToBiz(&p), nil
}

func (r *oidcRepo) CreateOIDCClient(ctx context.Context, tx biz.Tx, c *biz.OIDCClient) (*biz.OIDCClient, error) {
	redirects, _ := jsonx.Marshal(c.RedirectURIs)
	scopes, _ := jsonx.Marshal(c.Scopes)
	postLogout, _ := jsonx.Marshal(c.PostLogoutRedirectURIs)
	now := time.Now().UTC()
	p := &oidcClientPO{
		ClientID: c.ClientID, Name: c.Name, ServiceOwner: c.ServiceOwner, Status: "active",
		SecretHash: c.SecretHash, RedirectURIs: string(redirects), Scopes: string(scopes),
		PostLogoutRedirectURIs: string(postLogout),
		Public:                 c.Public, RequirePKCE: c.RequirePKCE, AccessTTL: c.AccessTTL,
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
	postLogout, _ := jsonx.Marshal(c.PostLogoutRedirectURIs)
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ? AND revision = ?", c.ID, expected).Updates(map[string]any{
		"name": c.Name, "redirect_uris": string(redirects), "scopes": string(scopes),
		"post_logout_redirect_uris": string(postLogout),
		"public":                    c.Public, "require_pkce": c.RequirePKCE,
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

func (r *oidcRepo) RotateOIDCClientSecret(ctx context.Context, tx biz.Tx, id int64, hash string, expected uint64) (*biz.OIDCClient, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ? AND revision = ?", id, expected).Updates(map[string]any{
		"secret_hash": hash, "revision": expected + 1, "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetOIDCClient(ctx, tx, id)
}

func (r *oidcRepo) DisableOIDCClient(ctx context.Context, tx biz.Tx, id int64, expected uint64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&oidcClientPO{}).Where("id = ? AND revision = ?", id, expected).Updates(map[string]any{
		"status": "disabled", "revision": expected + 1, "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

func (r *oidcRepo) CreateOIDCCode(ctx context.Context, tx biz.Tx, c *biz.OIDCCode) error {
	now := time.Now().UTC()
	p := &oidcCodePO{
		CodeHash: c.CodeHash, ClientID: c.ClientID, UserID: c.UserID, IdentityVersion: c.IdentityVersion,
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
	// MySQL's default collation is case insensitive; redirect matching is not.
	if p.ClientID != clientID || p.RedirectURI != redirectURI {
		return nil, biz.ErrOIDCInvalidGrant
	}
	res := db.Model(&oidcCodePO{}).Where("code_hash = ? AND consumed_at IS NULL", hash).Update("consumed_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrOIDCInvalidGrant
	}
	return &biz.OIDCCode{
		CodeHash: p.CodeHash, ClientID: p.ClientID, UserID: p.UserID, IdentityVersion: p.IdentityVersion,
		RedirectURI: p.RedirectURI, Scope: p.Scope, Nonce: p.Nonce,
		CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod,
		AuthTime: p.AuthTime.UTC(), ExpiresAt: p.ExpiresAt.UTC(),
	}, nil
}

func (r *oidcRepo) CreateOIDCRefreshToken(ctx context.Context, tx biz.Tx, t *biz.OIDCRefreshToken) error {
	p := &oidcRefreshPO{
		TokenHash: t.TokenHash, FamilyID: t.FamilyID, ClientID: t.ClientID, UserID: t.UserID, IdentityVersion: t.IdentityVersion,
		Scope: t.Scope, AuthTime: t.AuthTime, ExpiresAt: t.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *oidcRepo) ConsumeOIDCRefreshToken(ctx context.Context, tx biz.Tx, hash, clientID string, now time.Time) (*biz.OIDCRefreshToken, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var p oidcRefreshPO
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ? AND client_id = ?", hash, clientID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrOIDCInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if p.ClientID != clientID {
		return nil, biz.ErrOIDCInvalidGrant
	}
	refresh := &biz.OIDCRefreshToken{
		TokenHash: p.TokenHash, FamilyID: p.FamilyID, ClientID: p.ClientID, UserID: p.UserID, IdentityVersion: p.IdentityVersion,
		Scope: p.Scope, AuthTime: p.AuthTime.UTC(), ExpiresAt: p.ExpiresAt.UTC(),
	}
	if p.RevokedAt != nil && p.FamilyID != "" {
		if err := db.Model(&oidcRefreshPO{}).Where("client_id = ? AND family_id = ? AND revoked_at IS NULL", p.ClientID, p.FamilyID).Update("revoked_at", now).Error; err != nil {
			return nil, err
		}
		// The caller commits this denial so a detected replay revokes descendants.
		return refresh, biz.ErrOIDCInvalidGrant
	}
	if p.RevokedAt != nil || !p.ExpiresAt.After(now) || p.FamilyID == "" {
		return nil, biz.ErrOIDCInvalidGrant
	}
	res := db.Model(&oidcRefreshPO{}).Where("token_hash = ? AND revoked_at IS NULL", hash).Update("revoked_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrOIDCInvalidGrant
	}
	return refresh, nil
}

// --- consent ---

func oidcConsentToBiz(p *oidcConsentPO) *biz.OIDCConsent {
	var scopes []string
	_ = jsonx.Unmarshal([]byte(p.Scopes), &scopes)
	return &biz.OIDCConsent{
		ClientID: p.ClientID, UserID: p.UserID, Scopes: scopes,
		GrantedAt: p.GrantedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(), Revision: p.Revision,
	}
}

func (r *oidcRepo) GetConsent(ctx context.Context, tx biz.Tx, clientID string, userID int64) (*biz.OIDCConsent, error) {
	var p oidcConsentPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("client_id = ? AND user_id = ?", clientID, userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return oidcConsentToBiz(&p), nil
}

func (r *oidcRepo) ListConsentsByUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.OIDCConsent, error) {
	var rows []oidcConsentPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("updated_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.OIDCConsent, 0, len(rows))
	for i := range rows {
		out = append(out, oidcConsentToBiz(&rows[i]))
	}
	return out, nil
}

func (r *oidcRepo) UpsertConsent(ctx context.Context, tx biz.Tx, c *biz.OIDCConsent) error {
	scopes, _ := jsonx.Marshal(c.Scopes)
	now := time.Now().UTC()
	granted := c.GrantedAt
	if granted.IsZero() {
		granted = now
	}
	row := &oidcConsentPO{
		ClientID: c.ClientID, UserID: c.UserID, Scopes: string(scopes),
		GrantedAt: granted, UpdatedAt: now, Revision: 1,
	}
	return r.d.dbOr(tx).WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "client_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"scopes", "updated_at", "revision"}),
	}).Create(row).Error
}

func (r *oidcRepo) DeleteConsent(ctx context.Context, tx biz.Tx, clientID string, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("client_id = ? AND user_id = ?", clientID, userID).Delete(&oidcConsentPO{}).Error
}

func (r *oidcRepo) CreateConsentRequest(ctx context.Context, tx biz.Tx, q *biz.OIDCConsentRequest) error {
	p := &oidcConsentRequestPO{
		HandleHash: q.HandleHash, ClientID: q.ClientID, UserID: q.UserID,
		RedirectURI: q.RedirectURI, Scope: q.Scope, State: q.State, Nonce: q.Nonce,
		CodeChallenge: q.CodeChallenge, CodeChallengeMethod: q.CodeChallengeMethod,
		AuthTime: q.AuthTime, IdentityVersion: q.IdentityVersion,
		ExpiresAt: q.ExpiresAt, CreatedAt: time.Now().UTC(),
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *oidcRepo) GetConsentRequest(ctx context.Context, tx biz.Tx, hash string, userID int64) (*biz.OIDCConsentRequest, error) {
	var p oidcConsentRequestPO
	err := r.d.dbOr(tx).WithContext(ctx).
		Where("handle_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > ?", hash, userID, time.Now().UTC()).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return oidcConsentRequestToBiz(&p), nil
}

func (r *oidcRepo) ConsumeConsentRequest(ctx context.Context, tx biz.Tx, hash string, userID int64, now time.Time) (*biz.OIDCConsentRequest, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var p oidcConsentRequestPO
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("handle_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > ?", hash, userID, now).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	res := db.Model(&oidcConsentRequestPO{}).
		Where("handle_hash = ? AND consumed_at IS NULL", hash).Update("consumed_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrResourceNotFound
	}
	return oidcConsentRequestToBiz(&p), nil
}

func oidcConsentRequestToBiz(p *oidcConsentRequestPO) *biz.OIDCConsentRequest {
	return &biz.OIDCConsentRequest{
		HandleHash: p.HandleHash, ClientID: p.ClientID, UserID: p.UserID,
		RedirectURI: p.RedirectURI, Scope: p.Scope, State: p.State, Nonce: p.Nonce,
		CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod,
		AuthTime: p.AuthTime.UTC(), IdentityVersion: p.IdentityVersion,
		ExpiresAt: p.ExpiresAt.UTC(),
	}
}
