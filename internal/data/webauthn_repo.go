package data

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type webAuthnRepo struct{ d *Data }

func NewWebAuthnRepo(d *Data) biz.WebAuthnRepo { return &webAuthnRepo{d: d} }

func webAuthnToBiz(p *webauthnCredentialPO) *biz.WebAuthnCredential {
	key, _ := base64.RawURLEncoding.DecodeString(p.PublicKey)
	var transports []string
	_ = jsonx.Unmarshal([]byte(p.Transports), &transports)
	return &biz.WebAuthnCredential{
		ID: p.ID, UserID: p.UserID, CredentialID: p.CredentialID, Name: p.Name,
		PublicKey: key, SignCount: p.SignCount, AAGUID: p.AAGUID, Transports: transports,
		CreatedAt: p.CreatedAt.UTC(), LastUsedAt: p.LastUsedAt, Revision: p.Revision,
	}
}

func (r *webAuthnRepo) ListByUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.WebAuthnCredential, error) {
	var rows []webauthnCredentialPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.WebAuthnCredential, 0, len(rows))
	for i := range rows {
		out = append(out, webAuthnToBiz(&rows[i]))
	}
	return out, nil
}

func (r *webAuthnRepo) Get(ctx context.Context, tx biz.Tx, userID, id int64) (*biz.WebAuthnCredential, error) {
	var p webauthnCredentialPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return webAuthnToBiz(&p), nil
}

func (r *webAuthnRepo) GetByCredentialID(ctx context.Context, tx biz.Tx, credentialID string) (*biz.WebAuthnCredential, error) {
	var p webauthnCredentialPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("credential_id = ?", credentialID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return webAuthnToBiz(&p), nil
}

func (r *webAuthnRepo) Create(ctx context.Context, tx biz.Tx, c *biz.WebAuthnCredential) (*biz.WebAuthnCredential, error) {
	transports, _ := jsonx.Marshal(c.Transports)
	p := &webauthnCredentialPO{
		UserID: c.UserID, CredentialID: c.CredentialID, Name: c.Name,
		PublicKey: base64.RawURLEncoding.EncodeToString(c.PublicKey), SignCount: c.SignCount, AAGUID: c.AAGUID,
		Transports: string(transports), CreatedAt: time.Now().UTC(), Revision: 1,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return webAuthnToBiz(p), nil
}

func (r *webAuthnRepo) UpdateSignCount(ctx context.Context, tx biz.Tx, id int64, count uint32, usedAt *time.Time, expected uint64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&webauthnCredentialPO{}).
		Where("id = ? AND revision = ?", id, expected).
		Updates(map[string]any{
			"sign_count": count, "last_used_at": usedAt,
			"revision": expected + 1,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

func (r *webAuthnRepo) Delete(ctx context.Context, tx biz.Tx, userID, id int64) error {
	res := r.d.dbOr(tx).WithContext(ctx).
		Where("id = ? AND user_id = ?", id, userID).Delete(&webauthnCredentialPO{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ErrResourceNotFound
	}
	return nil
}
