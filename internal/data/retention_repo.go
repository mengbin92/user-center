package data

import (
	"context"
	"strconv"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
)

type retentionRepo struct{ d *Data }

func NewRetentionRepo(d *Data) biz.RetentionRepo { return &retentionRepo{d: d} }

func (r *retentionRepo) ListRetentionCandidates(ctx context.Context, tx biz.Tx, cutoff time.Time, limit int) ([]*biz.User, error) {
	var rows []userPO
	err := r.d.dbOr(tx).WithContext(ctx).
		Where("status = ? AND archived_at IS NOT NULL AND archived_at < ? AND anonymized_at IS NULL",
			biz.UserStatusArchived, cutoff).
		Order("archived_at ASC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*biz.User, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toBiz())
	}
	return out, nil
}

func (r *retentionRepo) HasLegalHold(ctx context.Context, tx biz.Tx, userID int64) (bool, error) {
	var count int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&legalHoldPO{}).
		Where("user_id = ? AND released_at IS NULL", userID).Count(&count).Error
	return count > 0, err
}

func (r *retentionRepo) AddLegalHold(ctx context.Context, tx biz.Tx, h *biz.LegalHold) error {
	p := &legalHoldPO{UserID: h.UserID, Reason: h.Reason, CreatedAt: time.Now().UTC()}
	return r.d.dbOr(tx).WithContext(ctx).Save(p).Error
}

func (r *retentionRepo) ReleaseLegalHold(ctx context.Context, tx biz.Tx, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&legalHoldPO{}).
		Where("user_id = ? AND released_at IS NULL", userID).
		Update("released_at", time.Now().UTC()).Error
}

func (r *retentionRepo) AnonymizeUser(ctx context.Context, tx biz.Tx, userID int64, at time.Time) error {
	anonymous := "anon_" + itoa(userID)
	return r.d.dbOr(tx).WithContext(ctx).Model(&userPO{}).Where("id = ? AND anonymized_at IS NULL", userID).
		Updates(map[string]any{
			"username": anonymous, "username_normalized": anonymous,
			"display_name": "已清理", "email": nil, "email_normalized": nil,
			"email_verified_at": nil, "anonymized_at": at,
		}).Error
}

func (r *retentionRepo) PurgeExternalIdentities(ctx context.Context, tx biz.Tx, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Delete(&externalIdentityPO{}).Error
}

func (r *retentionRepo) PurgeSessions(ctx context.Context, tx biz.Tx, userID int64) error {
	db := r.d.dbOr(tx).WithContext(ctx)
	if err := db.Where("user_id = ?", userID).Delete(&sessionPO{}).Error; err != nil {
		return err
	}
	return db.Where("session_id NOT IN (SELECT id FROM iam_sessions)").Delete(&sessionRolePO{}).Error
}

func (r *retentionRepo) PurgeMFA(ctx context.Context, tx biz.Tx, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Delete(&mfaPO{}).Error
}

func (r *retentionRepo) PurgeCredentials(ctx context.Context, tx biz.Tx, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Delete(&credentialPO{}).Error
}

func (r *retentionRepo) PurgeWebAuthn(ctx context.Context, tx biz.Tx, userID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Delete(&webauthnCredentialPO{}).Error
}

func itoa(v int64) string {
	// Deliberately local: retention payloads only ever contain decimal ids.
	return strconv.FormatInt(v, 10)
}
