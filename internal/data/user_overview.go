package data

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
)

func (r *userRepo) Overview(ctx context.Context, tx biz.Tx, filter biz.UserFilter, since, now time.Time) (*biz.Overview, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	visible := func() *gorm.DB {
		return r.scoped(db.Model(&userPO{}), filter)
	}
	type count struct {
		Status string
		N      int64
	}
	var counts []count
	if err := visible().Select("status, COUNT(*) AS n").Group("status").Scan(&counts).Error; err != nil {
		return nil, err
	}
	out := &biz.Overview{}
	for _, c := range counts {
		out.Total += c.N
		switch c.Status {
		case biz.UserStatusEnabled:
			out.Enabled = c.N
		case biz.UserStatusDisabled:
			out.Disabled = c.N
		case biz.UserStatusArchived:
			out.Archived = c.N
		}
	}
	if err := db.Model(&mfaPO{}).Where("user_id IN (?) AND secret_ciphertext <> ''", visible().Select("id")).Count(&out.MFA).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&sessionPO{}).Where("user_id IN (?) AND revoked_at IS NULL AND expires_at > ? AND idle_expires_at > ?", visible().Select("id"), now, now).Count(&out.ActiveSessions).Error; err != nil {
		return nil, err
	}
	for result, target := range map[string]*int64{"success": &out.Logins24h, "failure": &out.Failed24h} {
		results := []string{result}
		if result == "failure" {
			results = append(results, "denied")
		}
		if err := db.Model(&securityEventPO{}).Where("user_id IN (?) AND kind = ? AND result IN ? AND occurred_at >= ?", visible().Select("id"), "login", results, since).Count(target).Error; err != nil {
			return nil, err
		}
	}
	return out, nil
}
