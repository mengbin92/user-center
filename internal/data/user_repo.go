package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

type userRepo struct{ d *Data }

func NewUserRepo(d *Data) biz.UserRepo { return &userRepo{d: d} }

func newUserPO(u *biz.User) *userPO {
	p := &userPO{
		ID: u.ID, Username: u.Username, UsernameNormalized: u.UsernameNormalized,
		DisplayName: u.DisplayName, Status: u.Status, Revision: u.Revision,
		IdentityVersion: u.IdentityVersion, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		ArchivedAt: u.ArchivedAt,
	}
	if u.Email != "" {
		e, n := u.Email, u.EmailNormalized
		p.Email, p.EmailNormalized = &e, &n
	}
	if u.EmailVerified {
		t := u.UpdatedAt
		p.EmailVerifiedAt = &t
	}
	return p
}

func (p userPO) toBiz() *biz.User {
	u := &biz.User{
		ID: p.ID, Username: p.Username, UsernameNormalized: p.UsernameNormalized,
		DisplayName: p.DisplayName, Status: p.Status, Revision: p.Revision,
		IdentityVersion: p.IdentityVersion, CreatedAt: p.CreatedAt.UTC(),
		UpdatedAt: p.UpdatedAt.UTC(), ArchivedAt: p.ArchivedAt, AnonymizedAt: p.AnonymizedAt,
	}
	if p.Email != nil {
		u.Email = *p.Email
	}
	if p.EmailNormalized != nil {
		u.EmailNormalized = *p.EmailNormalized
	}
	u.EmailVerified = p.EmailVerifiedAt != nil
	return u
}

func (r *userRepo) Create(ctx context.Context, tx biz.Tx, u *biz.User) (*biz.User, error) {
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}
	if u.Revision == 0 {
		u.Revision = 1
	}
	if u.IdentityVersion == 0 {
		u.IdentityVersion = 1
	}
	p := newUserPO(u)
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return p.toBiz(), nil
}

func (r *userRepo) Get(ctx context.Context, tx biz.Tx, id int64) (*biz.User, error) {
	var p userPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return p.toBiz(), nil
}

// LockUser takes a row lock on the user row for the rest of tx.
//
// SQLite is skipped on purpose: it has no row locks, and the clause would be a
// syntax error. Its write transactions are serialised by the file lock instead,
// which is a stronger guarantee than the row lock this emulates.
func (r *userRepo) LockUser(ctx context.Context, tx biz.Tx, id int64) error {
	db := r.d.dbOr(tx).WithContext(ctx)
	if db.Dialector == nil || db.Dialector.Name() != "sqlite" {
		db = db.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate})
	}
	var p userPO
	err := db.Select("id").Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return biz.ErrUserNotFound
	}
	return err
}

func (r *userRepo) GetByUsername(ctx context.Context, tx biz.Tx, normalized string) (*biz.User, error) {
	var p userPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("username_normalized = ?", normalized).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return p.toBiz(), nil
}

func (r *userRepo) GetByEmail(ctx context.Context, tx biz.Tx, normalized string) (*biz.User, error) {
	var p userPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("email_normalized = ?", normalized).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return p.toBiz(), nil
}

func (r *userRepo) Update(ctx context.Context, tx biz.Tx, u *biz.User, expected uint64) (*biz.User, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	if expected == 0 {
		expected = u.Revision
	}
	now := time.Now().UTC()
	updates := map[string]any{
		"username":            u.Username,
		"username_normalized": u.UsernameNormalized,
		"display_name":        u.DisplayName,
		"status":              u.Status,
		"revision":            expected + 1,
		"updated_at":          now,
		"archived_at":         u.ArchivedAt,
	}
	if u.Email != "" {
		updates["email"] = u.Email
		updates["email_normalized"] = u.EmailNormalized
		if u.EmailVerified {
			updates["email_verified_at"] = now
		} else {
			updates["email_verified_at"] = nil
		}
	}
	res := db.Model(&userPO{}).Where("id = ? AND revision = ?", u.ID, expected).Updates(updates)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		current, err := r.Get(ctx, tx, u.ID)
		if err != nil {
			return nil, err
		}
		return nil, biz.ConflictRevision(current.Revision)
	}
	u.Revision = expected + 1
	u.UpdatedAt = now
	return r.Get(ctx, tx, u.ID)
}

func (r *userRepo) BumpIdentityVersion(ctx context.Context, tx biz.Tx, id int64) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	now := time.Now().UTC()
	if err := db.Model(&userPO{}).Where("id = ?", id).Updates(map[string]any{
		"identity_version": gorm.Expr("identity_version + 1"),
		"revision":         gorm.Expr("revision + 1"),
		"updated_at":       now,
	}).Error; err != nil {
		return 0, err
	}
	var p userPO
	if err := db.Select("identity_version").Where("id = ?", id).First(&p).Error; err != nil {
		return 0, err
	}
	return p.IdentityVersion, nil
}

func (r *userRepo) scoped(db *gorm.DB, f biz.UserFilter) *gorm.DB {
	if len(f.ExcludedIDs) > 0 {
		db = db.Where("id NOT IN ?", f.ExcludedIDs)
	}
	if !f.Scope.All {
		q := db
		switch {
		case len(f.Scope.UserIDs) > 0 && f.Scope.Self && f.ActorID > 0:
			q = q.Where("(id IN ? OR id = ?)", f.Scope.UserIDs, f.ActorID)
		case len(f.Scope.UserIDs) > 0:
			q = q.Where("id IN ?", f.Scope.UserIDs)
		case f.Scope.Self && f.ActorID > 0:
			q = q.Where("id = ?", f.ActorID)
		default:
			q = q.Where("1 = 0")
		}
		return q
	}
	return db
}

func (r *userRepo) List(ctx context.Context, tx biz.Tx, f biz.UserFilter) ([]*biz.User, int64, error) {
	db := r.scoped(r.d.dbOr(tx).WithContext(ctx).Model(&userPO{}), f)
	if f.Keyword != "" {
		like := "%" + escapeLike(strings.ToLower(f.Keyword)) + "%"
		if f.SearchEmail {
			db = db.Where("(LOWER(username) LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!' OR LOWER(COALESCE(email, '')) LIKE ? ESCAPE '!')", like, like, like)
		} else {
			db = db.Where("(LOWER(username) LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!')", like, like)
		}
	}
	if f.Status != "" {
		db = db.Where("status = ?", f.Status)
	}
	if f.RoleID > 0 {
		db = db.Where("id IN (?)", r.d.dbOr(tx).Model(&assignmentPO{}).Select("user_id").Where("role_id = ? AND status = ? AND starts_at <= ? AND (expires_at IS NULL OR expires_at > ?)", f.RoleID, "active", time.Now().UTC(), time.Now().UTC()))
	}
	if f.MFA != nil {
		sub := r.d.dbOr(tx).Model(&mfaPO{}).Select("user_id").Where("secret_ciphertext <> ''")
		if *f.MFA {
			db = db.Where("id IN (?)", sub)
		} else {
			db = db.Where("id NOT IN (?)", sub)
		}
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []userPO
	if err := db.Order("created_at DESC, id DESC").Offset(f.Offset).Limit(f.Limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]*biz.User, 0, len(rows))
	for _, p := range rows {
		out = append(out, p.toBiz())
	}
	return out, total, nil
}

func (r *userRepo) CountByStatus(ctx context.Context, tx biz.Tx, scope authorization.Scope) (map[string]int64, error) {
	db := r.scoped(r.d.dbOr(tx).WithContext(ctx).Model(&userPO{}), biz.UserFilter{Scope: scope})
	type row struct {
		Status string
		N      int64
	}
	var rows []row
	if err := db.Select("status, COUNT(*) AS n").Group("status").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	var total int64
	for _, x := range rows {
		out[x.Status] = x.N
		total += x.N
	}
	out["total"] = total
	return out, nil
}

func (r *userRepo) CountMFA(ctx context.Context, tx biz.Tx, scope authorization.Scope) (int64, error) {
	db := r.scoped(r.d.dbOr(tx).WithContext(ctx).Model(&userPO{}), biz.UserFilter{Scope: scope})
	var n int64
	err := db.Where("id IN (?)", r.d.dbOr(tx).Model(&mfaPO{}).Select("user_id").Where("secret_ciphertext <> ''")).Count(&n).Error
	return n, err
}

func (r *userRepo) RolesForUser(ctx context.Context, tx biz.Tx, userID int64) ([]biz.RoleRef, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	now := time.Now().UTC()
	type row struct {
		ID         int64
		Code, Name string
	}
	var rows []row
	err := db.Table("iam_user_roles AS ur").
		Select("r.id, r.code, r.name").
		Joins("JOIN iam_roles AS r ON r.id = ur.role_id").
		// Platform view only: organization-scoped assignments must never
		// surface as platform roles (tenant isolation).
		Where("ur.user_id = ? AND ur.status = ? AND r.status = ? AND ur.starts_at <= ? AND (ur.expires_at IS NULL OR ur.expires_at > ?)", userID, "active", "active", now, now).
		Where("ur.context_type = ? AND ur.context_id = 0 AND r.context_type = ? AND r.context_id = 0", authorization.ContextTypePlatform, authorization.ContextTypePlatform).
		Order("r.id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]biz.RoleRef, 0, len(rows))
	for _, x := range rows {
		out = append(out, biz.RoleRef{ID: x.ID, Code: x.Code, Name: x.Name})
	}
	return out, nil
}

// RolesForUsers resolves platform roles for a page of users in one query. The
// list screens must not issue one role lookup per row.
func (r *userRepo) RolesForUsers(ctx context.Context, tx biz.Tx, userIDs []int64) (map[int64][]biz.RoleRef, error) {
	out := make(map[int64][]biz.RoleRef, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	now := time.Now().UTC()
	type row struct {
		UserID     int64
		ID         int64
		Code, Name string
	}
	var rows []row
	err := r.d.dbOr(tx).WithContext(ctx).Table("iam_user_roles AS ur").
		Select("ur.user_id, r.id, r.code, r.name").
		Joins("JOIN iam_roles AS r ON r.id = ur.role_id").
		Where("ur.user_id IN ? AND ur.status = ? AND r.status = ? AND ur.starts_at <= ? AND (ur.expires_at IS NULL OR ur.expires_at > ?)", userIDs, "active", "active", now, now).
		Where("ur.context_type = ? AND ur.context_id = 0 AND r.context_type = ? AND r.context_id = 0", authorization.ContextTypePlatform, authorization.ContextTypePlatform).
		Order("ur.user_id, r.id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, x := range rows {
		out[x.UserID] = append(out[x.UserID], biz.RoleRef{ID: x.ID, Code: x.Code, Name: x.Name})
	}
	return out, nil
}

func (r *userRepo) CountsByRole(ctx context.Context, tx biz.Tx, roleID int64) (int64, error) {
	var n int64
	now := time.Now().UTC()
	err := r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).
		Where("role_id = ? AND status = ? AND starts_at <= ? AND (expires_at IS NULL OR expires_at > ?)", roleID, "active", now, now).
		Where("context_type = ? AND context_id = 0", authorization.ContextTypePlatform).
		Where("user_id IN (?)", r.d.dbOr(tx).Model(&userPO{}).Select("id").Where("status = ?", biz.UserStatusEnabled)).
		Distinct("user_id").Count(&n).Error
	return n, err
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "!", "!!")
	s = strings.ReplaceAll(s, "%", "!%")
	s = strings.ReplaceAll(s, "_", "!_")
	return s
}
