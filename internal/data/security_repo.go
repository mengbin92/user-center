package data

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
)

type credentialRepo struct{ d *Data }

func NewCredentialRepo(d *Data) biz.CredentialRepo { return &credentialRepo{d: d} }

func (r *credentialRepo) Get(ctx context.Context, tx biz.Tx, userID int64) (*biz.Credential, error) {
	var p credentialPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &biz.Credential{
		UserID: p.UserID, PasswordHash: p.PasswordHash, Algorithm: p.Algorithm,
		PasswordVersion: p.PasswordVersion, MustChangePassword: p.MustChangePassword,
		Revision: p.Revision, UpdatedAt: p.UpdatedAt.UTC(),
	}, nil
}

func (r *credentialRepo) Create(ctx context.Context, tx biz.Tx, c *biz.Credential) error {
	p := &credentialPO{
		UserID: c.UserID, PasswordHash: c.PasswordHash, Algorithm: c.Algorithm,
		PasswordVersion: c.PasswordVersion, MustChangePassword: c.MustChangePassword,
		Revision: c.Revision, UpdatedAt: c.UpdatedAt,
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *credentialRepo) UpdatePassword(ctx context.Context, tx biz.Tx, userID int64, hash, algorithm string, expected uint64, mustChange bool) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	now := time.Now().UTC()
	res := db.Model(&credentialPO{}).Where("user_id = ? AND revision = ?", userID, expected).Updates(map[string]any{
		"password_hash":        hash,
		"algorithm":            algorithm,
		"password_version":     gorm.Expr("password_version + 1"),
		"must_change_password": mustChange,
		"revision":             expected + 1,
		"updated_at":           now,
	})
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		var p credentialPO
		if err := db.Select("revision").Where("user_id = ?", userID).First(&p).Error; err != nil {
			return 0, err
		}
		return 0, biz.ConflictRevision(p.Revision)
	}
	return expected + 1, nil
}

func (r *credentialRepo) BumpPasswordVersion(ctx context.Context, tx biz.Tx, userID int64) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	if err := db.Model(&credentialPO{}).Where("user_id = ?", userID).Updates(map[string]any{
		"password_version": gorm.Expr("password_version + 1"),
		"revision":         gorm.Expr("revision + 1"),
		"updated_at":       time.Now().UTC(),
	}).Error; err != nil {
		return 0, err
	}
	var p credentialPO
	if err := db.Select("password_version").Where("user_id = ?", userID).First(&p).Error; err != nil {
		return 0, err
	}
	return p.PasswordVersion, nil
}

type externalIdentityRepo struct{ d *Data }

func NewExternalIdentityRepo(d *Data) biz.ExternalIdentityRepo {
	return &externalIdentityRepo{d: d}
}

func (r *externalIdentityRepo) ListByUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.ExternalIdentity, error) {
	var rows []externalIdentityPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.ExternalIdentity, 0, len(rows))
	for _, p := range rows {
		out = append(out, externalIdentityToBiz(p))
	}
	return out, nil
}

func externalIdentityToBiz(p externalIdentityPO) *biz.ExternalIdentity {
	return &biz.ExternalIdentity{
		ID: p.ID, UserID: p.UserID, Provider: p.Provider,
		ProviderSubject: p.ProviderSubject, Issuer: p.Issuer,
		Display: p.Display, CreatedAt: p.CreatedAt.UTC(),
	}
}

func (r *externalIdentityRepo) GetByID(ctx context.Context, tx biz.Tx, id int64) (*biz.ExternalIdentity, error) {
	var p externalIdentityPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return externalIdentityToBiz(p), nil
}

func (r *externalIdentityRepo) FindBySubject(ctx context.Context, tx biz.Tx, provider, issuer, subject string) (*biz.ExternalIdentity, error) {
	var p externalIdentityPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("provider = ? AND issuer = ? AND provider_subject = ?", provider, issuer, subject).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return externalIdentityToBiz(p), nil
}

func (r *externalIdentityRepo) Create(ctx context.Context, tx biz.Tx, identity *biz.ExternalIdentity) (*biz.ExternalIdentity, error) {
	now := time.Now().UTC()
	p := &externalIdentityPO{
		UserID: identity.UserID, Provider: identity.Provider,
		ProviderSubject: identity.ProviderSubject, Issuer: identity.Issuer,
		Display: identity.Display, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return externalIdentityToBiz(*p), nil
}

func (r *externalIdentityRepo) Delete(ctx context.Context, tx biz.Tx, id, userID int64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&externalIdentityPO{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ErrResourceNotFound
	}
	return nil
}

func (r *externalIdentityRepo) CountByUser(ctx context.Context, tx biz.Tx, userID int64) (int64, error) {
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&externalIdentityPO{}).Where("user_id = ?", userID).Count(&n).Error
	return n, err
}

type mfaRepo struct{ d *Data }

func NewMFARepo(d *Data) biz.MFARepo { return &mfaRepo{d: d} }

func (r *mfaRepo) Get(ctx context.Context, tx biz.Tx, userID int64) (*biz.MFAState, error) {
	var p mfaPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return mfaStateFromPO(&p), nil
}

// ListByUsers resolves MFA state for a page of users in one query.
func (r *mfaRepo) ListByUsers(ctx context.Context, tx biz.Tx, userIDs []int64) (map[int64]*biz.MFAState, error) {
	out := make(map[int64]*biz.MFAState, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	var rows []mfaPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id IN ?", userIDs).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		out[rows[i].UserID] = mfaStateFromPO(&rows[i])
	}
	return out, nil
}

func mfaStateFromPO(p *mfaPO) *biz.MFAState {
	hashes := []string{}
	if p.RecoveryHashes != "" {
		for _, h := range strings.Split(p.RecoveryHashes, ",") {
			if h != "" {
				hashes = append(hashes, h)
			}
		}
	}
	state := &biz.MFAState{
		UserID: p.UserID, Secret: p.Secret, KeyVersion: p.KeyVersion,
		PendingSecret: p.PendingSecret, PendingSession: p.PendingSession,
		RecoveryHashes: hashes, LastStep: p.LastStep, Failures: p.Failures,
		Revision: p.Revision,
	}
	if p.PendingUntil != nil {
		state.PendingUntil = p.PendingUntil.UTC()
	}
	if p.LockedUntil != nil {
		state.LockedUntil = p.LockedUntil.UTC()
	}
	return state
}

func (r *mfaRepo) Save(ctx context.Context, tx biz.Tx, s *biz.MFAState) error {
	var pending, locked *time.Time
	if !s.PendingUntil.IsZero() {
		t := s.PendingUntil.UTC()
		pending = &t
	}
	if !s.LockedUntil.IsZero() {
		t := s.LockedUntil.UTC()
		locked = &t
	}
	p := &mfaPO{
		UserID: s.UserID, Secret: s.Secret, KeyVersion: s.KeyVersion,
		PendingSecret: s.PendingSecret, PendingSession: s.PendingSession,
		PendingUntil: pending, RecoveryHashes: strings.Join(s.RecoveryHashes, ","),
		LastStep: s.LastStep, Failures: s.Failures, LockedUntil: locked,
		Revision: s.Revision,
	}
	if p.KeyVersion == 0 {
		p.KeyVersion = 1
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	db := r.d.dbOr(tx).WithContext(ctx)
	if p.Revision == 1 {
		err := db.Create(p).Error
		if isDuplicateKeyError(err) {
			return biz.ErrRevisionConflict
		}
		if err != nil {
			return biz.ErrDependency
		}
		return nil
	}
	// Every mutation carries the next revision. Consuming a TOTP step or a
	// recovery code must lose if another request already changed this state.
	res := db.Model(&mfaPO{}).Where("user_id = ? AND revision = ?", p.UserID, p.Revision-1).Updates(map[string]any{
		"secret_ciphertext": p.Secret, "key_version": p.KeyVersion,
		"pending_secret": p.PendingSecret, "pending_session": p.PendingSession,
		"pending_until": p.PendingUntil, "recovery_hashes": p.RecoveryHashes,
		"last_step": p.LastStep, "failures": p.Failures,
		"locked_until": p.LockedUntil, "revision": p.Revision,
	})
	if res.Error != nil {
		return biz.ErrDependency
	}
	if res.RowsAffected != 1 {
		return biz.ErrRevisionConflict
	}
	return nil
}

func (r *mfaRepo) Delete(ctx context.Context, tx biz.Tx, userID int64) error {
	// Preserve the monotonic revision after reset. Physically deleting the
	// row would restart at revision 1 and allow a delayed pre-reset write to
	// match a newly enrolled factor's revision (an ABA race).
	return r.d.dbOr(tx).WithContext(ctx).Model(&mfaPO{}).Where("user_id = ?", userID).Updates(map[string]any{
		"secret_ciphertext": "", "pending_secret": "", "pending_session": "",
		"pending_until": nil, "recovery_hashes": "", "last_step": 0,
		"failures": 0, "locked_until": nil, "revision": gorm.Expr("revision + 1"),
	}).Error
}

type sessionRepo struct{ d *Data }

func NewSessionRepo(d *Data) biz.SessionRepo { return &sessionRepo{d: d} }

func (r *sessionRepo) Create(ctx context.Context, tx biz.Tx, s *biz.Session) error {
	if tx == nil {
		return r.d.InTx(ctx, func(ctx context.Context, tx biz.Tx) error { return r.Create(ctx, tx, s) })
	}
	db := r.d.dbOr(tx).WithContext(ctx)
	p := &sessionPO{
		ID: s.ID, UserID: s.UserID, ApplicationCode: s.ApplicationCode,
		TokenHash: s.TokenHash, UserAgent: s.UserAgent, IPMasked: s.IPMasked,
		IssuedAt: s.IssuedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
		IdleExpiresAt: s.IdleExpiresAt, IdentityVersion: s.IdentityVersion,
		Revision: s.Revision,
	}
	if p.ApplicationCode == "" {
		p.ApplicationCode = biz.ApplicationCode
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	if err := db.Create(p).Error; err != nil {
		return err
	}
	for _, roleID := range s.ActiveRoleIDs {
		if err := db.Create(&sessionRolePO{SessionID: s.ID, RoleID: roleID, CreatedAt: s.IssuedAt}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *sessionRepo) GetByTokenHash(ctx context.Context, tx biz.Tx, hash string) (*biz.Session, error) {
	var p sessionPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("credential_hash = ?", hash).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return sessionToBiz(p), nil
}

func (r *sessionRepo) Get(ctx context.Context, tx biz.Tx, id string) (*biz.Session, error) {
	var p sessionPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return sessionToBiz(p), nil
}

func sessionToBiz(p sessionPO) *biz.Session {
	return &biz.Session{
		ID: p.ID, UserID: p.UserID, ApplicationCode: p.ApplicationCode,
		TokenHash: p.TokenHash, UserAgent: p.UserAgent, IPMasked: p.IPMasked,
		IssuedAt: p.IssuedAt.UTC(), LastSeenAt: p.LastSeenAt.UTC(),
		ExpiresAt: p.ExpiresAt.UTC(), IdleExpiresAt: p.IdleExpiresAt.UTC(),
		RevokedAt: p.RevokedAt, IdentityVersion: p.IdentityVersion, Revision: p.Revision,
	}
}

func (r *sessionRepo) ListByUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.Session, error) {
	var rows []sessionPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("issued_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Session, 0, len(rows))
	for _, p := range rows {
		out = append(out, sessionToBiz(p))
	}
	return out, nil
}

func (r *sessionRepo) Touch(ctx context.Context, tx biz.Tx, id string, lastSeen, idleExpires time.Time) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&sessionPO{}).Where("id = ?", id).Updates(map[string]any{
		"last_seen_at": lastSeen, "idle_expires_at": idleExpires,
	}).Error
}

func (r *sessionRepo) Revoke(ctx context.Context, tx biz.Tx, id string, at *time.Time) error {
	if at == nil {
		t := time.Now().UTC()
		at = &t
	}
	return r.d.dbOr(tx).WithContext(ctx).Model(&sessionPO{}).Where("id = ? AND revoked_at IS NULL", id).Update("revoked_at", at).Error
}

func (r *sessionRepo) RevokeAllForUser(ctx context.Context, tx biz.Tx, userID int64, at *time.Time) error {
	if at == nil {
		t := time.Now().UTC()
		at = &t
	}
	return r.d.dbOr(tx).WithContext(ctx).Model(&sessionPO{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", at).Error
}

func (r *sessionRepo) CountActive(ctx context.Context, tx biz.Tx) (int64, error) {
	now := time.Now().UTC()
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&sessionPO{}).
		Where("revoked_at IS NULL AND expires_at > ? AND idle_expires_at > ?", now, now).Count(&n).Error
	return n, err
}

func (r *sessionRepo) ListActiveRoleIDs(ctx context.Context, tx biz.Tx, sessionID string) ([]int64, error) {
	var rows []sessionRolePO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("session_id = ?", sessionID).Order("role_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(rows))
	for _, p := range rows {
		out = append(out, p.RoleID)
	}
	return out, nil
}

func (r *sessionRepo) SetActiveRoleIDs(ctx context.Context, tx biz.Tx, sessionID string, ids []int64, expected uint64) error {
	if tx == nil {
		return r.d.InTx(ctx, func(ctx context.Context, tx biz.Tx) error {
			return r.SetActiveRoleIDs(ctx, tx, sessionID, ids, expected)
		})
	}
	db := r.d.dbOr(tx).WithContext(ctx)
	res := db.Model(&sessionPO{}).Where("id = ? AND revision = ? AND revoked_at IS NULL", sessionID, expected).
		Update("revision", expected+1)
	if res.Error != nil {
		return biz.ErrDependency
	}
	if res.RowsAffected != 1 {
		return biz.ErrRevisionConflict
	}
	if err := db.Where("session_id = ?", sessionID).Delete(&sessionRolePO{}).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, id := range ids {
		if err := db.Create(&sessionRolePO{SessionID: sessionID, RoleID: id, CreatedAt: now}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *sessionRepo) SetIdentityVersion(ctx context.Context, tx biz.Tx, id string, version uint64) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&sessionPO{}).Where("id = ?", id).Update("identity_version", version).Error
}

type securityEventRepo struct{ d *Data }

func NewSecurityEventRepo(d *Data) biz.SecurityEventRepo { return &securityEventRepo{d: d} }

func (r *securityEventRepo) Append(ctx context.Context, tx biz.Tx, e *biz.SecurityEvent) error {
	p := &securityEventPO{
		ID: e.ID, UserID: e.UserID, SessionID: e.SessionID, Kind: e.Kind,
		Result: e.Result, IPMasked: e.IPMasked, UserAgentSummary: e.UserAgentSummary,
		RequestID: e.RequestID, OccurredAt: e.OccurredAt,
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *securityEventRepo) ListByUser(ctx context.Context, tx biz.Tx, userID int64, limit int, offsetRaw string) ([]*biz.SecurityEvent, string, error) {
	offset, _ := strconv.Atoi(offsetRaw)
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var rows []securityEventPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("occurred_at DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, "", err
	}
	out := make([]*biz.SecurityEvent, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.SecurityEvent{
			ID: p.ID, UserID: p.UserID, SessionID: p.SessionID, Kind: p.Kind,
			Result: p.Result, IPMasked: p.IPMasked, UserAgentSummary: p.UserAgentSummary,
			RequestID: p.RequestID, OccurredAt: p.OccurredAt.UTC(),
		})
	}
	next := ""
	if len(rows) == limit {
		next = strconv.Itoa(offset + limit)
	}
	return out, next, nil
}

func (r *securityEventRepo) CountRecent(ctx context.Context, tx biz.Tx, kind string, since time.Time) (int64, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&securityEventPO{}).Where("occurred_at >= ?", since)
	switch kind {
	case "login_success":
		db = db.Where("kind = ? AND result = ?", "login", "success")
	case "login_failure":
		db = db.Where("kind = ? AND result = ?", "login", "failure")
	default:
		db = db.Where("kind = ?", kind)
	}
	var n int64
	err := db.Count(&n).Error
	return n, err
}

type flowRepo struct{ d *Data }

func NewFlowCompletionRepo(d *Data) biz.FlowCompletionRepo { return &flowRepo{d: d} }

func (r *flowRepo) Complete(ctx context.Context, tx biz.Tx, challengeID, purpose string, userID int64, resultRef string) error {
	p := &flowCompletionPO{
		ChallengeID: challengeID, Purpose: purpose, UserID: userID,
		ResultRef: resultRef, CompletedAt: time.Now().UTC(),
	}
	err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error
	if isDuplicateKeyError(err) {
		return biz.ErrChallengeInvalid
	}
	if err != nil {
		return biz.ErrDependency
	}
	return nil
}

func isDuplicateKeyError(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return true
	}
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && (sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey || sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique)
}
