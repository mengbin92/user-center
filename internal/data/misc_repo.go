package data

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type auditRepo struct{ d *Data }

func NewAuditRepo(d *Data) biz.AuditRepo { return &auditRepo{d: d} }

func (r *auditRepo) Append(ctx context.Context, tx biz.Tx, e *biz.AuditEvent) error {
	p := &auditEventPO{
		EventID: e.EventID, ActorUserID: e.ActorUserID, ActorServiceID: e.ActorServiceID,
		ActorSessionID: e.ActorSessionID, Action: e.Action, Target: e.Target,
		BeforeData: e.Before, AfterData: e.After, Diff: e.Diff, Result: e.Result,
		Reason: e.Reason, RequestID: e.RequestID, Versions: e.Versions,
		OccurredAt: e.OccurredAt,
	}
	if p.OccurredAt.IsZero() {
		p.OccurredAt = time.Now().UTC()
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *auditRepo) List(ctx context.Context, tx biz.Tx, f biz.AuditFilter) ([]*biz.AuditEvent, int64, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&auditEventPO{})
	if f.Action != "" {
		db = db.Where("action = ?", f.Action)
	}
	if f.ActorUserID > 0 {
		db = db.Where("actor_user_id = ?", f.ActorUserID)
	}
	if f.Target != "" {
		db = db.Where("target = ?", f.Target)
	}
	if f.From != nil {
		db = db.Where("occurred_at >= ?", *f.From)
	}
	if f.To != nil {
		db = db.Where("occurred_at < ?", *f.To)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []auditEventPO
	if err := db.Order("occurred_at DESC, event_id DESC").Offset(f.Offset).Limit(f.Limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]*biz.AuditEvent, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.AuditEvent{
			EventID: p.EventID, ActorUserID: p.ActorUserID, ActorServiceID: p.ActorServiceID,
			ActorSessionID: p.ActorSessionID, Action: p.Action, Target: p.Target,
			Before: p.BeforeData, After: p.AfterData, Diff: p.Diff, Result: p.Result,
			Reason: p.Reason, RequestID: p.RequestID, Versions: p.Versions,
			OccurredAt: p.OccurredAt.UTC(),
		})
	}
	return out, total, nil
}

func (r *auditRepo) Get(ctx context.Context, tx biz.Tx, id string) (*biz.AuditEvent, error) {
	var p auditEventPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("event_id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &biz.AuditEvent{
		EventID: p.EventID, ActorUserID: p.ActorUserID, ActorServiceID: p.ActorServiceID,
		ActorSessionID: p.ActorSessionID, Action: p.Action, Target: p.Target,
		Before: p.BeforeData, After: p.AfterData, Diff: p.Diff, Result: p.Result,
		Reason: p.Reason, RequestID: p.RequestID, Versions: p.Versions,
		OccurredAt: p.OccurredAt.UTC(),
	}, nil
}

type outboxRepo struct{ d *Data }

func NewOutboxRepo(d *Data) biz.OutboxRepo { return &outboxRepo{d: d} }

func (r *outboxRepo) Append(ctx context.Context, tx biz.Tx, e *biz.Event) error {
	p := &outboxEventPO{
		EventID: e.EventID, AggregateType: e.AggregateType, AggregateID: e.AggregateID,
		AggregateRevision: e.AggregateRevision, EventType: e.EventType,
		SchemaVersion: e.SchemaVersion, Payload: e.Payload, CreatedAt: e.OccurredAt,
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	return r.d.dbOr(tx).WithContext(ctx).Create(p).Error
}

func (r *outboxRepo) ListRecentEvents(ctx context.Context, tx biz.Tx, limit int) ([]*biz.Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var rows []outboxEventPO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Event, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.Event{
			EventID: p.EventID, AggregateType: p.AggregateType, AggregateID: p.AggregateID,
			AggregateRevision: p.AggregateRevision, EventType: p.EventType,
			SchemaVersion: p.SchemaVersion, Payload: p.Payload, OccurredAt: p.CreatedAt.UTC(),
		})
	}
	return out, nil
}

func (r *outboxRepo) EnsureDelivery(ctx context.Context, tx biz.Tx, eventID, subscriberID string, next time.Time) error {
	return r.d.dbOr(tx).WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&deliveryPO{
		EventID: eventID, SubscriberID: subscriberID, Status: "pending", NextRetryAt: next,
	}).Error
}

func (r *outboxRepo) DueDeliveries(ctx context.Context, tx biz.Tx, now time.Time, limit int) ([]*biz.Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	type row struct {
		EventID       string
		SubscriberID  string
		Status        string
		Attempts      int
		NextRetryAt   time.Time
		LastError     string
		EventType     string
		AggregateType string
		AggregateID   int64
		SchemaVersion int
		Payload       string
		OccurredAt    time.Time
		CallbackURL   string
	}
	var rows []row
	err := r.d.dbOr(tx).WithContext(ctx).Table("event_deliveries AS d").
		Select("d.event_id, d.subscriber_id, d.status, d.attempts, d.next_retry_at, d.last_error, e.event_type, e.aggregate_type, e.aggregate_id, e.schema_version, e.payload, e.created_at AS occurred_at, c.callback_url").
		Joins("JOIN event_outbox AS e ON e.event_id = d.event_id").
		Joins("JOIN integration_clients AS c ON c.client_id = d.subscriber_id AND c.status = 'active'").
		Where("d.status IN ? AND d.next_retry_at <= ?", []string{"pending", "retrying"}, now).
		Order("d.next_retry_at").Limit(limit).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*biz.Delivery, 0, len(rows))
	for _, x := range rows {
		out = append(out, &biz.Delivery{
			EventID: x.EventID, EventType: x.EventType, SubscriberID: x.SubscriberID,
			Status: x.Status, Attempts: x.Attempts, NextRetryAt: x.NextRetryAt.UTC(),
			LastError: x.LastError, Payload: x.Payload, AggregateType: x.AggregateType,
			AggregateID: x.AggregateID, SchemaVersion: x.SchemaVersion,
			OccurredAt: x.OccurredAt.UTC(), CallbackURL: x.CallbackURL,
		})
	}
	return out, nil
}

func (r *outboxRepo) ListDeliveries(ctx context.Context, tx biz.Tx, status string, offset, limit int) ([]*biz.Delivery, int64, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&deliveryPO{})
	if status != "" {
		db = db.Where("status = ?", status)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []deliveryPO
	if err := db.Order("next_retry_at DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	eventIDs := make([]string, 0, len(rows))
	for _, p := range rows {
		eventIDs = append(eventIDs, p.EventID)
	}
	types := map[string]string{}
	if len(eventIDs) > 0 {
		var events []outboxEventPO
		if err := r.d.dbOr(tx).WithContext(ctx).Select("event_id, event_type").Where("event_id IN ?", eventIDs).Find(&events).Error; err != nil {
			return nil, 0, err
		}
		for _, e := range events {
			types[e.EventID] = e.EventType
		}
	}
	out := make([]*biz.Delivery, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.Delivery{
			EventID: p.EventID, EventType: types[p.EventID], SubscriberID: p.SubscriberID,
			Status: p.Status, Attempts: p.Attempts, NextRetryAt: p.NextRetryAt.UTC(), LastError: p.LastError,
		})
	}
	return out, total, nil
}

func (r *outboxRepo) MarkDelivered(ctx context.Context, eventID, subscriberID string, at time.Time) error {
	return r.d.dbOr(nil).WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "event_id"}, {Name: "subscriber_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "next_retry_at"}),
	}).Create(&deliveryPO{EventID: eventID, SubscriberID: subscriberID, Status: "delivered", NextRetryAt: at}).Error
}

func (r *outboxRepo) MarkRetry(ctx context.Context, eventID, subscriberID string, at time.Time, lastError string) error {
	return r.d.dbOr(nil).WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "event_id"}, {Name: "subscriber_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"status": "retrying", "next_retry_at": at, "last_error": lastError,
			"attempts": gorm.Expr("attempts + 1"),
		}),
	}).Create(&deliveryPO{EventID: eventID, SubscriberID: subscriberID, Status: "retrying", NextRetryAt: at, LastError: lastError, Attempts: 1}).Error
}

func (r *outboxRepo) RetryDelivery(ctx context.Context, tx biz.Tx, eventID, subscriberID string) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&deliveryPO{}).
		Where("event_id = ? AND subscriber_id = ?", eventID, subscriberID).
		Updates(map[string]any{"status": "pending", "next_retry_at": time.Now().UTC(), "last_error": ""})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ErrResourceNotFound
	}
	return nil
}

type settingsRepo struct{ d *Data }

func NewSettingsRepo(d *Data) biz.SettingsRepo { return &settingsRepo{d: d} }

func defaultAuthSettings() *biz.AuthSettings {
	return &biz.AuthSettings{
		RegistrationEnabled: true, EmailVerificationRequired: true,
		PasswordMinLength: 10, SessionTTLMinutes: 720, IdleTimeoutMinutes: 60,
		MFARequiredForAdmins: true, Providers: []string{}, Revision: 1,
	}
}

func (r *settingsRepo) GetAuth(ctx context.Context, tx biz.Tx) (*biz.AuthSettings, error) {
	var p authSettingsPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("name = ?", "auth").First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultAuthSettings(), nil
	}
	if err != nil {
		return nil, err
	}
	out := defaultAuthSettings()
	if err := jsonx.Unmarshal([]byte(p.Value), out); err != nil {
		return nil, err
	}
	out.Revision = p.Revision
	out.UpdatedAt = p.UpdatedAt.UTC()
	return out, nil
}

func (r *settingsRepo) SaveAuth(ctx context.Context, tx biz.Tx, s *biz.AuthSettings, expected uint64) (*biz.AuthSettings, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	payload, err := jsonx.Marshal(s)
	if err != nil {
		return nil, err
	}
	var p authSettingsPO
	err = db.Where("name = ?", "auth").First(&p).Error
	now := time.Now().UTC()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if expected == 0 {
			expected = 1
		}
		p = authSettingsPO{Key: "auth", Value: string(payload), Revision: expected + 1, UpdatedAt: now}
		if err := db.Create(&p).Error; err != nil {
			return nil, err
		}
		s.Revision = expected + 1
		s.UpdatedAt = now
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if expected == 0 {
		expected = p.Revision
	}
	if p.Revision != expected {
		return nil, biz.ConflictRevision(p.Revision)
	}
	res := db.Model(&authSettingsPO{}).Where("name = ? AND revision = ?", "auth", expected).Updates(map[string]any{
		"value": string(payload), "revision": expected + 1, "updated_at": now,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	s.Revision = expected + 1
	s.UpdatedAt = now
	return s, nil
}

func (r *settingsRepo) GetEmail(ctx context.Context, tx biz.Tx) (*biz.EmailSettings, string, error) {
	var p emailSettingsPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("name = ?", "email").First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &biz.EmailSettings{Driver: "console", From: "no-reply@localhost", SMTPPort: 587, Revision: 1}, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	out := &biz.EmailSettings{Revision: p.Revision, PasswordSet: p.Secret != ""}
	if err := jsonx.Unmarshal([]byte(p.Value), out); err != nil {
		return nil, "", err
	}
	out.PasswordSet = p.Secret != ""
	out.Revision = p.Revision
	return out, p.Secret, nil
}

func (r *settingsRepo) SaveEmail(ctx context.Context, tx biz.Tx, s *biz.EmailSettings, secret string, expected uint64) (*biz.EmailSettings, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	payload, err := jsonx.Marshal(s)
	if err != nil {
		return nil, err
	}
	var p emailSettingsPO
	err = db.Where("name = ?", "email").First(&p).Error
	now := time.Now().UTC()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if expected == 0 {
			expected = 1
		}
		p = emailSettingsPO{Key: "email", Value: string(payload), Secret: secret, Revision: expected + 1, UpdatedAt: now}
		if err := db.Create(&p).Error; err != nil {
			return nil, err
		}
		s.Revision = expected + 1
		s.PasswordSet = secret != ""
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if expected == 0 {
		expected = p.Revision
	}
	if p.Revision != expected {
		return nil, biz.ConflictRevision(p.Revision)
	}
	updates := map[string]any{"value": string(payload), "revision": expected + 1, "updated_at": now}
	if secret != "" {
		updates["secret"] = secret
		p.Secret = secret
	}
	res := db.Model(&emailSettingsPO{}).Where("name = ? AND revision = ?", "email", expected).Updates(updates)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	s.Revision = expected + 1
	s.PasswordSet = p.Secret != ""
	return s, nil
}

type exportRepo struct{ d *Data }

func NewExportRepo(d *Data) biz.ExportRepo { return &exportRepo{d: d} }

func exportToBiz(p exportJobPO) *biz.ExportJob {
	var fields []string
	_ = jsonx.Unmarshal([]byte(p.RequestedFields), &fields)
	return &biz.ExportJob{
		ID: p.ID, Kind: p.Kind, ActorUserID: p.ActorUserID, ActorSessionID: p.ActorSessionID,
		ScopeSnapshot: p.ScopeSnapshot, RequestedFields: fields, Status: p.Status,
		ArtifactName: p.ArtifactName, Error: p.Error, CreatedAt: p.CreatedAt.UTC(),
		ExpiresAt: p.ExpiresAt.UTC(),
	}
}

func (r *exportRepo) Create(ctx context.Context, job *biz.ExportJob) (*biz.ExportJob, error) {
	fields, _ := jsonx.Marshal(job.RequestedFields)
	p := &exportJobPO{
		Kind: job.Kind, ActorUserID: job.ActorUserID, ActorSessionID: job.ActorSessionID,
		ScopeSnapshot: job.ScopeSnapshot, RequestedFields: string(fields), Status: job.Status,
		ArtifactName: job.ArtifactName, Error: job.Error, CreatedAt: job.CreatedAt, ExpiresAt: job.ExpiresAt,
	}
	if err := r.d.db.WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return exportToBiz(*p), nil
}

func (r *exportRepo) Get(ctx context.Context, id int64) (*biz.ExportJob, error) {
	var p exportJobPO
	err := r.d.db.WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return exportToBiz(p), nil
}

func (r *exportRepo) ListByActor(ctx context.Context, actorID int64, limit int, offsetRaw string) ([]*biz.ExportJob, string, error) {
	offset, _ := strconv.Atoi(offsetRaw)
	var rows []exportJobPO
	if err := r.d.db.WithContext(ctx).Where("actor_user_id = ?", actorID).Order("id DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, "", err
	}
	out := make([]*biz.ExportJob, 0, len(rows))
	for _, p := range rows {
		out = append(out, exportToBiz(p))
	}
	next := ""
	if len(rows) == limit {
		next = strconv.Itoa(offset + limit)
	}
	return out, next, nil
}
