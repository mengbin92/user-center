package biz

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

func (uc *AuditUsecase) List(ctx context.Context, actor ActorContext, filter AuditFilter) ([]*AuditEvent, int64, error) {
	if _, err := uc.Authorize(ctx, actor, "audit.read", 0, true); err != nil {
		return nil, 0, err
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}
	return uc.Audit.List(ctx, nil, filter)
}

func (uc *AuditUsecase) Get(ctx context.Context, actor ActorContext, id string) (*AuditEvent, error) {
	if _, err := uc.Authorize(ctx, actor, "audit.read", 0, true); err != nil {
		return nil, err
	}
	e, err := uc.Audit.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	return e, nil
}

func (uc *AuditUsecase) Export(ctx context.Context, actor ActorContext, filter AuditFilter, fields []string, reason string) (*ExportJob, error) {
	if _, err := uc.Authorize(ctx, actor, "audit.export", 0, true); err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		fields = []string{"event_id", "occurred_at", "actor_user_id", "action", "target", "result", "reason", "request_id"}
	}
	allowed := map[string]bool{"event_id": true, "occurred_at": true, "actor_user_id": true, "actor_session_id": true, "action": true, "target": true, "result": true, "reason": true, "request_id": true, "before": true, "after": true, "diff": true}
	for _, f := range fields {
		if !allowed[f] {
			return nil, Validation("不支持的导出字段: " + f)
		}
	}
	filter.Limit = 100000
	events, _, err := uc.Audit.List(ctx, nil, filter)
	if err != nil {
		return nil, ErrDependency
	}
	if err := os.MkdirAll(uc.ArtifactDir, 0o750); err != nil {
		return nil, ErrDependency
	}
	job := &ExportJob{
		Kind: "audits", ActorUserID: actor.User.ID, ActorSessionID: actor.Session.ID,
		RequestedFields: fields, Status: ExportPending, CreatedAt: uc.Clock.Now().UTC(),
		ExpiresAt: uc.Clock.Now().Add(24 * time.Hour), ArtifactName: uc.IDs.NewID() + ".csv",
	}
	path := filepath.Join(uc.ArtifactDir, job.ArtifactName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, ErrDependency
	}
	w := csv.NewWriter(f)
	_ = w.Write(fields)
	for _, e := range events {
		row := make([]string, 0, len(fields))
		for _, field := range fields {
			switch field {
			case "event_id":
				row = append(row, e.EventID)
			case "occurred_at":
				row = append(row, e.OccurredAt.Format(time.RFC3339))
			case "actor_user_id":
				row = append(row, itoa(e.ActorUserID))
			case "actor_session_id":
				row = append(row, e.ActorSessionID)
			case "action":
				row = append(row, e.Action)
			case "target":
				row = append(row, e.Target)
			case "result":
				row = append(row, e.Result)
			case "reason":
				row = append(row, e.Reason)
			case "request_id":
				row = append(row, e.RequestID)
			case "before":
				row = append(row, e.Before)
			case "after":
				row = append(row, e.After)
			case "diff":
				row = append(row, e.Diff)
			}
		}
		_ = w.Write(row)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return nil, ErrDependency
	}
	if err := f.Close(); err != nil {
		return nil, ErrDependency
	}
	job.Status = ExportReady
	saved, err := uc.Exports.Create(ctx, job)
	if err != nil {
		return nil, ErrDependency
	}
	_ = uc.audit(ctx, nil, actor, "audit.export", "audits", "{}", "{}", string(mustJSON(map[string]any{"fields": fields})), reason, "success")
	return saved, nil
}

func (uc *SettingsUsecase) GetAuth(ctx context.Context, actor ActorContext) (*AuthSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.auth.read", 0, true); err != nil {
		return nil, err
	}
	s, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	return s, nil
}

func (uc *SettingsUsecase) UpdateAuth(ctx context.Context, actor ActorContext, in *AuthSettings, updateMask string, expected uint64, reason string) (*AuthSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.auth.update", 0, true); err != nil {
		return nil, err
	}
	if in.PasswordMinLength < 8 || in.PasswordMinLength > 128 {
		return nil, Validation("密码最小长度必须为 8-128")
	}
	if in.SessionTTLMinutes < 5 || in.SessionTTLMinutes > 60*24*30 {
		return nil, Validation("会话有效期不合法")
	}
	if in.IdleTimeoutMinutes < 5 || in.IdleTimeoutMinutes > in.SessionTTLMinutes {
		return nil, Validation("闲置超时不能大于会话有效期")
	}
	before, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	in.Revision = before.Revision
	in.UpdatedAt = uc.Clock.Now().UTC()
	var saved *AuthSettings
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		s, err := uc.Settings.SaveAuth(ctx, tx, in, expected)
		if err != nil {
			return err
		}
		saved = s
		if err := uc.audit(ctx, tx, actor, "settings.auth.update", "auth", "{}", "{}", "{}", reason, "success"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}

func (uc *SettingsUsecase) GetEmail(ctx context.Context, actor ActorContext) (*EmailSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.email.read", 0, true); err != nil {
		return nil, err
	}
	s, _, err := uc.Settings.GetEmail(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	return s, nil
}

func (uc *SettingsUsecase) UpdateEmail(ctx context.Context, actor ActorContext, in *EmailSettings, secret, updateMask string, expected uint64, reason string) (*EmailSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.email.update", 0, true); err != nil {
		return nil, err
	}
	if in.Driver != "console" && in.Driver != "smtp" {
		return nil, Validation("邮件驱动只能是 console 或 smtp")
	}
	if in.Driver == "smtp" && (in.SMTPHost == "" || in.SMTPPort <= 0) {
		return nil, Validation("SMTP 主机和端口不能为空")
	}
	if secret != "" {
		enc, err := uc.Secrets.Encrypt(secret)
		if err != nil {
			return nil, ErrDependency
		}
		secret = enc
	}
	var saved *EmailSettings
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		s, err := uc.Settings.SaveEmail(ctx, tx, in, secret, expected)
		if err != nil {
			return err
		}
		saved = s
		return uc.audit(ctx, tx, actor, "settings.email.update", "email", "{}", "{}", string(mustJSON(map[string]any{"driver": in.Driver})), reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}

var _ = fmt.Sprintf
var _ = jsonx.Marshal
