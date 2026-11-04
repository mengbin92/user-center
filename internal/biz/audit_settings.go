package biz

import (
	"context"
	"net/mail"
	"strings"
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
	return uc.writeAuditExport(ctx, actor, filter, fields, reason, "audit.export", "audits", 0)
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
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	fields, err := mutationFields(updateMask, "registration_enabled", "email_verification_required", "password_min_length", "session_ttl_minutes", "idle_timeout_minutes", "mfa_required_for_admins", "allowed_email_domains", "providers")
	if err != nil {
		return nil, err
	}
	before, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	merged := *before
	if fields["registration_enabled"] {
		merged.RegistrationEnabled = in.RegistrationEnabled
	}
	if fields["email_verification_required"] {
		merged.EmailVerificationRequired = in.EmailVerificationRequired
	}
	if fields["password_min_length"] {
		merged.PasswordMinLength = in.PasswordMinLength
	}
	if fields["session_ttl_minutes"] {
		merged.SessionTTLMinutes = in.SessionTTLMinutes
	}
	if fields["idle_timeout_minutes"] {
		merged.IdleTimeoutMinutes = in.IdleTimeoutMinutes
	}
	if fields["mfa_required_for_admins"] {
		merged.MFARequiredForAdmins = in.MFARequiredForAdmins
	}
	if fields["allowed_email_domains"] {
		merged.AllowedEmailDomains = in.AllowedEmailDomains
	}
	if fields["providers"] {
		merged.Providers = in.Providers
	}
	in = &merged
	if in.PasswordMinLength < 8 || in.PasswordMinLength > 72 {
		return nil, Validation("密码最小长度必须为 8-72 字节")
	}
	if in.SessionTTLMinutes < 5 || in.SessionTTLMinutes > 60*24*30 {
		return nil, Validation("会话有效期不合法")
	}
	if in.IdleTimeoutMinutes < 5 || in.IdleTimeoutMinutes > in.SessionTTLMinutes {
		return nil, Validation("闲置超时不能大于会话有效期")
	}
	for _, provider := range in.Providers {
		if uc.OAuth[provider] == nil {
			return nil, Validation("登录提供方尚未配置: " + provider)
		}
	}
	for i, domain := range in.AllowedEmailDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || strings.ContainsAny(domain, "@ \t\r\n/") {
			return nil, Validation("邮箱域名不合法")
		}
		in.AllowedEmailDomains[i] = domain
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
		if _, err := uc.Policy.BumpPolicyRevision(ctx, tx); err != nil {
			return ErrDependency
		}
		return uc.audit(ctx, tx, actor, "settings.auth.update", "auth", "{}", "{}", "{}", reason, "success")
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
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	fields, err := mutationFields(updateMask, "driver", "from", "smtp_host", "smtp_port", "smtp_username", "smtp_password")
	if err != nil {
		return nil, err
	}
	before, _, err := uc.Settings.GetEmail(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	merged := *before
	if fields["driver"] {
		merged.Driver = in.Driver
	}
	if fields["from"] {
		merged.From = in.From
	}
	if fields["smtp_host"] {
		merged.SMTPHost = in.SMTPHost
	}
	if fields["smtp_port"] {
		merged.SMTPPort = in.SMTPPort
	}
	if fields["smtp_username"] {
		merged.SMTPUsername = in.SMTPUsername
	}
	if !fields["smtp_password"] {
		secret = ""
	}
	in = &merged
	if in.Driver != "console" && in.Driver != "smtp" {
		return nil, Validation("邮件驱动只能是 console 或 smtp")
	}
	if strings.ContainsAny(in.From, "\r\n") {
		return nil, Validation("发件人不合法")
	}
	if _, err := mail.ParseAddress(in.From); err != nil {
		return nil, Validation("发件人邮箱不合法")
	}
	if in.Driver == "smtp" && (in.SMTPHost == "" || in.SMTPPort <= 0 || in.SMTPPort > 65535 || strings.ContainsAny(in.SMTPHost, "\r\n")) {
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
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
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
