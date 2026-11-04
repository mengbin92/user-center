package service

import (
	"context"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type AuditService struct {
	usercv1.UnimplementedAuditServiceServer
	uc *biz.AuditUsecase
}

func NewAuditService(uc *biz.AuditUsecase) *AuditService { return &AuditService{uc: uc} }

func (s *AuditService) ListAuditEvents(ctx context.Context, req *usercv1.ListAuditEventsRequest) (*usercv1.AuditsReply, error) {
	offset, err := biz.DecodePageToken(req.GetPageToken(), bizFingerprint(req.GetAction(), req.GetActorUserId(), req.GetTarget(), req.GetFrom(), req.GetTo()))
	if err != nil {
		return nil, err
	}
	from, err := biz.ParseTime(req.GetFrom(), "from")
	if err != nil {
		return nil, err
	}
	to, err := biz.ParseTime(req.GetTo(), "to")
	if err != nil {
		return nil, err
	}
	var actorID int64
	if req.GetActorUserId() != "" {
		actorID, err = parseIDField(req.GetActorUserId(), "actor_user_id")
		if err != nil {
			return nil, err
		}
	}
	filter := biz.AuditFilter{
		Action: req.GetAction(), ActorUserID: actorID, Target: req.GetTarget(),
		Offset: offset, Limit: pageSize(req.GetPageSize()),
	}
	if !from.IsZero() {
		filter.From = &from
	}
	if !to.IsZero() {
		filter.To = &to
	}
	items, total, err := s.uc.List(ctx, requestMeta(ctx), filter)
	if err != nil {
		return nil, err
	}
	out := &usercv1.AuditsReply{Meta: &usercv1.ListMeta{TotalSize: rev(uint64(total))}}
	for _, e := range items {
		out.Items = append(out.Items, auditProto(e))
	}
	if offset+len(items) < int(total) {
		out.Meta.NextPageToken = biz.EncodePageToken(offset+len(items), bizFingerprint(req.GetAction(), req.GetActorUserId(), req.GetTarget(), req.GetFrom(), req.GetTo()))
	}
	return out, nil
}

func auditProto(e *biz.AuditEvent) *usercv1.AuditEvent {
	return &usercv1.AuditEvent{
		Id: e.EventID, ActorUserId: id(e.ActorUserID), ActorServiceId: e.ActorServiceID,
		ActorSessionId: e.ActorSessionID, Action: e.Action, Target: e.Target,
		Before: e.Before, After: e.After, Diff: e.Diff, Result: e.Result,
		Reason: e.Reason, RequestId: e.RequestID, AuthorizationVersions: e.Versions,
		OccurredAt: ts(e.OccurredAt),
	}
}

func (s *AuditService) GetAuditEvent(ctx context.Context, req *usercv1.GetAuditEventRequest) (*usercv1.AuditEvent, error) {
	if req.GetId() == "" {
		return nil, biz.Validation("id 不能为空")
	}
	e, err := s.uc.Get(ctx, requestMeta(ctx), req.GetId())
	if err != nil {
		return nil, err
	}
	return auditProto(e), nil
}

func (s *AuditService) ExportAuditEvents(ctx context.Context, req *usercv1.ExportAuditEventsRequest) (*usercv1.ExportJob, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, metaErr := managementMeta(ctx, req)
	if metaErr != nil {
		return nil, metaErr
	}
	var actorID int64
	var err error
	if req.GetActorUserId() != "" {
		actorID, err = parseIDField(req.GetActorUserId(), "actor_user_id")
		if err != nil {
			return nil, err
		}
	}
	from, err := biz.ParseTime(req.GetFrom(), "from")
	if err != nil {
		return nil, err
	}
	to, err := biz.ParseTime(req.GetTo(), "to")
	if err != nil {
		return nil, err
	}
	filter := biz.AuditFilter{Action: req.GetAction(), ActorUserID: actorID, Target: req.GetTarget()}
	if !from.IsZero() {
		filter.From = &from
	}
	if !to.IsZero() {
		filter.To = &to
	}
	job, err := s.uc.Export(ctx, actor, filter, req.GetFields(), auditReason)
	if err != nil {
		return nil, err
	}
	return exportProto(job), nil
}

type SettingsService struct {
	usercv1.UnimplementedSettingsServiceServer
	uc *biz.SettingsUsecase
}

func NewSettingsService(uc *biz.SettingsUsecase) *SettingsService { return &SettingsService{uc: uc} }

func authSettingsProto(s *biz.AuthSettings) *usercv1.AuthSettings {
	return &usercv1.AuthSettings{
		RegistrationEnabled: s.RegistrationEnabled, EmailVerificationRequired: s.EmailVerificationRequired,
		PasswordMinLength: int32(s.PasswordMinLength), SessionTtlMinutes: int32(s.SessionTTLMinutes),
		IdleTimeoutMinutes: int32(s.IdleTimeoutMinutes), MfaRequiredForAdmins: s.MFARequiredForAdmins,
		AllowedEmailDomains: s.AllowedEmailDomains, Providers: s.Providers, Revision: rev(s.Revision),
	}
}

func (s *SettingsService) GetAuthSettings(ctx context.Context, _ *usercv1.GetAuthSettingsRequest) (*usercv1.AuthSettings, error) {
	settings, err := s.uc.GetAuth(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	return authSettingsProto(settings), nil
}

func (s *SettingsService) UpdateAuthSettings(ctx context.Context, req *usercv1.UpdateAuthSettingsRequest) (*usercv1.AuthSettings, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, metaErr := managementMeta(ctx, req)
	if metaErr != nil {
		return nil, metaErr
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	settings, err := s.uc.UpdateAuth(ctx, actor, &biz.AuthSettings{
		RegistrationEnabled: req.GetRegistrationEnabled(), EmailVerificationRequired: req.GetEmailVerificationRequired(),
		PasswordMinLength: int(req.GetPasswordMinLength()), SessionTTLMinutes: int(req.GetSessionTtlMinutes()),
		IdleTimeoutMinutes: int(req.GetIdleTimeoutMinutes()), MFARequiredForAdmins: req.GetMfaRequiredForAdmins(),
		AllowedEmailDomains: req.GetAllowedEmailDomains(), Providers: req.GetProviders(),
	}, req.GetUpdateMask(), expected, auditReason)
	if err != nil {
		return nil, err
	}
	return authSettingsProto(settings), nil
}

func emailSettingsProto(s *biz.EmailSettings) *usercv1.EmailSettings {
	return &usercv1.EmailSettings{
		Driver: s.Driver, From: s.From, SmtpHost: s.SMTPHost, SmtpPort: int32(s.SMTPPort),
		SmtpUsername: s.SMTPUsername, PasswordConfigured: s.PasswordSet, Revision: rev(s.Revision),
	}
}

func (s *SettingsService) GetEmailSettings(ctx context.Context, _ *usercv1.GetEmailSettingsRequest) (*usercv1.EmailSettings, error) {
	settings, err := s.uc.GetEmail(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	return emailSettingsProto(settings), nil
}

func (s *SettingsService) UpdateEmailSettings(ctx context.Context, req *usercv1.UpdateEmailSettingsRequest) (*usercv1.EmailSettings, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, metaErr := managementMeta(ctx, req)
	if metaErr != nil {
		return nil, metaErr
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	settings, err := s.uc.UpdateEmail(ctx, actor, &biz.EmailSettings{
		Driver: req.GetDriver(), From: req.GetFrom(), SMTPHost: req.GetSmtpHost(),
		SMTPPort: int(req.GetSmtpPort()), SMTPUsername: req.GetSmtpUsername(),
	}, req.GetSmtpPassword(), req.GetUpdateMask(), expected, auditReason)
	if err != nil {
		return nil, err
	}
	return emailSettingsProto(settings), nil
}
