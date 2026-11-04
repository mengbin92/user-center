package service

import (
	"context"
	"time"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

// --- R9: identity provider configuration view ---

func (s *SettingsService) GetAuthProviders(ctx context.Context, _ *usercv1.GetAuthProvidersRequest) (*usercv1.AuthProvidersReply, error) {
	reply, err := s.uc.AuthProviders(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.AuthProvidersReply{Revision: rev(reply.Revision)}
	for _, item := range reply.Items {
		out.Items = append(out.Items, &usercv1.AuthProviderView{
			Code: item.Code, Name: item.Name, Enabled: item.Enabled,
			CredentialSource: item.CredentialSource, CredentialConfigured: item.CredentialConfigured,
			CallbackUrl: item.CallbackURL, RequiredEnv: item.RequiredEnv, UpdatedAt: ts(item.UpdatedAt),
		})
	}
	return out, nil
}

// --- R12: organization quota settings ---

func organizationSettingsProto(s *biz.OrganizationSettings) *usercv1.OrganizationSettings {
	return &usercv1.OrganizationSettings{
		QuotaEnabled: s.QuotaEnabled, MaxOwnedPerUser: int32(s.MaxOwnedPerUser),
		CountArchived: s.CountArchived, Revision: rev(s.Revision), UpdatedAt: ts(s.UpdatedAt),
	}
}

func (s *SettingsService) GetOrganizationSettings(ctx context.Context, _ *usercv1.GetOrganizationSettingsRequest) (*usercv1.OrganizationSettings, error) {
	settings, err := s.uc.GetOrganizationSettings(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	return organizationSettingsProto(settings), nil
}

func (s *SettingsService) UpdateOrganizationSettings(ctx context.Context, req *usercv1.UpdateOrganizationSettingsRequest) (*usercv1.OrganizationSettings, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	settings, err := s.uc.UpdateOrganizationSettings(ctx, requestMeta(ctx), &biz.OrganizationSettings{
		QuotaEnabled: req.GetQuotaEnabled(), MaxOwnedPerUser: int(req.GetMaxOwnedPerUser()),
		CountArchived: req.GetCountArchived(),
	}, req.GetUpdateMask(), expected, reason)
	if err != nil {
		return nil, err
	}
	return organizationSettingsProto(settings), nil
}

// --- R10: username change ---

func (s *MeService) UpdateUsername(ctx context.Context, req *usercv1.UpdateUsernameRequest) (*usercv1.User, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	user, err := s.users.UpdateUsername(ctx, actor, biz.UpdateUsernameInput{
		Username: req.GetUsername(), CurrentPassword: req.GetCurrentPassword(),
		ExpectedRevision: expected, Reason: reason,
	})
	if err != nil {
		return nil, err
	}
	return userProto(user), nil
}

// --- R11: single assignment preview ---

func (s *IAMService) PreviewAssignment(ctx context.Context, req *usercv1.PreviewAssignmentRequest) (*usercv1.PreviewAssignmentReply, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	boundary, err := scopeBiz(req.GetBoundary())
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	preview, err := s.iam.PreviewAssignment(ctx, requestMeta(ctx), userID, roleID, boundary, expPtr)
	if err != nil {
		return nil, err
	}
	out := &usercv1.PreviewAssignmentReply{
		Eligible: preview.Eligible, Reason: preview.Reason, Scope: preview.Scope,
		PolicyRevision: rev(preview.PolicyRevision), RoleStatus: preview.RoleStatus,
	}
	if preview.ValidUntil != nil {
		out.ValidUntil = ts(*preview.ValidUntil)
	}
	if preview.MaxMembers != nil {
		out.MaxMembers = rev(uint64(*preview.MaxMembers))
	}
	for _, g := range preview.Permissions {
		out.Permissions = append(out.Permissions, &usercv1.PermissionSummary{
			Operation: g.Operation, Effect: g.Effect, Scope: g.Scope,
		})
	}
	for _, src := range preview.Denies {
		out.DenySources = append(out.DenySources, grantSourceProto(src, userID))
	}
	return out, nil
}
