package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type MeService struct {
	usercv1.UnimplementedMeServiceServer
	users    *biz.UserUsecase
	security *biz.SecurityUsecase
	sessions *biz.SessionUsecase
	oidc     *biz.OIDCUsecase
	webauthn *biz.WebAuthnUsecase
	deps     Deps
}

func NewMeService(users *biz.UserUsecase, security *biz.SecurityUsecase, sessions *biz.SessionUsecase, oidc *biz.OIDCUsecase, webauthn *biz.WebAuthnUsecase, deps Deps) *MeService {
	return &MeService{users: users, security: security, sessions: sessions, oidc: oidc, webauthn: webauthn, deps: deps}
}

func requireActor(ctx context.Context) (biz.ActorContext, error) {
	return biz.RequireActor(ctx)
}

func (s *MeService) GetMe(ctx context.Context, _ *usercv1.GetMeRequest) (*usercv1.User, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.users.Me(ctx, actor)
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *MeService) UpdateMe(ctx context.Context, req *usercv1.UpdateMeRequest) (*usercv1.User, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	revision, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	u, err := s.users.UpdateMe(ctx, actor, biz.UpdateMeInput{
		DisplayName: req.GetDisplayName(), UpdateMask: req.GetUpdateMask(), ExpectedRevision: revision,
	})
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *MeService) ChangePassword(ctx context.Context, req *usercv1.ChangePasswordRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.users.ChangePassword(ctx, actor, req.GetCurrentPassword(), req.GetNewPassword()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) CreateEmailChallenge(ctx context.Context, req *usercv1.CreateEmailChallengeRequest) (*usercv1.ChallengeReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	challengeID, expires, err := s.users.CreateEmailChallenge(ctx, actor, req.GetNewEmail(), req.GetCurrentPassword())
	if err != nil {
		return nil, err
	}
	return &usercv1.ChallengeReply{ChallengeId: challengeID, ExpiresAt: expires.Format(timeLayout)}, nil
}

func (s *MeService) ConfirmEmail(ctx context.Context, req *usercv1.ConfirmEmailRequest) (*usercv1.User, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.users.ConfirmEmail(ctx, actor, req.GetChallengeId(), req.GetCode())
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *MeService) ListExternalIdentities(ctx context.Context, _ *usercv1.ListExternalIdentitiesRequest) (*usercv1.ExternalIdentitiesReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.users.ExternalIdentities(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.ExternalIdentitiesReply{}
	for _, identity := range items {
		out.Items = append(out.Items, &usercv1.ExternalIdentity{
			Id: id(identity.ID), Provider: identity.Provider, Display: identity.Display,
			CreatedAt: ts(identity.CreatedAt),
		})
	}
	return out, nil
}

func (s *MeService) DeleteExternalIdentity(ctx context.Context, req *usercv1.DeleteExternalIdentityRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	identityID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	if err := s.users.DeleteExternalIdentity(ctx, actor, identityID); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) GetSecurity(ctx context.Context, _ *usercv1.GetSecurityRequest) (*usercv1.SecurityStatus, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	enabled, passwordAvailable, remaining, until, err := s.security.Status(ctx, actor)
	if err != nil {
		return nil, err
	}
	settings, cfgErr := s.security.AuthConfig(ctx)
	mfaRequired := false
	if cfgErr == nil && settings.MFARequiredForAdmins && !enabled {
		for _, role := range actor.User.Roles {
			if role.Code == "root" || role.Code == "admin" {
				mfaRequired = true
				break
			}
		}
	}
	return &usercv1.SecurityStatus{
		MfaEnabled: enabled, PasswordAvailable: passwordAvailable,
		RecoveryCodesRemaining: int32(remaining), StepUpVerified: !until.IsZero(),
		StepUpExpiresAt: ts(until), MfaRequired: mfaRequired,
		PasswordChangeRequired: actor.PasswordChangeRequired,
	}, nil
}

func (s *MeService) SetupMFA(ctx context.Context, req *usercv1.SetupMFARequest) (*usercv1.SetupMFAReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	secret, uri, expires, err := s.security.Setup(ctx, actor, req.GetCurrentPassword())
	if err != nil {
		return nil, err
	}
	return &usercv1.SetupMFAReply{Secret: secret, OtpauthUri: uri, ExpiresAt: expires.Format(timeLayout)}, nil
}

func (s *MeService) ConfirmMFA(ctx context.Context, req *usercv1.ConfirmMFARequest) (*usercv1.RecoveryCodesReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := s.security.Confirm(ctx, actor, req.GetCode())
	if err != nil {
		return nil, err
	}
	return &usercv1.RecoveryCodesReply{RecoveryCodes: codes}, nil
}

func (s *MeService) DisableMFA(ctx context.Context, req *usercv1.DisableMFARequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.security.Disable(ctx, actor, req.GetCurrentPassword(), req.GetCode()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) RotateRecoveryCodes(ctx context.Context, req *usercv1.RotateRecoveryCodesRequest) (*usercv1.RecoveryCodesReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := s.security.RotateRecoveryCodes(ctx, actor, req.GetCurrentPassword(), req.GetCode())
	if err != nil {
		return nil, err
	}
	return &usercv1.RecoveryCodesReply{RecoveryCodes: codes}, nil
}

func (s *MeService) VerifySecurity(ctx context.Context, req *usercv1.VerifySecurityRequest) (*usercv1.VerifySecurityReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	until, err := s.security.Verify(ctx, actor, req.GetCurrentPassword(), req.GetCode())
	if err != nil {
		return nil, err
	}
	return &usercv1.VerifySecurityReply{Verified: true, ExpiresAt: ts(until)}, nil
}

func (s *MeService) ListSessions(ctx context.Context, _ *usercv1.ListSessionsRequest) (*usercv1.SessionsReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.sessions.List(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.SessionsReply{}
	for _, row := range rows {
		out.Items = append(out.Items, sessionProto(row, actor.Session.ID))
	}
	return out, nil
}

func sessionProto(s *biz.Session, currentID string) *usercv1.SessionInfo {
	out := &usercv1.SessionInfo{
		Id: s.ID, UserId: id(s.UserID), ApplicationCode: s.ApplicationCode,
		Device: s.UserAgent, IpMasked: s.IPMasked, Current: s.ID == currentID,
		IssuedAt: ts(s.IssuedAt), LastSeenAt: ts(s.LastSeenAt),
		ExpiresAt: ts(s.ExpiresAt), RevokedAt: tptr(s.RevokedAt),
	}
	for _, roleID := range s.ActiveRoleIDs {
		out.ActiveRoleIds = append(out.ActiveRoleIds, id(roleID))
	}
	return out
}

func (s *MeService) RevokeSession(ctx context.Context, req *usercv1.RevokeSessionRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.RevokeOwn(ctx, actor, req.GetId()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) RevokeOtherSessions(ctx context.Context, _ *usercv1.RevokeOtherSessionsRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.RevokeOthers(ctx, actor); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) GetSessionRoles(ctx context.Context, _ *usercv1.GetSessionRolesRequest) (*usercv1.SessionRolesReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	roles, revision, err := s.sessions.Roles(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.SessionRolesReply{Revision: rev(revision)}
	for _, r := range roles {
		out.Items = append(out.Items, &usercv1.SessionRole{
			Id: id(r.ID), Code: r.Code, Name: r.Name, Active: r.Active, Builtin: r.Builtin,
		})
	}
	return out, nil
}

func (s *MeService) PutSessionRoles(ctx context.Context, req *usercv1.PutSessionRolesRequest) (*usercv1.SessionRolesReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	var roleIDs []int64
	for _, raw := range req.GetRoleIds() {
		roleID, err := parseIDField(raw, "role_id")
		if err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, roleID)
	}
	revision, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	roles, newRevision, err := s.sessions.PutRoles(ctx, actor, roleIDs, revision)
	if err != nil {
		return nil, err
	}
	out := &usercv1.SessionRolesReply{Revision: rev(newRevision)}
	for _, r := range roles {
		out.Items = append(out.Items, &usercv1.SessionRole{
			Id: id(r.ID), Code: r.Code, Name: r.Name, Active: r.Active, Builtin: r.Builtin,
		})
	}
	return out, nil
}

func (s *MeService) GetAuthorization(ctx context.Context, _ *usercv1.GetAuthorizationRequest) (*usercv1.AuthorizationReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	grants, menus, policy, userRev, err := s.sessions.Authorization(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.AuthorizationReply{
		MenuKeys: menus, PolicyRevision: rev(policy), UserRevision: rev(userRev),
	}
	seen := map[string]bool{}
	for _, g := range grants {
		key := g.Operation + "|" + g.Effect
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Permissions = append(out.Permissions, &usercv1.PermissionSummary{
			Operation: g.Operation, Effect: g.Effect, Scope: g.Scope,
		})
	}
	return out, nil
}

func (s *MeService) ListSecurityEvents(ctx context.Context, req *usercv1.ListSecurityEventsRequest) (*usercv1.SecurityEventsReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	events, next, err := s.users.SecurityEvents(ctx, actor, pageSize(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &usercv1.SecurityEventsReply{Meta: &usercv1.ListMeta{NextPageToken: next}}
	for _, e := range events {
		out.Items = append(out.Items, &usercv1.SecurityEvent{
			Id: e.ID, UserId: id(e.UserID), SessionId: e.SessionID, Kind: e.Kind,
			Result: e.Result, IpMasked: e.IPMasked, UserAgentSummary: e.UserAgentSummary,
			RequestId: e.RequestID, OccurredAt: ts(e.OccurredAt),
		})
	}
	return out, nil
}
