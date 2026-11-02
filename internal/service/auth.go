package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type AuthService struct {
	usercv1.UnimplementedAuthServiceServer
	uc   *biz.AuthUsecase
	deps Deps
}

func NewAuthService(uc *biz.AuthUsecase, deps Deps) *AuthService {
	return &AuthService{uc: uc, deps: deps}
}

// Usecase exposes the auth usecase to the raw OAuth redirect handlers.
func (s *AuthService) Usecase() *biz.AuthUsecase { return s.uc }

func (s *AuthService) GetAuthContext(ctx context.Context, _ *usercv1.GetAuthContextRequest) (*usercv1.AuthContext, error) {
	settings, err := s.uc.AuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	providers := s.uc.OAuthProviders()
	if providers == nil {
		providers = []string{}
	}
	return &usercv1.AuthContext{
		RegistrationEnabled:       settings.RegistrationEnabled,
		EmailVerificationRequired: settings.EmailVerificationRequired,
		Providers:                 providers,
		CsrfToken:                 ensureCSRF(ctx, s.deps),
		PasswordMinLength:         int32(settings.PasswordMinLength),
		MfaRequiredForAdmins:      settings.MFARequiredForAdmins,
	}, nil
}

func (s *AuthService) CreateRegistrationChallenge(ctx context.Context, req *usercv1.CreateRegistrationChallengeRequest) (*usercv1.ChallengeReply, error) {
	meta := requestMeta(ctx)
	challengeID, expires, err := s.uc.CreateRegistrationChallenge(ctx, req.GetEmail(), meta.IP)
	if err != nil {
		return nil, err
	}
	return &usercv1.ChallengeReply{ChallengeId: challengeID, ExpiresAt: expires.Format(timeLayout)}, nil
}

func (s *AuthService) Register(ctx context.Context, req *usercv1.RegisterRequest) (*usercv1.RegisterReply, error) {
	user, err := s.uc.Register(ctx, biz.RegisterInput{
		Username: req.GetUsername(), Email: req.GetEmail(), Password: req.GetPassword(),
		Code: req.GetCode(), ChallengeID: req.GetChallengeId(), TermsVersion: req.GetTermsVersion(),
	})
	if err != nil {
		return nil, err
	}
	user.MFAEnabled = false
	return &usercv1.RegisterReply{User: userProto(user)}, nil
}

func (s *AuthService) Login(ctx context.Context, req *usercv1.LoginRequest) (*usercv1.LoginReply, error) {
	meta := requestMeta(ctx)
	result, err := s.uc.Login(ctx, biz.LoginInput{
		Username: req.GetUsername(), Password: req.GetPassword(),
		Remember: req.GetRemember(), IP: meta.IP, UserAgent: meta.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	reply := &usercv1.LoginReply{
		Status: result.Status, PasswordChangeRequired: result.PasswordChangeRequired,
		MfaEnrollmentRequired: s.uc.MFAEnrollmentRequired(ctx, result.User),
	}
	if result.User != nil {
		reply.User = userProto(result.User)
	}
	if result.Status == "mfa_required" {
		reply.ChallengeId = result.ChallengeID
		reply.ChallengeExpiresAt = result.ChallengeExpires.Format(timeLayout)
		return reply, nil
	}
	setSessionCookie(ctx, s.deps, result.RawToken, result.Session.ExpiresAt)
	reply.SessionExpiresAt = result.Session.ExpiresAt.Format(timeLayout)
	return reply, nil
}

func (s *AuthService) CompleteMFA(ctx context.Context, req *usercv1.CompleteMFARequest) (*usercv1.LoginReply, error) {
	meta := requestMeta(ctx)
	result, err := s.uc.CompleteMFA(ctx, req.GetChallengeId(), req.GetCode(), meta.IP, meta.UserAgent)
	if err != nil {
		return nil, err
	}
	setSessionCookie(ctx, s.deps, result.RawToken, result.Session.ExpiresAt)
	return &usercv1.LoginReply{
		Status: result.Status, User: userProto(result.User),
		SessionExpiresAt:       result.Session.ExpiresAt.Format(timeLayout),
		PasswordChangeRequired: result.PasswordChangeRequired,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, _ *usercv1.LogoutRequest) (*emptypb.Empty, error) {
	actor, _ := biz.ActorFromContext(ctx)
	_ = s.uc.Logout(ctx, actor)
	clearSessionCookie(ctx, s.deps)
	return &emptypb.Empty{}, nil
}

func (s *AuthService) CreatePasswordResetChallenge(ctx context.Context, req *usercv1.CreatePasswordResetChallengeRequest) (*usercv1.ChallengeReply, error) {
	meta := requestMeta(ctx)
	challengeID, expires, err := s.uc.CreatePasswordResetChallenge(ctx, req.GetIdentifier(), meta.IP)
	if err != nil {
		return nil, err
	}
	return &usercv1.ChallengeReply{ChallengeId: challengeID, ExpiresAt: expires.Format(timeLayout)}, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req *usercv1.ResetPasswordRequest) (*emptypb.Empty, error) {
	if err := s.uc.ResetPassword(ctx, req.GetChallengeId(), req.GetCode(), req.GetNewPassword()); err != nil {
		return nil, err
	}
	clearSessionCookie(ctx, s.deps)
	return &emptypb.Empty{}, nil
}
