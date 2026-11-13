package service

import (
	"context"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

func (s *AuthService) BeginPasskeyLogin(ctx context.Context, req *usercv1.BeginPasskeyLoginRequest) (*usercv1.PasskeyLoginChallengeReply, error) {
	meta := requestMeta(ctx)
	challenge, err := s.uc.BeginPasskeyLogin(ctx, req.GetUsername(), meta.IP)
	if err != nil {
		return nil, err
	}
	allow := challenge.AllowCredentialIDs
	if allow == nil {
		allow = []string{}
	}
	return &usercv1.PasskeyLoginChallengeReply{
		ChallengeId: challenge.ChallengeID, Challenge: challenge.Challenge,
		RpId: challenge.RPID, AllowCredentialIds: allow,
		ExpiresAt: challenge.ExpiresAt.Format(timeLayout),
	}, nil
}

// CompletePasskeyLogin mints the same HttpOnly session cookie as the password
// path. An MFA-pending account gets mfa_required plus a challenge, never a
// cookie.
func (s *AuthService) CompletePasskeyLogin(ctx context.Context, req *usercv1.CompletePasskeyLoginRequest) (*usercv1.LoginReply, error) {
	meta := requestMeta(ctx)
	authData, err := decodeB64(req.GetAuthenticatorData())
	if err != nil {
		return nil, biz.Validation("authenticator_data 不是合法的 base64url")
	}
	clientData, err := decodeB64(req.GetClientDataJson())
	if err != nil {
		return nil, biz.Validation("client_data_json 不是合法的 base64url")
	}
	signature, err := decodeB64(req.GetSignature())
	if err != nil {
		return nil, biz.Validation("signature 不是合法的 base64url")
	}
	result, err := s.uc.CompletePasskeyLogin(ctx, biz.PasskeyLoginInput{
		ChallengeID: req.GetChallengeId(),
		Assertion: biz.WebAuthnAssertion{
			ChallengeID: req.GetChallengeId(), CredentialID: req.GetCredentialId(),
			AuthenticatorData: authData, ClientDataJSON: clientData, Signature: signature,
		},
		Remember: req.GetRemember(), IP: meta.IP, UserAgent: meta.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	reply := &usercv1.LoginReply{
		Status: result.Status, User: userProto(result.User),
		PasswordChangeRequired: result.PasswordChangeRequired,
		RecycledSessions:       int32(result.RecycledSessions),
	}
	if result.User != nil {
		reply.MfaEnrollmentRequired = s.uc.MFAEnrollmentRequired(ctx, result.User)
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
