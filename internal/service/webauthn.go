package service

import (
	"context"
	"encoding/base64"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

func decodeB64(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

func webAuthnCredentialProto(c *biz.WebAuthnCredential) *usercv1.WebAuthnCredential {
	out := &usercv1.WebAuthnCredential{
		Id: id(c.ID), CredentialId: c.CredentialID, Name: c.Name,
		Aaguid: c.AAGUID, Transports: c.Transports,
		SignCount: rev(uint64(c.SignCount)), CreatedAt: ts(c.CreatedAt),
		Revision: rev(c.Revision),
	}
	if c.LastUsedAt != nil {
		out.LastUsedAt = ts(*c.LastUsedAt)
	}
	return out
}

func (s *MeService) CreateWebAuthnRegistrationChallenge(ctx context.Context, req *usercv1.CreateWebAuthnRegistrationChallengeRequest) (*usercv1.WebAuthnRegistrationChallengeReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.webauthn.RegistrationChallenge(ctx, actor, req.GetCurrentPassword())
	if err != nil {
		return nil, err
	}
	return &usercv1.WebAuthnRegistrationChallengeReply{
		ChallengeId: c.ChallengeID, Challenge: c.Challenge, RpId: c.RPID,
		RpName: c.RPName, UserId: c.UserID, UserName: c.UserName,
		ExpiresAt: ts(c.ExpiresAt), ExistingCredentialIds: c.ExistingCredentialIDs,
	}, nil
}

func (s *MeService) ConfirmWebAuthnRegistration(ctx context.Context, req *usercv1.ConfirmWebAuthnRegistrationRequest) (*usercv1.WebAuthnCredential, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	attestation, err := decodeB64(req.GetAttestationObject())
	if err != nil {
		return nil, biz.Validation("attestation_object 不是合法的 base64url")
	}
	clientData, err := decodeB64(req.GetClientDataJson())
	if err != nil {
		return nil, biz.Validation("client_data_json 不是合法的 base64url")
	}
	cred, err := s.webauthn.ConfirmRegistration(ctx, actor, biz.WebAuthnRegistrationInput{
		ChallengeID: req.GetChallengeId(), CredentialID: req.GetCredentialId(),
		AttestationObject: attestation, ClientDataJSON: clientData,
		Transports: req.GetTransports(), Name: req.GetName(),
	})
	if err != nil {
		return nil, err
	}
	return webAuthnCredentialProto(cred), nil
}

func (s *MeService) ListWebAuthnCredentials(ctx context.Context, _ *usercv1.ListWebAuthnCredentialsRequest) (*usercv1.WebAuthnCredentialsReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.webauthn.List(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.WebAuthnCredentialsReply{}
	for _, item := range items {
		out.Items = append(out.Items, webAuthnCredentialProto(item))
	}
	return out, nil
}

func (s *MeService) DeleteWebAuthnCredential(ctx context.Context, req *usercv1.DeleteWebAuthnCredentialRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	credID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	if err := s.webauthn.Delete(ctx, actor, credID, req.GetCurrentPassword()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *MeService) CreateWebAuthnAssertionChallenge(ctx context.Context, req *usercv1.CreateWebAuthnAssertionChallengeRequest) (*usercv1.WebAuthnAssertionChallengeReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.webauthn.AssertionChallenge(ctx, actor, req.GetCurrentPassword())
	if err != nil {
		return nil, err
	}
	return &usercv1.WebAuthnAssertionChallengeReply{
		ChallengeId: c.ChallengeID, Challenge: c.Challenge, RpId: c.RPID,
		AllowCredentialIds: c.AllowCredentialIDs, ExpiresAt: ts(c.ExpiresAt),
	}, nil
}

func (s *MeService) VerifyWebAuthnAssertion(ctx context.Context, req *usercv1.VerifyWebAuthnAssertionRequest) (*usercv1.VerifySecurityReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
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
	until, err := s.webauthn.VerifyAssertion(ctx, actor, biz.WebAuthnAssertion{
		ChallengeID: req.GetChallengeId(), CredentialID: req.GetCredentialId(),
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: signature,
	}, req.GetCurrentPassword(), true)
	if err != nil {
		return nil, err
	}
	return &usercv1.VerifySecurityReply{Verified: true, ExpiresAt: ts(until)}, nil
}

func (s *AuthService) CompleteMFAWithWebAuthn(ctx context.Context, req *usercv1.CompleteMFARequest) (*usercv1.LoginReply, error) {
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
	result, err := s.uc.CompleteMFAWithWebAuthn(ctx, biz.WebAuthnAssertion{
		ChallengeID: req.GetChallengeId(), CredentialID: req.GetCredentialId(),
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: signature,
	}, meta.IP, meta.UserAgent)
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
