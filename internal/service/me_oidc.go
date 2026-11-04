package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
)

// OIDC consent surface (V2.4 R1). All calls require the session that started
// the authorization request: the one-time handle is bound to that user.

func (s *MeService) GetOIDCConsentRequest(ctx context.Context, req *usercv1.GetOIDCConsentRequestRequest) (*usercv1.OIDCConsentRequestView, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	prompt, err := s.oidc.ConsentPrompt(ctx, actor, req.GetHandle())
	if err != nil {
		return nil, err
	}
	return &usercv1.OIDCConsentRequestView{
		ClientId: prompt.Client.ClientID, ClientName: prompt.Client.Name,
		ServiceOwner: prompt.Client.ServiceOwner, Scopes: prompt.Scopes,
		PreviouslyGrantedScopes: prompt.Granted, RedirectHost: prompt.RedirectHost,
		RequestedAt: ts(prompt.RequestedAt), ExpiresAt: ts(prompt.ExpiresAt),
	}, nil
}

func (s *MeService) DecideOIDCConsent(ctx context.Context, req *usercv1.DecideOIDCConsentRequest) (*usercv1.DecideOIDCConsentReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	redirect, err := s.oidc.DecideConsent(ctx, actor, req.GetHandle(), req.GetApprove(), req.GetRemember())
	if err != nil {
		return nil, err
	}
	return &usercv1.DecideOIDCConsentReply{RedirectUrl: redirect}, nil
}

func (s *MeService) ListOIDCConsents(ctx context.Context, _ *usercv1.ListOIDCConsentsRequest) (*usercv1.OIDCConsentsReply, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	consents, err := s.oidc.Consents(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OIDCConsentsReply{}
	for _, c := range consents {
		out.Items = append(out.Items, &usercv1.OIDCConsent{
			ClientId: c.ClientID, ClientName: s.oidc.ClientName(ctx, c.ClientID),
			Scopes: c.Scopes, GrantedAt: ts(c.GrantedAt), UpdatedAt: ts(c.UpdatedAt),
		})
	}
	return out, nil
}

func (s *MeService) RevokeOIDCConsent(ctx context.Context, req *usercv1.RevokeOIDCConsentRequest) (*emptypb.Empty, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.oidc.RevokeConsent(ctx, actor, req.GetClientId()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
