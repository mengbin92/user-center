package service

import (
	"context"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type OIDCAdminService struct {
	usercv1.UnimplementedOIDCAdminServiceServer
	uc *biz.OIDCUsecase
}

func NewOIDCAdminService(uc *biz.OIDCUsecase) *OIDCAdminService {
	return &OIDCAdminService{uc: uc}
}

func (s *OIDCAdminService) Usecase() *biz.OIDCUsecase { return s.uc }

func oidcClientProto(c *biz.OIDCClient) *usercv1.OIDCClient {
	return &usercv1.OIDCClient{
		Id: id(c.ID), ClientId: c.ClientID, Name: c.Name, ServiceOwner: c.ServiceOwner,
		Status: c.Status, RedirectUris: c.RedirectURIs, Scopes: c.Scopes,
		Public: c.Public, RequirePkce: c.RequirePKCE,
		AccessTokenTtlSeconds: int32(c.AccessTTL), RefreshTokenTtlSeconds: int32(c.RefreshTTL),
		Revision: rev(c.Revision), CreatedAt: ts(c.CreatedAt),
	}
}

func (s *OIDCAdminService) ListOIDCClients(ctx context.Context, _ *usercv1.ListOIDCClientsRequest) (*usercv1.OIDCClientsReply, error) {
	items, err := s.uc.Clients(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.OIDCClientsReply{}
	for _, c := range items {
		out.Items = append(out.Items, oidcClientProto(c))
	}
	return out, nil
}

func (s *OIDCAdminService) CreateOIDCClient(ctx context.Context, req *usercv1.CreateOIDCClientRequest) (*usercv1.OIDCClientCredentialReply, error) {
	actor, err := managementMeta(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := s.uc.CreateClient(ctx, actor, biz.OIDCClientInput{
		Name: req.GetName(), ServiceOwner: req.GetServiceOwner(),
		RedirectURIs: req.GetRedirectUris(), Scopes: req.GetScopes(),
		Public: req.GetPublic(), RequirePKCE: req.GetRequirePkce(),
		AccessTTL: int(req.GetAccessTokenTtlSeconds()), RefreshTTL: int(req.GetRefreshTokenTtlSeconds()),
	}, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &usercv1.OIDCClientCredentialReply{Client: oidcClientProto(result.Client), ClientSecret: result.Secret}, nil
}

func (s *OIDCAdminService) UpdateOIDCClient(ctx context.Context, req *usercv1.UpdateOIDCClientRequest) (*usercv1.OIDCClient, error) {
	actor, err := managementMeta(ctx, req)
	if err != nil {
		return nil, err
	}
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	c, err := s.uc.UpdateClient(ctx, actor, clientID, biz.OIDCClientInput{
		Name: req.GetName(), RedirectURIs: req.GetRedirectUris(), Scopes: req.GetScopes(),
		Public: req.GetPublic(), RequirePKCE: req.GetRequirePkce(),
		AccessTTL: int(req.GetAccessTokenTtlSeconds()), RefreshTTL: int(req.GetRefreshTokenTtlSeconds()),
	}, expected, req.GetReason())
	if err != nil {
		return nil, err
	}
	return oidcClientProto(c), nil
}

func (s *OIDCAdminService) RotateOIDCClientSecret(ctx context.Context, req *usercv1.RotateOIDCClientSecretRequest) (*usercv1.OIDCClientCredentialReply, error) {
	actor, err := managementMeta(ctx, req)
	if err != nil {
		return nil, err
	}
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	result, err := s.uc.RotateSecret(ctx, actor, clientID, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &usercv1.OIDCClientCredentialReply{Client: oidcClientProto(result.Client), ClientSecret: result.Secret}, nil
}

func (s *OIDCAdminService) DisableOIDCClient(ctx context.Context, req *usercv1.DisableOIDCClientRequest) (*usercv1.OIDCClient, error) {
	actor, err := managementMeta(ctx, req)
	if err != nil {
		return nil, err
	}
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	c, err := s.uc.DisableClient(ctx, actor, clientID, req.GetReason())
	if err != nil {
		return nil, err
	}
	return oidcClientProto(c), nil
}
