package service

import (
	"context"
	"time"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type IntegrationAdminService struct {
	usercv1.UnimplementedIntegrationAdminServiceServer
	uc *biz.IntegrationAdminUsecase
}

func NewIntegrationAdminService(uc *biz.IntegrationAdminUsecase) *IntegrationAdminService {
	return &IntegrationAdminService{uc: uc}
}

func integrationClientProto(c *biz.IntegrationClient) *usercv1.IntegrationClient {
	out := &usercv1.IntegrationClient{
		Id: id(c.ID), ClientId: c.ClientID, Code: c.Code, ServiceOwner: c.ServiceOwner,
		Status: c.Status, AllowedMethods: c.AllowedMethods, EventSubscriptions: c.EventSubscriptions,
		CallbackUrl: c.CallbackURL, CredentialVersion: int32(c.CredentialVersion),
		ExpiresAt: tptr(c.ExpiresAt), CreatedAt: ts(c.CreatedAt), Revision: rev(c.Revision),
	}
	return out
}

func (s *IntegrationAdminService) ListIntegrationClients(ctx context.Context, _ *usercv1.ListIntegrationClientsRequest) (*usercv1.IntegrationClientsReply, error) {
	items, err := s.uc.Clients(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.IntegrationClientsReply{}
	for _, c := range items {
		out.Items = append(out.Items, integrationClientProto(c))
	}
	return out, nil
}

func (s *IntegrationAdminService) CreateIntegrationClient(ctx context.Context, req *usercv1.CreateIntegrationClientRequest) (*usercv1.IntegrationClientCredentialReply, error) {
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	result, err := s.uc.CreateClient(ctx, requestMeta(ctx), &biz.IntegrationClient{
		Code: req.GetCode(), ServiceOwner: req.GetServiceOwner(),
		AllowedMethods: req.GetAllowedMethods(), EventSubscriptions: req.GetEventSubscriptions(),
		CallbackURL: req.GetCallbackUrl(), ExpiresAt: expPtr,
	}, reasonOr(req.GetReason(), "create integration client"))
	if err != nil {
		return nil, err
	}
	return &usercv1.IntegrationClientCredentialReply{
		Client: integrationClientProto(result.Client), Credential: result.Credential,
	}, nil
}

func (s *IntegrationAdminService) UpdateIntegrationClient(ctx context.Context, req *usercv1.UpdateIntegrationClientRequest) (*usercv1.IntegrationClient, error) {
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	c, err := s.uc.UpdateClient(ctx, requestMeta(ctx), &biz.IntegrationClient{
		ID: clientID, AllowedMethods: req.GetAllowedMethods(),
		EventSubscriptions: req.GetEventSubscriptions(), CallbackURL: req.GetCallbackUrl(),
	}, expected, reasonOr(req.GetReason(), "update integration client"))
	if err != nil {
		return nil, err
	}
	return integrationClientProto(c), nil
}

func (s *IntegrationAdminService) RotateIntegrationClientCredential(ctx context.Context, req *usercv1.RotateIntegrationClientCredentialRequest) (*usercv1.IntegrationClientCredentialReply, error) {
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	result, err := s.uc.Rotate(ctx, requestMeta(ctx), clientID, reasonOr(req.GetReason(), "rotate integration credential"))
	if err != nil {
		return nil, err
	}
	return &usercv1.IntegrationClientCredentialReply{
		Client: integrationClientProto(result.Client), Credential: result.Credential,
	}, nil
}

func (s *IntegrationAdminService) DisableIntegrationClient(ctx context.Context, req *usercv1.DisableIntegrationClientRequest) (*usercv1.IntegrationClient, error) {
	clientID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	c, err := s.uc.Disable(ctx, requestMeta(ctx), clientID, reasonOr(req.GetReason(), "disable integration client"))
	if err != nil {
		return nil, err
	}
	return integrationClientProto(c), nil
}

func deliveryProto(d *biz.Delivery) *usercv1.EventDelivery {
	return &usercv1.EventDelivery{
		EventId: d.EventID, EventType: d.EventType, SubscriberId: d.SubscriberID,
		Status: d.Status, Attempts: int32(d.Attempts), NextRetryAt: ts(d.NextRetryAt),
		LastError: d.LastError,
	}
}

func (s *IntegrationAdminService) ListEventDeliveries(ctx context.Context, req *usercv1.ListEventDeliveriesRequest) (*usercv1.EventDeliveriesReply, error) {
	offset, err := biz.DecodePageToken(req.GetPageToken(), bizFingerprint(req.GetStatus()))
	if err != nil {
		return nil, err
	}
	limit := pageSize(req.GetPageSize())
	items, total, err := s.uc.Deliveries(ctx, requestMeta(ctx), req.GetStatus(), offset, limit)
	if err != nil {
		return nil, err
	}
	out := &usercv1.EventDeliveriesReply{Meta: &usercv1.ListMeta{TotalSize: rev(uint64(total))}}
	for _, d := range items {
		out.Items = append(out.Items, deliveryProto(d))
	}
	if offset+len(items) < int(total) {
		out.Meta.NextPageToken = biz.EncodePageToken(offset+len(items), bizFingerprint(req.GetStatus()))
	}
	return out, nil
}

func (s *IntegrationAdminService) RetryEventDelivery(ctx context.Context, req *usercv1.RetryEventDeliveryRequest) (*usercv1.EventDelivery, error) {
	if err := s.uc.RetryDelivery(ctx, requestMeta(ctx), req.GetEventId(), req.GetSubscriberId(), reasonOr(req.GetReason(), "retry delivery")); err != nil {
		return nil, err
	}
	return &usercv1.EventDelivery{EventId: req.GetEventId(), SubscriberId: req.GetSubscriberId(), Status: "pending"}, nil
}
