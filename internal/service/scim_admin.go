package service

import (
	"context"
	"strconv"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

// SCIMService is both the browser-facing governance surface for SCIM tokens
// and the owner of the raw /scim/v2 protocol handler. Keeping them on one
// struct means a rotated or disabled token is enforced by the same usecase the
// protocol handler authenticates against.
type SCIMService struct {
	usercv1.UnimplementedSCIMAdminServiceServer
	uc *biz.SCIMUsecase
}

func NewSCIMService(uc *biz.SCIMUsecase) *SCIMService { return &SCIMService{uc: uc} }

func scimTokenProto(t *biz.SCIMToken) *usercv1.SCIMToken {
	if t == nil {
		return nil
	}
	out := &usercv1.SCIMToken{
		Id: id(t.ID), OrganizationId: id(t.OrganizationID), Name: t.Name,
		Status: t.Status, CredentialVersion: fmtInt(t.CredentialVersion),
		Revision: rev(t.Revision), CreatedBy: id(t.CreatedBy), CreatedAt: ts(t.CreatedAt),
		LastUsedAt: tptr(t.LastUsedAt), DisabledAt: tptr(t.DisabledAt),
	}
	return out
}

func fmtInt(v int) string { return strconv.Itoa(v) }

func (s *SCIMService) ListSCIMTokens(ctx context.Context, req *usercv1.ListSCIMTokensRequest) (*usercv1.SCIMTokensReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	// An empty organization_id lists nothing rather than every tenant's tokens.
	var orgID int64
	if req.GetOrganizationId() != "" {
		orgID, err = parseIDField(req.GetOrganizationId(), "organization_id")
		if err != nil {
			return nil, err
		}
	} else {
		return &usercv1.SCIMTokensReply{}, nil
	}
	items, err := s.uc.Tokens(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.SCIMTokensReply{}
	for _, t := range items {
		out.Items = append(out.Items, scimTokenProto(t))
	}
	return out, nil
}

func (s *SCIMService) CreateSCIMToken(ctx context.Context, req *usercv1.CreateSCIMTokenRequest) (*usercv1.SCIMTokenCredentialReply, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	token, raw, err := s.uc.CreateToken(ctx, actor, orgID, req.GetName(), reason)
	if err != nil {
		return nil, err
	}
	return &usercv1.SCIMTokenCredentialReply{Token: scimTokenProto(token), TokenValue: raw}, nil
}

func (s *SCIMService) RotateSCIMToken(ctx context.Context, req *usercv1.RotateSCIMTokenRequest) (*usercv1.SCIMTokenCredentialReply, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	tokenID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	token, raw, err := s.uc.RotateToken(ctx, actor, tokenID, expected, reason)
	if err != nil {
		return nil, err
	}
	return &usercv1.SCIMTokenCredentialReply{Token: scimTokenProto(token), TokenValue: raw}, nil
}

func (s *SCIMService) DisableSCIMToken(ctx context.Context, req *usercv1.DisableSCIMTokenRequest) (*usercv1.SCIMToken, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	tokenID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	token, err := s.uc.DisableToken(ctx, actor, tokenID, expected, reason)
	if err != nil {
		return nil, err
	}
	return scimTokenProto(token), nil
}
