package service

import (
	"context"
	"errors"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

// IntegrationService is the internal gRPC surface. The gRPC interceptor
// authenticates the integration client before any handler runs.
type IntegrationService struct {
	usercv1.UnimplementedIntegrationServiceServer
	uc *biz.IntegrationUsecase
}

func NewIntegrationService(uc *biz.IntegrationUsecase) *IntegrationService {
	return &IntegrationService{uc: uc}
}

// Usecase exposes the integration usecase to the gRPC auth interceptor.
func (s *IntegrationService) Usecase() *biz.IntegrationUsecase { return s.uc }

func (s *IntegrationService) ValidateSession(ctx context.Context, req *usercv1.ValidateSessionRequest) (*usercv1.ValidateSessionReply, error) {
	facts, user, err := s.uc.ValidateSession(ctx, req.GetSessionToken(), req.GetApplicationCode())
	if err != nil {
		if errors.Is(err, biz.ErrUnauthenticated) || errors.Is(err, biz.ErrSessionRevoked) {
			return &usercv1.ValidateSessionReply{Valid: false, Reason: "SESSION_INVALID"}, nil
		}
		return nil, err
	}
	return &usercv1.ValidateSessionReply{
		Valid: true,
		Session: &usercv1.SessionFacts{
			SessionId: facts.SessionID, UserId: id(facts.UserID),
			ApplicationCode: facts.ApplicationCode, Status: facts.Status,
			IdentityVersion: rev(facts.IdentityVersion),
			IssuedAt:        ts(facts.IssuedAt), ExpiresAt: ts(facts.ExpiresAt),
		},
		User: userProto(user),
	}, nil
}

func (s *IntegrationService) ValidateSubject(ctx context.Context, req *usercv1.ValidateSubjectRequest) (*usercv1.ValidateSubjectReply, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	enabled, status, version, err := s.uc.ValidateSubject(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &usercv1.ValidateSubjectReply{Enabled: enabled, Status: status, IdentityVersion: rev(version)}, nil
}

func (s *IntegrationService) GetUser(ctx context.Context, req *usercv1.IntegrationGetUserRequest) (*usercv1.IntegrationUserReply, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := s.uc.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &usercv1.IntegrationUserReply{User: userProto(u)}, nil
}

func (s *IntegrationService) BatchGetUsers(ctx context.Context, req *usercv1.BatchGetUsersRequest) (*usercv1.IntegrationUsersReply, error) {
	ids, err := parseIDs(req.GetUserIds(), "user_id")
	if err != nil {
		return nil, err
	}
	users, err := s.uc.BatchGetUsers(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := &usercv1.IntegrationUsersReply{}
	for _, u := range users {
		out.Items = append(out.Items, userProto(u))
	}
	return out, nil
}

func (s *IntegrationService) GetSessionAuthorization(ctx context.Context, req *usercv1.SessionAuthorizationRequest) (*usercv1.SessionAuthorizationReply, error) {
	grants, menus, policy, err := s.uc.SessionAuthorization(ctx, req.GetSessionToken(), req.GetApplicationCode())
	if err != nil {
		return nil, err
	}
	out := &usercv1.SessionAuthorizationReply{MenuKeys: menus, PolicyRevision: rev(policy)}
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

func (s *IntegrationService) GetResourceAuthorization(ctx context.Context, req *usercv1.ResourceAuthorizationRequest) (*usercv1.ResourceAuthorizationReply, error) {
	var ownerID, resourceID int64
	var err error
	if req.GetObject() != nil && req.GetObject().GetOwnerUserId() != "" {
		ownerID, err = parseIDField(req.GetObject().GetOwnerUserId(), "owner_user_id")
		if err != nil {
			return nil, err
		}
	}
	if req.GetObject() != nil && req.GetObject().GetResourceId() != "" {
		resourceID, err = parseIDField(req.GetObject().GetResourceId(), "resource_id")
		if err != nil {
			return nil, err
		}
	}
	allowed, reason, scope, policy, validUntil, err := s.uc.ResourceAuthorization(ctx, req.GetSessionToken(), req.GetExecutionPoint(), req.GetOperation(), ownerID, resourceID)
	if err != nil {
		return nil, err
	}
	return &usercv1.ResourceAuthorizationReply{
		Allowed: allowed, Reason: reason, Scope: scopeProto(scope), PolicyRevision: rev(policy), ValidUntil: tptr(validUntil),
	}, nil
}

func (s *IntegrationService) RevokeSession(ctx context.Context, req *usercv1.IntegrationRevokeSessionRequest) (*emptypb.Empty, error) {
	if err := s.uc.RevokeSession(ctx, req.GetSessionToken(), req.GetSessionId(), req.GetReason()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
