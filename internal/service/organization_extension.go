package service

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

func organizationInvitationProto(inv *biz.OrganizationInvitation) *usercv1.OrganizationInvitation {
	out := &usercv1.OrganizationInvitation{
		Id: id(inv.ID), OrganizationId: id(inv.OrganizationID), Email: inv.Email,
		Role: inv.Role, Status: inv.Status, InvitedBy: id(inv.InvitedBy),
		ExpiresAt: ts(inv.ExpiresAt), CreatedAt: ts(inv.CreatedAt), Revision: rev(inv.Revision),
	}
	if inv.DepartmentID != nil {
		out.DepartmentId = id(*inv.DepartmentID)
	}
	if inv.AcceptedAt != nil {
		out.AcceptedAt = ts(*inv.AcceptedAt)
	}
	return out
}

func (s *OrganizationService) CreateOrganizationInvitation(ctx context.Context, req *usercv1.CreateOrganizationInvitationRequest) (*usercv1.OrganizationInvitation, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	var deptID *int64
	if req.GetDepartmentId() != "" {
		v, err := parseIDField(req.GetDepartmentId(), "department_id")
		if err != nil {
			return nil, err
		}
		deptID = &v
	}
	invitation, _, err := s.uc.CreateInvitation(ctx, actor, orgID, biz.InvitationInput{
		Email: req.GetEmail(), Role: req.GetRole(), DepartmentID: deptID,
	}, reason)
	if err != nil {
		return nil, err
	}
	// The raw token is only in the e-mail; never return it in the API response.
	return organizationInvitationProto(invitation), nil
}

func (s *OrganizationService) ListOrganizationInvitations(ctx context.Context, req *usercv1.ListOrganizationInvitationsRequest) (*usercv1.OrganizationInvitationsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.uc.ListInvitations(ctx, actor, orgID, req.GetStatus())
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrganizationInvitationsReply{}
	for _, item := range items {
		out.Items = append(out.Items, organizationInvitationProto(item))
	}
	return out, nil
}

func (s *OrganizationService) RevokeOrganizationInvitation(ctx context.Context, req *usercv1.RevokeOrganizationInvitationRequest) (*emptypb.Empty, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	invitationID, err := parseIDField(req.GetInvitationId(), "invitation_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.uc.RevokeInvitation(ctx, actor, orgID, invitationID, expected, reason); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) AcceptOrganizationInvitation(ctx context.Context, req *usercv1.AcceptOrganizationInvitationRequest) (*usercv1.OrganizationMember, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	member, err := s.uc.AcceptInvitation(ctx, actor, req.GetToken())
	if err != nil {
		return nil, err
	}
	return organizationMemberProto(member), nil
}

func (s *OrganizationService) ExportOrgAudits(ctx context.Context, req *usercv1.ExportOrgAuditsRequest) (*usercv1.ExportJob, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	from, err := optionalTime(req.GetFrom(), "from")
	if err != nil {
		return nil, err
	}
	to, err := optionalTime(req.GetTo(), "to")
	if err != nil {
		return nil, err
	}
	job, err := s.iam.ExportAudits(ctx, actor, orgID, biz.AuditFilter{
		Action: req.GetAction(), From: from, To: to,
	}, req.GetFields(), reason)
	if err != nil {
		return nil, err
	}
	return exportProto(job), nil
}

func (s *OrganizationService) ExplainOrgAuthorization(ctx context.Context, req *usercv1.ExplainOrgAuthorizationRequest) (*usercv1.ExplainOrgAuthorizationReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	result, err := s.iam.Explain(ctx, actor, orgID, userID, strings.TrimSpace(req.GetOperation()))
	if err != nil {
		return nil, err
	}
	out := &usercv1.ExplainOrgAuthorizationReply{
		Allowed: result.Allowed, Reason: result.Reason, Context: result.Context,
		Scope: result.Scope, Missing: result.Missing,
		PolicyRevision: rev(result.PolicyRevision), UserRevision: rev(result.UserRevision),
	}
	if result.ValidUntil != nil {
		out.ValidUntil = ts(*result.ValidUntil)
	}
	for _, src := range result.Sources {
		out.Sources = append(out.Sources, grantSourceProto(src, userID))
	}
	return out, nil
}

// AuditExportForDownload is used by the raw CSV streaming route. It re-checks
// tenant membership, organization.audit.read and the export snapshot.
func (s *OrganizationService) AuditExportForDownload(ctx context.Context, orgID, jobID int64) (*biz.ExportJob, error) {
	actor, ok := biz.ActorFromContext(ctx)
	if !ok {
		return nil, biz.ErrUnauthenticated
	}
	return s.uc.GetAuditExport(ctx, actor, orgID, jobID)
}
