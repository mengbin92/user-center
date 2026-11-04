package service

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

func orgRoleProto(r *biz.Role) *usercv1.OrgRole {
	if r == nil {
		return nil
	}
	out := &usercv1.OrgRole{
		Id: id(r.ID), Code: r.Code, Name: r.Name, Description: r.Description,
		Builtin: r.Builtin, Status: r.Status, Revision: rev(r.Revision),
	}
	for _, g := range r.Grants {
		out.Grants = append(out.Grants, grantProto(g))
	}
	return out
}

func orgAssignmentProto(a *biz.AssignmentItem) *usercv1.OrgAssignment {
	if a == nil || a.Assignment == nil {
		return nil
	}
	x := a.Assignment
	return &usercv1.OrgAssignment{
		Id: id(x.ID), UserId: id(x.UserID), Username: a.Username, DisplayName: a.DisplayName,
		RoleId: id(x.RoleID), RoleCode: a.RoleCode, RoleName: a.RoleName,
		Boundary: scopeProto(x.Boundary), Status: statusOf(x), Revision: rev(x.Revision),
		Origin: x.Origin, ExpiresAt: tptr(x.ExpiresAt), CreatedAt: ts(x.CreatedAt),
	}
}

func statusOf(a *biz.Assignment) string {
	if a.Revoked {
		return "revoked"
	}
	return "active"
}

func orgAuditProto(e *biz.AuditEvent) *usercv1.OrgAuditEvent {
	return &usercv1.OrgAuditEvent{
		EventId: e.EventID, ActorUserId: id(e.ActorUserID), Action: e.Action, Target: e.Target,
		Result: e.Result, Reason: e.Reason, OccurredAt: ts(e.OccurredAt),
	}
}

func (s *OrganizationService) ListOrgRoles(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.OrgRolesReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roles, err := s.iam.Roles(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgRolesReply{}
	for _, r := range roles {
		out.Items = append(out.Items, orgRoleProto(r))
	}
	return out, nil
}

func (s *OrganizationService) ListOrgPermissions(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.OrgPermissionsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.Permissions(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgPermissionsReply{}
	for _, p := range items {
		out.Items = append(out.Items, permissionProto(p))
	}
	return out, nil
}

func (s *OrganizationService) CreateOrgRole(ctx context.Context, req *usercv1.CreateOrgRoleRequest) (*usercv1.OrgRole, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	role, err := s.iam.CreateRole(ctx, actor, orgID, biz.OrgRoleInput{
		Code: req.GetCode(), Name: req.GetName(), Description: req.GetDescription(), Grants: grants,
	}, auditReason)
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) UpdateOrgRole(ctx context.Context, req *usercv1.UpdateOrgRoleRequest) (*usercv1.OrgRole, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	role, err := s.iam.UpdateRole(ctx, actor, orgID, roleID, req.GetName(), req.GetDescription(), expected, auditReason)
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) PutOrgRolePermissions(ctx context.Context, req *usercv1.PutOrgRolePermissionsRequest) (*usercv1.OrgRole, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	role, err := s.iam.PutRoleGrants(ctx, actor, orgID, roleID, grants, expected, auditReason)
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) ArchiveOrgRole(ctx context.Context, req *usercv1.ArchiveOrgRoleRequest) (*emptypb.Empty, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.iam.ArchiveRole(ctx, actor, orgID, roleID, expected, auditReason); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) ListOrgAssignments(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.OrgAssignmentsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.Assignments(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgAssignmentsReply{}
	for _, item := range items {
		out.Items = append(out.Items, orgAssignmentProto(item))
	}
	return out, nil
}

func (s *OrganizationService) CreateOrgAssignment(ctx context.Context, req *usercv1.CreateOrgAssignmentRequest) (*usercv1.OrgAssignment, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
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
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	var expires *time.Time
	if raw := req.GetExpiresAt(); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, biz.Validation("expires_at 必须为 RFC3339 时间")
		}
		expires = &t
	}
	assignment, err := s.iam.AssignRole(ctx, actor, orgID, biz.OrgAssignmentInput{
		UserID: userID, RoleID: roleID, ExpiresAt: expires,
	}, auditReason)
	if err != nil {
		return nil, err
	}
	item := &biz.AssignmentItem{Assignment: assignment}
	return orgAssignmentProto(item), nil
}

func (s *OrganizationService) RevokeOrgAssignment(ctx context.Context, req *usercv1.RevokeOrgAssignmentRequest) (*emptypb.Empty, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	assignmentID, err := parseIDField(req.GetAssignmentId(), "assignment_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.iam.RevokeAssignment(ctx, actor, orgID, assignmentID, expected, auditReason); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) ListOrgAudits(ctx context.Context, req *usercv1.ListOrgAuditsRequest) (*usercv1.OrgAuditsReply, error) {
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
	events, total, err := s.iam.Audits(ctx, actor, orgID, req.GetAction(), from, to, int(req.GetOffset()), pageSize(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgAuditsReply{Total: total}
	for _, e := range events {
		out.Items = append(out.Items, orgAuditProto(e))
	}
	return out, nil
}

func optionalTime(raw, field string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, biz.Validation(field + " 必须为 RFC3339 时间")
	}
	return &t, nil
}
