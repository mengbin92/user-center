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
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roles, err := s.iam.Roles(ctx, requestMeta(ctx), orgID)
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
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.Permissions(ctx, requestMeta(ctx), orgID)
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
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	role, err := s.iam.CreateRole(ctx, requestMeta(ctx), orgID, biz.OrgRoleInput{
		Code: req.GetCode(), Name: req.GetName(), Description: req.GetDescription(), Grants: grants,
	}, reasonOr(req.GetReason(), "create organization role"))
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) UpdateOrgRole(ctx context.Context, req *usercv1.UpdateOrgRoleRequest) (*usercv1.OrgRole, error) {
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
	role, err := s.iam.UpdateRole(ctx, requestMeta(ctx), orgID, roleID, req.GetName(), req.GetDescription(), expected, reasonOr(req.GetReason(), "update organization role"))
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) PutOrgRolePermissions(ctx context.Context, req *usercv1.PutOrgRolePermissionsRequest) (*usercv1.OrgRole, error) {
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
	role, err := s.iam.PutRoleGrants(ctx, requestMeta(ctx), orgID, roleID, grants, expected, reasonOr(req.GetReason(), "update organization role permissions"))
	if err != nil {
		return nil, err
	}
	return orgRoleProto(role), nil
}

func (s *OrganizationService) ArchiveOrgRole(ctx context.Context, req *usercv1.ArchiveOrgRoleRequest) (*emptypb.Empty, error) {
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
	if err := s.iam.ArchiveRole(ctx, requestMeta(ctx), orgID, roleID, expected, reasonOr(req.GetReason(), "archive organization role")); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) ListOrgAssignments(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.OrgAssignmentsReply, error) {
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.Assignments(ctx, requestMeta(ctx), orgID)
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
	assignment, err := s.iam.AssignRole(ctx, requestMeta(ctx), orgID, biz.OrgAssignmentInput{
		UserID: userID, RoleID: roleID, ExpiresAt: expires,
	}, reasonOr(req.GetReason(), "assign organization role"))
	if err != nil {
		return nil, err
	}
	item := &biz.AssignmentItem{Assignment: assignment}
	return orgAssignmentProto(item), nil
}

func (s *OrganizationService) RevokeOrgAssignment(ctx context.Context, req *usercv1.RevokeOrgAssignmentRequest) (*emptypb.Empty, error) {
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
	if err := s.iam.RevokeAssignment(ctx, requestMeta(ctx), orgID, assignmentID, expected, reasonOr(req.GetReason(), "revoke organization assignment")); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) ListOrgAudits(ctx context.Context, req *usercv1.ListOrgAuditsRequest) (*usercv1.OrgAuditsReply, error) {
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
	events, total, err := s.iam.Audits(ctx, requestMeta(ctx), orgID, req.GetAction(), from, to, int(req.GetOffset()), pageSize(req.GetPageSize()))
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
