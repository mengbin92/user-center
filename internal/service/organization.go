package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/platform/httpx"
)

type OrganizationService struct {
	usercv1.UnimplementedOrganizationServiceServer
	uc  *biz.OrganizationUsecase
	iam *biz.OrgIAMUsecase
}

func NewOrganizationService(uc *biz.OrganizationUsecase, iam *biz.OrgIAMUsecase) *OrganizationService {
	return &OrganizationService{uc: uc, iam: iam}
}

// requireActorMeta keeps the audit/request metadata that requestMeta attaches
// while still failing closed for unauthenticated callers.
func requireActorMeta(ctx context.Context) (biz.ActorContext, error) {
	actor, err := requireActor(ctx)
	if err != nil {
		return actor, err
	}
	info := httpx.From(ctx)
	actor.RequestID = info.RequestID
	actor.IP = info.IP
	actor.UserAgent = info.UserAgent
	return actor, nil
}

func organizationProto(o *biz.Organization) *usercv1.Organization {
	return &usercv1.Organization{
		Id: id(o.ID), Code: o.Code, Name: o.Name, Status: o.Status, Role: o.Role,
		MemberCount: o.MemberCount, Revision: rev(o.Revision),
		CreatedAt: ts(o.CreatedAt), UpdatedAt: ts(o.UpdatedAt),
	}
}

func organizationMemberProto(m *biz.OrganizationMember) *usercv1.OrganizationMember {
	out := &usercv1.OrganizationMember{
		Id: id(m.ID), OrganizationId: id(m.OrganizationID), UserId: id(m.UserID),
		Username: m.Username, DisplayName: m.DisplayName, Email: m.Email,
		Role: m.Role, Status: m.Status, Revision: rev(m.Revision), JoinedAt: ts(m.JoinedAt),
	}
	if m.DepartmentID != nil {
		out.DepartmentId = id(*m.DepartmentID)
	}
	return out
}

func departmentProto(d *biz.Department) *usercv1.Department {
	return &usercv1.Department{
		Id: id(d.ID), OrganizationId: id(d.OrganizationID), ParentId: id(d.ParentID),
		Code: d.Code, Name: d.Name, Status: d.Status, Revision: rev(d.Revision),
	}
}

func (s *OrganizationService) ListMyOrganizations(ctx context.Context, _ *usercv1.ListMyOrganizationsRequest) (*usercv1.OrganizationsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.uc.ListMine(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrganizationsReply{}
	for _, org := range items {
		out.Items = append(out.Items, organizationProto(org))
	}
	return out, nil
}

func (s *OrganizationService) CreateOrganization(ctx context.Context, req *usercv1.CreateOrganizationRequest) (*usercv1.Organization, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	org, err := s.uc.Create(ctx, actor, biz.OrganizationInput{Code: req.GetCode(), Name: req.GetName()})
	if err != nil {
		return nil, err
	}
	return organizationProto(org), nil
}

func (s *OrganizationService) GetOrganization(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.Organization, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	org, err := s.uc.Get(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	return organizationProto(org), nil
}

func (s *OrganizationService) UpdateOrganization(ctx context.Context, req *usercv1.UpdateOrganizationRequest) (*usercv1.Organization, error) {
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
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	org, err := s.uc.Update(ctx, actor, orgID, req.GetName(), expected, auditReason)
	if err != nil {
		return nil, err
	}
	return organizationProto(org), nil
}

func (s *OrganizationService) ArchiveOrganization(ctx context.Context, req *usercv1.ArchiveOrganizationRequest) (*usercv1.Organization, error) {
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
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	org, err := s.uc.Archive(ctx, actor, orgID, expected, auditReason)
	if err != nil {
		return nil, err
	}
	return organizationProto(org), nil
}

func (s *OrganizationService) ListOrganizationMembers(ctx context.Context, req *usercv1.ListOrganizationMembersRequest) (*usercv1.OrganizationMembersReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.uc.Members(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrganizationMembersReply{}
	for _, m := range items {
		out.Items = append(out.Items, organizationMemberProto(m))
	}
	return out, nil
}

func (s *OrganizationService) AddOrganizationMember(ctx context.Context, req *usercv1.AddOrganizationMemberRequest) (*usercv1.OrganizationMember, error) {
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
	var deptID *int64
	if req.GetDepartmentId() != "" {
		v, err := parseIDField(req.GetDepartmentId(), "department_id")
		if err != nil {
			return nil, err
		}
		deptID = &v
	}
	m, err := s.uc.AddMember(ctx, actor, orgID, biz.MemberInput{
		Identifier: req.GetIdentifier(), Role: req.GetRole(), DepartmentID: deptID,
	}, auditReason)
	if err != nil {
		return nil, err
	}
	return organizationMemberProto(m), nil
}

func (s *OrganizationService) UpdateOrganizationMember(ctx context.Context, req *usercv1.UpdateOrganizationMemberRequest) (*usercv1.OrganizationMember, error) {
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
	var deptID *int64
	if req.GetDepartmentId() != "" {
		v, err := parseIDField(req.GetDepartmentId(), "department_id")
		if err != nil {
			return nil, err
		}
		deptID = &v
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	m, err := s.uc.UpdateMember(ctx, actor, orgID, userID, req.GetRole(), deptID, expected, auditReason)
	if err != nil {
		return nil, err
	}
	return organizationMemberProto(m), nil
}

func (s *OrganizationService) RemoveOrganizationMember(ctx context.Context, req *usercv1.RemoveOrganizationMemberRequest) (*emptypb.Empty, error) {
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
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.uc.RemoveMember(ctx, actor, orgID, userID, expected, auditReason); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) LeaveOrganization(ctx context.Context, req *usercv1.LeaveOrganizationRequest) (*emptypb.Empty, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	if err := s.uc.Leave(ctx, actor, orgID); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *OrganizationService) ListDepartments(ctx context.Context, req *usercv1.ListDepartmentsRequest) (*usercv1.DepartmentsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.uc.Departments(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.DepartmentsReply{}
	for _, d := range items {
		out.Items = append(out.Items, departmentProto(d))
	}
	return out, nil
}

func (s *OrganizationService) CreateDepartment(ctx context.Context, req *usercv1.CreateDepartmentRequest) (*usercv1.Department, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	var parentID int64
	if req.GetParentId() != "" {
		parentID, err = parseIDField(req.GetParentId(), "parent_id")
		if err != nil {
			return nil, err
		}
	}
	d, err := s.uc.CreateDepartment(ctx, actor, orgID, biz.DepartmentInput{
		ParentID: parentID, Code: req.GetCode(), Name: req.GetName(),
	})
	if err != nil {
		return nil, err
	}
	return departmentProto(d), nil
}

func (s *OrganizationService) UpdateDepartment(ctx context.Context, req *usercv1.UpdateDepartmentRequest) (*usercv1.Department, error) {
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
	deptID, err := parseIDField(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, err
	}
	var parentID int64
	if req.GetParentId() != "" {
		parentID, err = parseIDField(req.GetParentId(), "parent_id")
		if err != nil {
			return nil, err
		}
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	d, err := s.uc.UpdateDepartment(ctx, actor, orgID, deptID, biz.DepartmentInput{
		ParentID: parentID, Code: req.GetCode(), Name: req.GetName(),
	}, expected, auditReason)
	if err != nil {
		return nil, err
	}
	return departmentProto(d), nil
}

func (s *OrganizationService) ArchiveDepartment(ctx context.Context, req *usercv1.ArchiveDepartmentRequest) (*usercv1.Department, error) {
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
	deptID, err := parseIDField(req.GetDepartmentId(), "department_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.uc.ArchiveDepartment(ctx, actor, orgID, deptID, expected, auditReason); err != nil {
		return nil, err
	}
	return &usercv1.Department{Id: id(deptID), OrganizationId: id(orgID), Status: "archived", Revision: rev(expected + 1)}, nil
}

func (s *OrganizationService) AdminListOrganizations(ctx context.Context, req *usercv1.AdminListOrganizationsRequest) (*usercv1.OrganizationsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.uc.AdminList(ctx, actor, req.GetStatus())
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrganizationsReply{}
	for _, org := range items {
		out.Items = append(out.Items, organizationProto(org))
	}
	return out, nil
}

func (s *OrganizationService) AdminArchiveOrganization(ctx context.Context, req *usercv1.AdminArchiveOrganizationRequest) (*usercv1.Organization, error) {
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
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	org, err := s.uc.AdminArchive(ctx, actor, orgID, expected, auditReason)
	if err != nil {
		return nil, err
	}
	return organizationProto(org), nil
}
