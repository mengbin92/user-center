package service

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

type IAMService struct {
	usercv1.UnimplementedIAMServiceServer
	iam *biz.IAMUsecase
}

func NewIAMService(iam *biz.IAMUsecase) *IAMService { return &IAMService{iam: iam} }

func (s *IAMService) ListResources(ctx context.Context, _ *usercv1.ListResourcesRequest) (*usercv1.ResourcesReply, error) {
	items, err := s.iam.Resources(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.ResourcesReply{}
	for _, r := range items {
		out.Items = append(out.Items, &usercv1.Resource{Id: id(r.ID), Code: r.Code, Name: r.Name, Owner: r.Owner, Enabled: r.Enabled})
	}
	return out, nil
}

func permissionProto(p *biz.Permission) *usercv1.Permission {
	return &usercv1.Permission{
		Id: id(p.ID), ResourceId: id(p.ResourceID), Code: p.Code, Name: p.Name,
		Category: p.Category, RiskLevel: p.RiskLevel, Status: p.Status,
		Binding: p.Binding, SupportedScopes: p.SupportedScopes, ContextTypes: p.ContextTypes,
		Protected: p.Protected, Description: p.Description, Sort: p.Sort, Revision: rev(p.Revision),
	}
}

func (s *IAMService) ListPermissions(ctx context.Context, req *usercv1.ListPermissionsRequest) (*usercv1.PermissionsReply, error) {
	items, err := s.iam.Permissions(ctx, requestMeta(ctx), biz.PermissionFilter{
		Category: req.GetCategory(), Status: req.GetStatus(), Keyword: req.GetKeyword(),
	})
	if err != nil {
		return nil, err
	}
	out := &usercv1.PermissionsReply{}
	for _, p := range items {
		out.Items = append(out.Items, permissionProto(p))
	}
	return out, nil
}

func (s *IAMService) GetPermission(ctx context.Context, req *usercv1.GetPermissionRequest) (*usercv1.Permission, error) {
	permID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	p, err := s.iam.Permission(ctx, requestMeta(ctx), permID)
	if err != nil {
		return nil, err
	}
	return permissionProto(p), nil
}

func (s *IAMService) CreatePermission(ctx context.Context, req *usercv1.CreatePermissionRequest) (*usercv1.Permission, error) {
	resourceID, err := parseIDField(req.GetResourceId(), "resource_id")
	if err != nil {
		return nil, err
	}
	p, err := s.iam.CreatePermission(ctx, requestMeta(ctx), &biz.Permission{
		ResourceID: resourceID, Code: req.GetCode(), Name: req.GetName(),
		Category: req.GetCategory(), RiskLevel: req.GetRiskLevel(),
		SupportedScopes: req.GetSupportedScopes(), ContextTypes: req.GetContextTypes(),
		Description: req.GetDescription(), Sort: req.GetSort(),
	}, reasonOr(req.GetReason(), "create permission"))
	if err != nil {
		return nil, err
	}
	return permissionProto(p), nil
}

func (s *IAMService) UpdatePermission(ctx context.Context, req *usercv1.UpdatePermissionRequest) (*usercv1.Permission, error) {
	permID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	p, err := s.iam.UpdatePermission(ctx, requestMeta(ctx), &biz.Permission{
		ID: permID, Name: req.GetName(), Category: req.GetCategory(),
		RiskLevel: req.GetRiskLevel(), SupportedScopes: req.GetSupportedScopes(),
		Description: req.GetDescription(), Sort: req.GetSort(),
	}, expected, reasonOr(req.GetReason(), "update permission"))
	if err != nil {
		return nil, err
	}
	return permissionProto(p), nil
}

func (s *IAMService) SetPermissionStatus(ctx context.Context, req *usercv1.SetPermissionStatusRequest) (*usercv1.Permission, error) {
	permID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	p, err := s.iam.SetPermissionStatus(ctx, requestMeta(ctx), permID, req.GetStatus(), expected, reasonOr(req.GetReason(), "permission status"))
	if err != nil {
		return nil, err
	}
	return permissionProto(p), nil
}

func (s *IAMService) ArchivePermission(ctx context.Context, req *usercv1.ArchivePermissionRequest) (*usercv1.Permission, error) {
	permID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	p, err := s.iam.ArchivePermission(ctx, requestMeta(ctx), permID, expected, reasonOr(req.GetReason(), "archive permission"))
	if err != nil {
		return nil, err
	}
	return permissionProto(p), nil
}

func (s *IAMService) GetPermissionReferences(ctx context.Context, req *usercv1.GetPermissionReferencesRequest) (*usercv1.ReferencesReply, error) {
	permID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	refs, err := s.iam.PermissionReferences(ctx, requestMeta(ctx), permID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.ReferencesReply{}
	for _, r := range refs {
		out.Items = append(out.Items, &usercv1.Reference{Kind: r.Kind, Id: id(r.ID), UserId: id(r.UserID)})
	}
	return out, nil
}

func (s *IAMService) ListRoles(ctx context.Context, req *usercv1.ListRolesRequest) (*usercv1.RolesReply, error) {
	items, err := s.iam.Roles(ctx, requestMeta(ctx), biz.RoleFilter{Status: req.GetStatus(), Keyword: req.GetKeyword()})
	if err != nil {
		return nil, err
	}
	out := &usercv1.RolesReply{}
	for _, r := range items {
		out.Items = append(out.Items, roleProto(r))
	}
	return out, nil
}

func (s *IAMService) GetRole(ctx context.Context, req *usercv1.GetRoleRequest) (*usercv1.Role, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	r, err := s.iam.Role(ctx, requestMeta(ctx), roleID)
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) CreateRole(ctx context.Context, req *usercv1.CreateRoleRequest) (*usercv1.Role, error) {
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	var inherits []int64
	for _, raw := range req.GetInherits() {
		roleID, err := parseIDField(raw, "inherits")
		if err != nil {
			return nil, err
		}
		inherits = append(inherits, roleID)
	}
	var maxMembers *int64
	if req.GetMaxMembers() > 0 {
		v := req.GetMaxMembers()
		maxMembers = &v
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	r, err := s.iam.CreateRole(ctx, requestMeta(ctx), &biz.Role{
		Code: req.GetCode(), Name: req.GetName(), Description: req.GetDescription(),
		Grants: grants, Inherits: inherits, MaxMembers: maxMembers,
	}, reasonOr(req.GetReason(), "create role"), policy)
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) UpdateRole(ctx context.Context, req *usercv1.UpdateRoleRequest) (*usercv1.Role, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	r, err := s.iam.UpdateRole(ctx, requestMeta(ctx), roleID, req.GetName(), req.GetDescription(), req.GetMaxMembers(), expected, reasonOr(req.GetReason(), "update role"))
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) CopyRole(ctx context.Context, req *usercv1.CopyRoleRequest) (*usercv1.Role, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	r, err := s.iam.CopyRole(ctx, requestMeta(ctx), roleID, req.GetCode(), req.GetName(), reasonOr(req.GetReason(), "copy role"))
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) SetRoleStatus(ctx context.Context, req *usercv1.SetRoleStatusRequest) (*usercv1.Role, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	r, err := s.iam.SetRoleStatus(ctx, requestMeta(ctx), roleID, req.GetStatus(), expected, reasonOr(req.GetReason(), "role status"))
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) ArchiveRole(ctx context.Context, req *usercv1.ArchiveRoleRequest) (*usercv1.Role, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	r, err := s.iam.ArchiveRole(ctx, requestMeta(ctx), roleID, expected, reasonOr(req.GetReason(), "archive role"))
	if err != nil {
		return nil, err
	}
	return roleProto(r), nil
}

func (s *IAMService) ListRoleMembers(ctx context.Context, req *usercv1.ListRoleMembersRequest) (*usercv1.RoleMembersReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	members, err := s.iam.RoleMembers(ctx, requestMeta(ctx), roleID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.RoleMembersReply{}
	for _, m := range members {
		out.Items = append(out.Items, &usercv1.RoleMember{
			UserId: id(m.UserID), Username: m.Username, DisplayName: m.DisplayName,
			AssignmentId: id(m.AssignmentID), AssignedAt: ts(m.AssignedAt),
			ExpiresAt: tptr(m.ExpiresAt), Origin: m.Origin,
		})
	}
	return out, nil
}

func (s *IAMService) GetRolePermissions(ctx context.Context, req *usercv1.GetRolePermissionsRequest) (*usercv1.RolePermissionsReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, revision, err := s.iam.RolePermissions(ctx, requestMeta(ctx), roleID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.RolePermissionsReply{Revision: rev(revision)}
	for _, g := range grants {
		out.Grants = append(out.Grants, grantProto(g))
	}
	return out, nil
}

func (s *IAMService) PutRolePermissions(ctx context.Context, req *usercv1.PutRolePermissionsRequest) (*usercv1.RolePermissionsReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	saved, revision, err := s.iam.PutRolePermissions(ctx, requestMeta(ctx), roleID, grants, expected, policy, reasonOr(req.GetReason(), "update role permissions"))
	if err != nil {
		return nil, err
	}
	out := &usercv1.RolePermissionsReply{Revision: rev(revision)}
	for _, g := range saved {
		out.Grants = append(out.Grants, grantProto(g))
	}
	return out, nil
}

func (s *IAMService) GetRoleInheritance(ctx context.Context, req *usercv1.GetRoleInheritanceRequest) (*usercv1.RoleInheritanceReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	inherits, revision, err := s.iam.RoleInheritance(ctx, requestMeta(ctx), roleID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.RoleInheritanceReply{Revision: rev(revision)}
	for _, in := range inherits {
		out.Inherits = append(out.Inherits, id(in))
	}
	return out, nil
}

func (s *IAMService) PutRoleInheritance(ctx context.Context, req *usercv1.PutRoleInheritanceRequest) (*usercv1.RoleInheritanceReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	var inherits []int64
	for _, raw := range req.GetInherits() {
		in, err := parseIDField(raw, "inherits")
		if err != nil {
			return nil, err
		}
		inherits = append(inherits, in)
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	saved, revision, err := s.iam.PutRoleInheritance(ctx, requestMeta(ctx), roleID, inherits, expected, policy, reasonOr(req.GetReason(), "update role inheritance"))
	if err != nil {
		return nil, err
	}
	out := &usercv1.RoleInheritanceReply{Revision: rev(revision)}
	for _, in := range saved {
		out.Inherits = append(out.Inherits, id(in))
	}
	return out, nil
}

func (s *IAMService) PreviewRoleChange(ctx context.Context, req *usercv1.PreviewRoleChangeRequest) (*usercv1.PreviewReply, error) {
	roleID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, err := grantsBiz(req.GetGrants())
	if err != nil {
		return nil, err
	}
	var inherits []int64
	for _, raw := range req.GetInherits() {
		in, err := parseIDField(raw, "inherits")
		if err != nil {
			return nil, err
		}
		inherits = append(inherits, in)
	}
	preview, err := s.iam.PreviewRoleChange(ctx, requestMeta(ctx), roleID, grants, inherits)
	if err != nil {
		return nil, err
	}
	return &usercv1.PreviewReply{
		Warnings: preview.Warnings, PermissionDiffAdded: preview.Added,
		PermissionDiffRemoved: preview.Removed, AffectedUserCount: preview.AffectedUserCount,
	}, nil
}

func assignmentProto(a *biz.Assignment) *usercv1.Assignment {
	return &usercv1.Assignment{
		Id: id(a.ID), UserId: id(a.UserID), RoleId: id(a.RoleID),
		Boundary: scopeProto(a.Boundary), StartsAt: ts(a.StartsAt), ExpiresAt: tptr(a.ExpiresAt),
		Revoked: a.Revoked, Origin: a.Origin, Revision: rev(a.Revision), AssignedBy: id(a.AssignedBy),
	}
}

func (s *IAMService) ListUserRoles(ctx context.Context, req *usercv1.ListUserRolesRequest) (*usercv1.AssignmentsReply, error) {
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.UserAssignments(ctx, requestMeta(ctx), userID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.AssignmentsReply{}
	for _, a := range items {
		out.Items = append(out.Items, assignmentProto(a))
	}
	return out, nil
}

func (s *IAMService) ListAssignments(ctx context.Context, req *usercv1.ListAssignmentsRequest) (*usercv1.AssignmentListReply, error) {
	offset, err := biz.DecodePageToken(req.GetPageToken(), bizFingerprint(req.GetUserId(), req.GetRoleId(), req.GetStatus()))
	if err != nil {
		return nil, err
	}
	var userID, roleID int64
	if req.GetUserId() != "" {
		userID, err = parseIDField(req.GetUserId(), "user_id")
		if err != nil {
			return nil, err
		}
	}
	if req.GetRoleId() != "" {
		roleID, err = parseIDField(req.GetRoleId(), "role_id")
		if err != nil {
			return nil, err
		}
	}
	limit := pageSize(req.GetPageSize())
	items, total, err := s.iam.Assignments(ctx, requestMeta(ctx), biz.AssignmentFilter{
		UserID: userID, RoleID: roleID, Status: req.GetStatus(), Offset: offset, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := &usercv1.AssignmentListReply{Meta: &usercv1.ListMeta{TotalSize: rev(uint64(total))}}
	for _, item := range items {
		a := item.Assignment
		out.Items = append(out.Items, &usercv1.AssignmentItem{
			Id: id(a.ID), UserId: id(a.UserID), Username: item.Username, DisplayName: item.DisplayName,
			RoleId: id(a.RoleID), RoleCode: item.RoleCode, RoleName: item.RoleName,
			Boundary: scopeProto(a.Boundary), StartsAt: ts(a.StartsAt), ExpiresAt: tptr(a.ExpiresAt),
			Revoked: a.Revoked, Origin: a.Origin, Revision: rev(a.Revision),
		})
	}
	if offset+len(items) < int(total) {
		out.Meta.NextPageToken = biz.EncodePageToken(offset+len(items), bizFingerprint(req.GetUserId(), req.GetRoleId(), req.GetStatus()))
	}
	return out, nil
}

func (s *IAMService) CreateAssignment(ctx context.Context, req *usercv1.CreateAssignmentRequest) (*usercv1.Assignment, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	boundary, err := scopeBiz(req.GetBoundary())
	if err != nil {
		return nil, err
	}
	starts, err := biz.ParseTime(req.GetStartsAt(), "starts_at")
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	a, err := s.iam.CreateAssignment(ctx, requestMeta(ctx), &biz.Assignment{
		UserID: userID, RoleID: roleID, Boundary: boundary, StartsAt: starts, ExpiresAt: expPtr,
	}, reasonOr(req.GetReason(), "grant role"), policy)
	if err != nil {
		return nil, err
	}
	return assignmentProto(a), nil
}

func (s *IAMService) RevokeAssignment(ctx context.Context, req *usercv1.RevokeAssignmentRequest) (*usercv1.Assignment, error) {
	assignmentID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	a, err := s.iam.RevokeAssignment(ctx, requestMeta(ctx), assignmentID, reasonOr(req.GetReason(), "revoke role"), policy)
	if err != nil {
		return nil, err
	}
	return assignmentProto(a), nil
}

func (s *IAMService) PreviewBatchAssign(ctx context.Context, req *usercv1.PreviewBatchAssignRequest) (*usercv1.BatchPreviewReply, error) {
	userIDs, err := parseIDs(req.GetUserIds(), "user_id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	boundary, err := scopeBiz(req.GetBoundary())
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	preview, err := s.iam.PreviewBatch(ctx, requestMeta(ctx), userIDs, roleID, boundary, expPtr)
	if err != nil {
		return nil, err
	}
	out := &usercv1.BatchPreviewReply{}
	for _, uid := range preview.Eligible {
		out.EligibleUserIds = append(out.EligibleUserIds, id(uid))
	}
	for _, f := range preview.Failures {
		out.Failures = append(out.Failures, &usercv1.BatchFailure{UserId: id(f.UserID), Reason: f.Reason})
	}
	return out, nil
}

func (s *IAMService) BatchAssign(ctx context.Context, req *usercv1.BatchAssignRequest) (*usercv1.BatchAssignReply, error) {
	userIDs, err := parseIDs(req.GetUserIds(), "user_id")
	if err != nil {
		return nil, err
	}
	roleID, err := parseIDField(req.GetRoleId(), "role_id")
	if err != nil {
		return nil, err
	}
	boundary, err := scopeBiz(req.GetBoundary())
	if err != nil {
		return nil, err
	}
	starts, err := biz.ParseTime(req.GetStartsAt(), "starts_at")
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	assignments, err := s.iam.BatchAssign(ctx, requestMeta(ctx), userIDs, roleID, boundary, starts, expPtr, reasonOr(req.GetReason(), "batch grant role"), policy)
	if err != nil {
		return nil, err
	}
	out := &usercv1.BatchAssignReply{}
	for _, a := range assignments {
		out.Assignments = append(out.Assignments, assignmentProto(a))
	}
	return out, nil
}

func (s *IAMService) ListConstraints(ctx context.Context, _ *usercv1.ListConstraintsRequest) (*usercv1.ConstraintsReply, error) {
	items, err := s.iam.Constraints(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.ConstraintsReply{}
	for _, c := range items {
		out.Items = append(out.Items, constraintProto(c))
	}
	return out, nil
}

func constraintProto(c *biz.Constraint) *usercv1.Constraint {
	out := &usercv1.Constraint{
		Id: id(c.ID), Kind: c.Kind, Name: c.Name, MaxCount: c.MaxCount,
		Enabled: c.Enabled, Revision: rev(c.Revision),
	}
	for _, rid := range c.RoleIDs {
		out.RoleIds = append(out.RoleIds, id(rid))
	}
	return out
}

func (s *IAMService) CreateConstraint(ctx context.Context, req *usercv1.CreateConstraintRequest) (*usercv1.Constraint, error) {
	roleIDs, err := parseIDs(req.GetRoleIds(), "role_id")
	if err != nil {
		return nil, err
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	c, err := s.iam.CreateConstraint(ctx, requestMeta(ctx), &biz.Constraint{
		Kind: req.GetKind(), Name: req.GetName(), RoleIDs: roleIDs,
		MaxCount: req.GetMaxCount(), Enabled: true,
	}, reasonOr(req.GetReason(), "create constraint"), policy)
	if err != nil {
		return nil, err
	}
	return constraintProto(c), nil
}

func (s *IAMService) UpdateConstraint(ctx context.Context, req *usercv1.UpdateConstraintRequest) (*usercv1.Constraint, error) {
	constraintID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roleIDs, err := parseIDs(req.GetRoleIds(), "role_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	c, err := s.iam.UpdateConstraint(ctx, requestMeta(ctx), &biz.Constraint{
		ID: constraintID, Name: req.GetName(), RoleIDs: roleIDs,
		MaxCount: req.GetMaxCount(), Enabled: req.GetEnabled(),
	}, expected, reasonOr(req.GetReason(), "update constraint"))
	if err != nil {
		return nil, err
	}
	return constraintProto(c), nil
}

func (s *IAMService) DeleteConstraint(ctx context.Context, req *usercv1.DeleteConstraintRequest) (*emptypb.Empty, error) {
	constraintID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	if err := s.iam.DeleteConstraint(ctx, requestMeta(ctx), constraintID, expected, reasonOr(req.GetReason(), "delete constraint")); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *IAMService) ListMenus(ctx context.Context, _ *usercv1.ListMenusRequest) (*usercv1.MenusReply, error) {
	items, err := s.iam.Menus(ctx, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	out := &usercv1.MenusReply{}
	for _, m := range items {
		out.Items = append(out.Items, menuProto(m))
	}
	return out, nil
}

func menuProto(m *biz.MenuItem) *usercv1.MenuItem {
	return &usercv1.MenuItem{
		Id: id(m.ID), ParentId: id(m.ParentID), RouteKey: m.RouteKey, Name: m.Name,
		IconKey: m.IconKey, Sort: m.Sort, Enabled: m.Enabled,
		RequiredAll: m.RequiredAll, RequiredAny: m.RequiredAny, Revision: rev(m.Revision),
	}
}

func (s *IAMService) CreateMenuItem(ctx context.Context, req *usercv1.CreateMenuItemRequest) (*usercv1.MenuItem, error) {
	var parentID int64
	var err error
	if req.GetParentId() != "" {
		parentID, err = parseIDField(req.GetParentId(), "parent_id")
		if err != nil {
			return nil, err
		}
	}
	m, err := s.iam.CreateMenu(ctx, requestMeta(ctx), &biz.MenuItem{
		ParentID: parentID, RouteKey: req.GetRouteKey(), Name: req.GetName(),
		IconKey: req.GetIconKey(), Sort: req.GetSort(),
		RequiredAll: req.GetRequiredAll(), RequiredAny: req.GetRequiredAny(),
	}, reasonOr(req.GetReason(), "create menu"))
	if err != nil {
		return nil, err
	}
	return menuProto(m), nil
}

func (s *IAMService) UpdateMenuItem(ctx context.Context, req *usercv1.UpdateMenuItemRequest) (*usercv1.MenuItem, error) {
	menuID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	m, err := s.iam.UpdateMenu(ctx, requestMeta(ctx), &biz.MenuItem{
		ID: menuID, Name: req.GetName(), IconKey: req.GetIconKey(), Sort: req.GetSort(),
		Enabled: req.GetEnabled(), RequiredAll: req.GetRequiredAll(), RequiredAny: req.GetRequiredAny(),
	}, expected, reasonOr(req.GetReason(), "update menu"))
	if err != nil {
		return nil, err
	}
	return menuProto(m), nil
}

func (s *IAMService) ArchiveMenuItem(ctx context.Context, req *usercv1.ArchiveMenuItemRequest) (*usercv1.MenuItem, error) {
	menuID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	m, err := s.iam.ArchiveMenu(ctx, requestMeta(ctx), menuID, expected, reasonOr(req.GetReason(), "archive menu"))
	if err != nil {
		return nil, err
	}
	return menuProto(m), nil
}

func (s *IAMService) ExplainAuthorization(ctx context.Context, req *usercv1.ExplainAuthorizationRequest) (*usercv1.ExplainAuthorizationReply, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	result, err := s.iam.Explain(ctx, requestMeta(ctx), userID, req.GetOperation(), req.GetResourceId(), req.GetOwnerUserId())
	if err != nil {
		return nil, err
	}
	out := &usercv1.ExplainAuthorizationReply{
		Allowed: result.Allowed, Reason: result.Reason,
		PolicyRevision: rev(result.PolicyRevision), UserRevision: rev(result.UserRevision),
		ValidUntil: tptr(result.ValidUntil),
	}
	for _, src := range result.Sources {
		out.Sources = append(out.Sources, grantSourceProto(src))
	}
	return out, nil
}

func grantSourceProto(src authorization.GrantSource) *usercv1.GrantSource {
	out := &usercv1.GrantSource{
		RoleId: id(src.RoleID), RoleCode: src.RoleCode, Operation: src.Operation,
		Effect: string(src.Effect), Scope: scopeProto(IntersectScope(src)),
		AssignmentId: id(src.AssignmentID), Active: src.Active,
	}
	for _, p := range src.Inheritance {
		out.InheritancePath = append(out.InheritancePath, id(p))
	}
	if src.Validity.ExpiresAt != nil {
		out.ExpiresAt = ts(*src.Validity.ExpiresAt)
	}
	return out
}

func IntersectScope(src authorization.GrantSource) authorization.Scope {
	return authorization.Intersect(src.RoleScope, src.Boundary)
}

func (s *IAMService) SimulateAuthorization(ctx context.Context, req *usercv1.SimulateAuthorizationRequest) (*usercv1.SimulateAuthorizationReply, error) {
	userID, err := parseIDField(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	add, err := parseIDs(req.GetAddRoleIds(), "add_role_id")
	if err != nil {
		return nil, err
	}
	remove, err := parseIDs(req.GetRemoveRoleIds(), "remove_role_id")
	if err != nil {
		return nil, err
	}
	result, err := s.iam.Simulate(ctx, requestMeta(ctx), userID, add, remove, req.GetOperation(), req.GetOwnerUserId())
	if err != nil {
		return nil, err
	}
	return &usercv1.SimulateAuthorizationReply{
		BeforeAllowed: result.BeforeAllowed, AfterAllowed: result.AfterAllowed,
		BeforeReason: result.BeforeReason, AfterReason: result.AfterReason,
		AddedPermissions: result.Added, RemovedPermissions: result.Removed,
	}, nil
}

func parseIDs(raw []string, field string) ([]int64, error) {
	out := make([]int64, 0, len(raw))
	for _, s := range raw {
		id, err := parseIDField(s, field)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func delegationProto(d *biz.Delegation) *usercv1.Delegation {
	out := &usercv1.Delegation{
		Id: id(d.ID), ManagerRoleId: id(d.ManagerRoleID), TargetRoleId: id(d.TargetRoleID),
		TargetKind: d.TargetKind, Actions: d.Actions, TargetUserScope: scopeProto(d.TargetUserScope),
		CanRedelegate: d.CanRedelegate, StartsAt: ts(d.StartsAt), ExpiresAt: tptr(d.ExpiresAt),
		Revision: rev(d.Revision), CreatedBy: id(d.CreatedBy),
		Revoked: d.RevokedAt != nil, RevokedAt: tptr(d.RevokedAt),
	}
	for _, c := range d.GrantCeiling {
		out.GrantCeiling = append(out.GrantCeiling, &usercv1.DelegationCeiling{Operation: c.Operation, Scope: scopeProto(c.Scope)})
	}
	return out
}

func (s *IAMService) ListDelegations(ctx context.Context, req *usercv1.ListDelegationsRequest) (*usercv1.DelegationsReply, error) {
	filter := biz.DelegationFilter{Status: req.GetStatus()}
	var err error
	if req.GetManagerRoleId() != "" {
		filter.ManagerRoleID, err = parseIDField(req.GetManagerRoleId(), "manager_role_id")
		if err != nil {
			return nil, err
		}
	}
	if req.GetTargetRoleId() != "" {
		filter.TargetRoleID, err = parseIDField(req.GetTargetRoleId(), "target_role_id")
		if err != nil {
			return nil, err
		}
	}
	items, err := s.iam.Delegations(ctx, requestMeta(ctx), filter)
	if err != nil {
		return nil, err
	}
	out := &usercv1.DelegationsReply{}
	for _, d := range items {
		out.Items = append(out.Items, delegationProto(d))
	}
	return out, nil
}

func (s *IAMService) CreateDelegation(ctx context.Context, req *usercv1.CreateDelegationRequest) (*usercv1.Delegation, error) {
	managerID, err := parseIDField(req.GetManagerRoleId(), "manager_role_id")
	if err != nil {
		return nil, err
	}
	targetID, err := parseIDField(req.GetTargetRoleId(), "target_role_id")
	if err != nil {
		return nil, err
	}
	scope, err := scopeBiz(req.GetTargetUserScope())
	if err != nil {
		return nil, err
	}
	starts, err := biz.ParseTime(req.GetStartsAt(), "starts_at")
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	var ceiling []biz.DelegationCeiling
	for _, c := range req.GetGrantCeiling() {
		cs, err := scopeBiz(c.GetScope())
		if err != nil {
			return nil, err
		}
		ceiling = append(ceiling, biz.DelegationCeiling{Operation: c.GetOperation(), Scope: cs})
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	d, err := s.iam.CreateDelegation(ctx, requestMeta(ctx), &biz.Delegation{
		ManagerRoleID: managerID, TargetRoleID: targetID, TargetKind: req.GetTargetKind(),
		Actions: req.GetActions(), TargetUserScope: scope, GrantCeiling: ceiling,
		CanRedelegate: req.GetCanRedelegate(), StartsAt: starts, ExpiresAt: expPtr,
	}, reasonOr(req.GetReason(), "create delegation"), policy)
	if err != nil {
		return nil, err
	}
	return delegationProto(d), nil
}

func (s *IAMService) UpdateDelegation(ctx context.Context, req *usercv1.UpdateDelegationRequest) (*usercv1.Delegation, error) {
	delegationID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	existing, err := s.iam.Delegation(ctx, requestMeta(ctx), delegationID)
	if err != nil {
		return nil, err
	}
	scope, err := scopeBiz(req.GetTargetUserScope())
	if err != nil {
		return nil, err
	}
	starts, err := biz.ParseTime(req.GetStartsAt(), "starts_at")
	if err != nil {
		return nil, err
	}
	expires, err := biz.ParseTime(req.GetExpiresAt(), "expires_at")
	if err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	var ceiling []biz.DelegationCeiling
	for _, c := range req.GetGrantCeiling() {
		cs, err := scopeBiz(c.GetScope())
		if err != nil {
			return nil, err
		}
		ceiling = append(ceiling, biz.DelegationCeiling{Operation: c.GetOperation(), Scope: cs})
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	existing.Actions = req.GetActions()
	existing.TargetUserScope = scope
	existing.GrantCeiling = ceiling
	existing.CanRedelegate = req.GetCanRedelegate()
	if starts.IsZero() {
		starts = existing.StartsAt
	}
	existing.StartsAt = starts
	existing.ExpiresAt = expPtr
	d, err := s.iam.UpdateDelegation(ctx, requestMeta(ctx), existing, expected, reasonOr(req.GetReason(), "update delegation"))
	if err != nil {
		return nil, err
	}
	return delegationProto(d), nil
}

func (s *IAMService) RevokeDelegation(ctx context.Context, req *usercv1.RevokeDelegationRequest) (*usercv1.Delegation, error) {
	delegationID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	d, err := s.iam.RevokeDelegation(ctx, requestMeta(ctx), delegationID, expected, reasonOr(req.GetReason(), "revoke delegation"))
	if err != nil {
		return nil, err
	}
	return delegationProto(d), nil
}
