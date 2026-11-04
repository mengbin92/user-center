package biz

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Organization IAM: every organization owns an isolated policy space. Roles,
// assignments and audit rows carry the organization context, and decisions for
// that tenant are evaluated only against grants issued in it.

var orgRoleCodePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,63}$`)

type orgRoleSpec struct {
	Code, Name, Description string
	Grants                  []Grant
}

func allowAll(operations ...string) []Grant {
	out := make([]Grant, 0, len(operations))
	for _, op := range operations {
		out = append(out, Grant{Operation: op, Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	}
	return out
}

var orgBuiltinRoleSpecs = []orgRoleSpec{
	{
		Code: OrgRoleCodeOwner, Name: "组织所有者",
		Description: "组织内最高权限，可管理成员、部门、角色、授权与审计",
		Grants: allowAll(
			PermOrgMemberRead, PermOrgMemberManage,
			PermOrgDepartmentRead, PermOrgDepartmentManage,
			PermOrgRoleRead, PermOrgRoleManage,
			PermOrgAssignmentRead, PermOrgAssignmentManage,
			PermOrgAuditRead, PermOrgSettingsUpdate, PermOrgArchive,
		),
	},
	{
		Code: OrgRoleCodeAdmin, Name: "组织管理员",
		Description: "管理成员与部门，可查看组织角色、授权与审计",
		Grants: allowAll(
			PermOrgMemberRead, PermOrgMemberManage,
			PermOrgDepartmentRead, PermOrgDepartmentManage,
			PermOrgRoleRead, PermOrgAssignmentRead, PermOrgAuditRead,
		),
	},
	{
		Code: OrgRoleCodeMember, Name: "组织成员",
		Description: "查看本组织成员与部门结构",
		Grants: allowAll(
			PermOrgMemberRead, PermOrgDepartmentRead,
		),
	},
}

// provisionOrgIAM materializes the built-in roles for a new organization. It
// runs inside the organization-create transaction and is idempotent.
func provisionOrgIAM(ctx context.Context, s *Services, tx Tx, orgID int64) error {
	authCtx := authorization.Organization(orgID)
	for _, spec := range orgBuiltinRoleSpecs {
		existing, err := s.OrgIAM.GetRoleByCode(ctx, tx, authCtx, spec.Code)
		if err != nil && !errors.Is(err, ErrResourceNotFound) {
			return err
		}
		var role *Role
		if existing != nil {
			role = existing
			// A concurrent or interrupted provisioning may have left the role
			// without grants; only an empty grant set is re-applied so manual
			// fixes are never overwritten.
			if len(existing.Grants) > 0 {
				continue
			}
		} else {
			role, err = s.OrgIAM.CreateRole(ctx, tx, authCtx, &Role{
				Code: spec.Code, Name: spec.Name, Description: spec.Description,
				Builtin: true, Status: RoleStatusActive,
			})
			if err != nil {
				if errors.Is(err, ErrOrgRoleExists) {
					continue
				}
				return err
			}
		}
		if _, err := s.OrgIAM.PutRoleGrants(ctx, tx, authCtx, role.ID, spec.Grants, role.Revision); err != nil {
			return err
		}
	}
	return nil
}

// syncOrgMembershipRole projects the membership role (owner/admin/member) onto
// the organization's built-in IAM role. Custom role assignments are preserved.
func syncOrgMembershipRole(ctx context.Context, s *Services, tx Tx, orgID, userID int64, membershipRole string, by int64) error {
	authCtx := authorization.Organization(orgID)
	roles, err := s.OrgIAM.ListRoles(ctx, tx, authCtx)
	if err != nil {
		return err
	}
	builtinIDs := make([]int64, 0, len(roles))
	var target *Role
	for _, role := range roles {
		if !role.Builtin {
			continue
		}
		builtinIDs = append(builtinIDs, role.ID)
		if role.Code == OrgRoleCode(membershipRole) {
			target = role
		}
	}
	if target == nil {
		return ErrDependency
	}
	items, err := s.OrgIAM.ListAssignments(ctx, tx, authCtx, userID)
	if err != nil {
		return err
	}
	hasTarget := false
	for _, item := range items {
		if item.Assignment == nil {
			continue
		}
		a := item.Assignment
		// Idempotent sync: an active assignment of the target role is kept, so
		// a repeated membership update does not churn the assignment history.
		if a.RoleID == target.ID && !a.Revoked {
			hasTarget = true
			continue
		}
		if slices.Contains(builtinIDs, a.RoleID) {
			if _, err := s.OrgIAM.RevokeMemberAssignments(ctx, tx, authCtx, userID, []int64{a.RoleID}, by); err != nil {
				return err
			}
		}
	}
	if hasTarget {
		return nil
	}
	_, err = s.OrgIAM.CreateAssignment(ctx, tx, authCtx, &Assignment{
		UserID: userID, RoleID: target.ID, Boundary: authorization.Scope{All: true},
		Origin: "organization_membership", AssignedBy: by,
	})
	return err
}

// revokeOrgMemberAssignments removes every organization-scoped grant a member
// holds, including custom roles.
func revokeOrgMemberAssignments(ctx context.Context, s *Services, tx Tx, orgID, userID, by int64) error {
	_, err := s.OrgIAM.RevokeMemberAssignments(ctx, tx, authorization.Organization(orgID), userID, nil, by)
	return err
}

// ensureOrganizationIAM upgrades organizations created before V2.3 (or by an
// import path that skipped provisioning): the built-in roles are materialized
// and every active membership receives its built-in assignment.
func (s *Services) ensureOrganizationIAM(ctx context.Context, orgID int64) error {
	authCtx := authorization.Organization(orgID)
	if _, err := s.OrgIAM.GetRoleByCode(ctx, nil, authCtx, OrgRoleCodeOwner); err == nil {
		return nil
	} else if !errors.Is(err, ErrResourceNotFound) {
		return ErrDependency
	}
	return s.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := provisionOrgIAM(ctx, s, tx, orgID); err != nil {
			return err
		}
		members, err := s.Organizations.ListMembers(ctx, tx, orgID)
		if err != nil {
			return err
		}
		for _, m := range members {
			if err := syncOrgMembershipRole(ctx, s, tx, orgID, m.UserID, m.Role, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

// BackfillOrganizationIAM prepares every existing organization after an
// upgrade. It is idempotent and safe to run on every migrate invocation.
func (s *Services) BackfillOrganizationIAM(ctx context.Context) error {
	orgs, err := s.Organizations.ListAllOrganizations(ctx, nil, "")
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := s.ensureOrganizationIAM(ctx, org.ID); err != nil {
			return err
		}
	}
	return nil
}

type OrgRoleInput struct {
	Code        string
	Name        string
	Description string
	Grants      []Grant
}

type OrgAssignmentInput struct {
	UserID    int64
	RoleID    int64
	ExpiresAt *time.Time
}

// orgGuard validates the tenant boundary and evaluates the operation in the
// organization context. Platform administrators keep an explicit override for
// support and governance. Cross-tenant identifiers fail closed as "not found".
func (uc *OrgIAMUsecase) orgGuard(ctx context.Context, actor ActorContext, orgID int64, operation string, targetUserID int64, wholeObject bool) (authorization.Context, error) {
	authCtx := authorization.Organization(orgID)
	if orgID <= 0 {
		return authCtx, ErrResourceNotFound
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil || org.Status != OrgStatusActive {
		return authCtx, ErrResourceNotFound
	}
	// Materialize built-in roles even for platform administrators: otherwise a
	// legacy organization that skipped backfill shows an empty role list.
	if err := uc.ensureOrganizationIAM(ctx, orgID); err != nil {
		return authCtx, err
	}
	if isPlatformAdmin(actor) {
		return authCtx, nil
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, actor.User.ID)
	if err != nil || member.Status != OrgMemberActive {
		return authCtx, ErrPermissionDenied
	}
	if _, err := uc.AuthorizeIn(ctx, actor, authCtx, operation, targetUserID, wholeObject); err != nil {
		return authCtx, err
	}
	return authCtx, nil
}

func (uc *OrgIAMUsecase) Roles(ctx context.Context, actor ActorContext, orgID int64) ([]*Role, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleRead, 0, true)
	if err != nil {
		return nil, err
	}
	roles, err := uc.OrgIAM.ListRoles(ctx, nil, authCtx)
	if err != nil {
		return nil, ErrDependency
	}
	return roles, nil
}

// Permissions lists the privileges that may be granted inside a tenant.
func (uc *OrgIAMUsecase) Permissions(ctx context.Context, actor ActorContext, orgID int64) ([]*Permission, error) {
	if _, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleRead, 0, true); err != nil {
		return nil, err
	}
	items, err := uc.IAM.ListPermissions(ctx, nil, PermissionFilter{Status: PermissionStatusActive})
	if err != nil {
		return nil, ErrDependency
	}
	out := make([]*Permission, 0, len(items))
	for _, p := range items {
		if slices.Contains(p.ContextTypes, authorization.ContextTypeOrganization) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (uc *OrgIAMUsecase) validateGrants(ctx context.Context, grants []Grant) error {
	seen := make(map[string]bool, len(grants))
	for _, g := range grants {
		if seen[g.Operation] {
			return Validation("同一权限不能重复授予：" + g.Operation)
		}
		seen[g.Operation] = true
		if g.Effect != authorization.Allow {
			return Validation("组织角色只支持授予权限，不支持拒绝策略")
		}
		if strings.TrimSpace(g.Operation) == "" {
			return Validation("权限操作不能为空")
		}
		p, err := uc.permission(ctx, g.Operation)
		if err != nil {
			return Validation("权限不存在：" + g.Operation)
		}
		if !slices.Contains(p.ContextTypes, authorization.ContextTypeOrganization) {
			return Validation("该权限不支持组织域：" + g.Operation)
		}
		if err := g.Scope.Validate(p.ScopeKinds()); err != nil {
			return Validation("权限数据范围不合法：" + g.Operation)
		}
	}
	return nil
}

func (uc *OrgIAMUsecase) CreateRole(ctx context.Context, actor ActorContext, orgID int64, in OrgRoleInput, reason string) (*Role, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleManage, 0, true)
	if err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	in.Code, in.Name = strings.ToLower(strings.TrimSpace(in.Code)), strings.TrimSpace(in.Name)
	if !orgRoleCodePattern.MatchString(in.Code) {
		return nil, Validation("角色 code 必须为 2-64 位小写字母、数字、点、下划线或短横线")
	}
	if strings.HasPrefix(in.Code, "org_") {
		return nil, Validation("org_ 前缀为内置角色保留")
	}
	if in.Name == "" || len([]rune(in.Name)) > 128 {
		return nil, Validation("角色名称必须为 1-128 个字符")
	}
	if err := uc.validateGrants(ctx, in.Grants); err != nil {
		return nil, err
	}
	if _, err := uc.OrgIAM.GetRoleByCode(ctx, nil, authCtx, in.Code); err == nil {
		return nil, ErrOrgRoleExists
	} else if !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	var created *Role
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		role, err := uc.OrgIAM.CreateRole(ctx, tx, authCtx, &Role{
			Code: in.Code, Name: in.Name, Description: strings.TrimSpace(in.Description),
			Status: RoleStatusActive, Grants: in.Grants,
		})
		if err != nil {
			return err
		}
		if len(in.Grants) > 0 {
			if _, err := uc.OrgIAM.PutRoleGrants(ctx, tx, authCtx, role.ID, in.Grants, role.Revision); err != nil {
				return err
			}
		}
		created = role
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.role.create", itoa(role.ID), reason)
	})
	if err != nil {
		return nil, err
	}
	return uc.OrgIAM.GetRole(ctx, nil, authCtx, created.ID)
}

func (uc *OrgIAMUsecase) UpdateRole(ctx context.Context, actor ActorContext, orgID, roleID int64, name, description string, expected uint64, reason string) (*Role, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleManage, 0, true)
	if err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	role, err := uc.OrgIAM.GetRole(ctx, nil, authCtx, roleID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if role.Builtin {
		return nil, Validation("内置组织角色不可修改")
	}
	if role.Status == RoleStatusArchived {
		return nil, Validation("已归档角色不可修改")
	}
	name, description = strings.TrimSpace(name), strings.TrimSpace(description)
	if name == "" || len([]rune(name)) > 128 {
		return nil, Validation("角色名称必须为 1-128 个字符")
	}
	role.Name, role.Description = name, description
	var updated *Role
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.OrgIAM.UpdateRole(ctx, tx, authCtx, role, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.role.update", itoa(roleID), reason)
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *OrgIAMUsecase) PutRoleGrants(ctx context.Context, actor ActorContext, orgID, roleID int64, grants []Grant, expected uint64, reason string) (*Role, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleManage, 0, true)
	if err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	role, err := uc.OrgIAM.GetRole(ctx, nil, authCtx, roleID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if role.Builtin {
		return nil, Validation("内置组织角色不可修改")
	}
	if role.Status == RoleStatusArchived {
		return nil, Validation("已归档角色不可修改")
	}
	if err := uc.validateGrants(ctx, grants); err != nil {
		return nil, err
	}
	var revision uint64
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		rev, err := uc.OrgIAM.PutRoleGrants(ctx, tx, authCtx, roleID, grants, expected)
		if err != nil {
			return err
		}
		revision = rev
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.role.permissions", itoa(roleID), reason)
	})
	if err != nil {
		return nil, err
	}
	updated, err := uc.OrgIAM.GetRole(ctx, nil, authCtx, roleID)
	if err != nil {
		return nil, ErrDependency
	}
	updated.Revision = revision
	return updated, nil
}

func (uc *OrgIAMUsecase) ArchiveRole(ctx context.Context, actor ActorContext, orgID, roleID int64, expected uint64, reason string) error {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleManage, 0, true)
	if err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	role, err := uc.OrgIAM.GetRole(ctx, nil, authCtx, roleID)
	if err != nil {
		return ErrResourceNotFound
	}
	if role.Builtin {
		return Validation("内置组织角色不可归档")
	}
	if n, err := uc.OrgIAM.CountActiveAssignments(ctx, nil, authCtx, roleID); err != nil {
		return ErrDependency
	} else if n > 0 {
		return ConflictCode("ORGANIZATION_ROLE_IN_USE", "角色仍被成员使用，请先撤销授权")
	}
	role.Status = RoleStatusArchived
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.OrgIAM.UpdateRole(ctx, tx, authCtx, role, expected); err != nil {
			return err
		}
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.role.archive", itoa(roleID), reason)
	})
}

func (uc *OrgIAMUsecase) Assignments(ctx context.Context, actor ActorContext, orgID int64) ([]*AssignmentItem, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgAssignmentRead, 0, true)
	if err != nil {
		return nil, err
	}
	items, err := uc.OrgIAM.ListAssignments(ctx, nil, authCtx, 0)
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *OrgIAMUsecase) AssignRole(ctx context.Context, actor ActorContext, orgID int64, in OrgAssignmentInput, reason string) (*Assignment, error) {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgAssignmentManage, in.UserID, false)
	if err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, in.UserID)
	if err != nil || member.Status != OrgMemberActive {
		return nil, Validation("目标用户不是本组织成员")
	}
	role, err := uc.OrgIAM.GetRole(ctx, nil, authCtx, in.RoleID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if role.Builtin {
		return nil, Validation("内置组织角色由成员角色决定，请通过成员管理调整")
	}
	if role.Status != RoleStatusActive {
		return nil, Validation("角色已停用")
	}
	if in.ExpiresAt != nil && !uc.Clock.Now().Before(*in.ExpiresAt) {
		return nil, Validation("授权过期时间必须晚于当前时间")
	}
	var created *Assignment
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		// Lock the role row: the duplicate and max_members checks below must not
		// run on a stale snapshot when two admins grant the same role at once.
		locked, err := uc.OrgIAM.GetRoleForUpdate(ctx, tx, authCtx, role.ID)
		if err != nil {
			return ErrResourceNotFound
		}
		if locked.Status != RoleStatusActive {
			return Validation("角色已停用")
		}
		existing, err := uc.OrgIAM.ListAssignments(ctx, tx, authCtx, in.UserID)
		if err != nil {
			return ErrDependency
		}
		for _, item := range existing {
			if item.Assignment != nil && item.Assignment.RoleID == locked.ID && !item.Assignment.Revoked {
				return ConflictCode("ORGANIZATION_ASSIGNMENT_EXISTS", "该成员已拥有此角色")
			}
		}
		if locked.MaxMembers != nil && *locked.MaxMembers > 0 {
			n, err := uc.OrgIAM.CountActiveAssignments(ctx, tx, authCtx, locked.ID)
			if err != nil {
				return ErrDependency
			}
			if n >= *locked.MaxMembers {
				return ConflictCode("ORGANIZATION_ROLE_FULL", "角色成员数已达上限")
			}
		}
		row, err := uc.OrgIAM.CreateAssignment(ctx, tx, authCtx, &Assignment{
			UserID: in.UserID, RoleID: role.ID, Boundary: authorization.Scope{All: true},
			ExpiresAt: in.ExpiresAt, Origin: OriginExplicit, AssignedBy: actor.User.ID,
			CreatedAt: uc.Clock.Now().UTC(),
		})
		if err != nil {
			return err
		}
		created = row
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.assignment.create", itoa(row.ID), reason)
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *OrgIAMUsecase) RevokeAssignment(ctx context.Context, actor ActorContext, orgID, assignmentID int64, expected uint64, reason string) error {
	authCtx, err := uc.orgGuard(ctx, actor, orgID, PermOrgAssignmentManage, 0, true)
	if err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	assignment, err := uc.OrgIAM.GetAssignment(ctx, nil, authCtx, assignmentID)
	if err != nil {
		return ErrResourceNotFound
	}
	roles, err := uc.OrgIAM.ListRoles(ctx, nil, authCtx)
	if err != nil {
		return ErrDependency
	}
	for _, role := range roles {
		if role.ID == assignment.RoleID && role.Builtin {
			return Validation("内置组织角色由成员角色决定，请通过成员管理调整")
		}
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.OrgIAM.RevokeAssignment(ctx, tx, authCtx, assignmentID, expected, actor.User.ID); err != nil {
			return err
		}
		return uc.auditOrg(ctx, tx, actor, orgID, "organization.iam.assignment.revoke", itoa(assignmentID), reason)
	})
}

func (uc *OrgIAMUsecase) Audits(ctx context.Context, actor ActorContext, orgID int64, action string, from, to *time.Time, offset, limit int) ([]*AuditEvent, int64, error) {
	if _, err := uc.orgGuard(ctx, actor, orgID, PermOrgAuditRead, 0, true); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	filter := AuditFilter{Action: action, From: from, To: to, OrganizationID: orgID, Offset: offset, Limit: limit}
	events, total, err := uc.Audit.List(ctx, nil, filter)
	if err != nil {
		return nil, 0, ErrDependency
	}
	return events, total, nil
}

// auditOrg writes a tenant-scoped audit event in the caller's transaction.
func (uc *OrgIAMUsecase) auditOrg(ctx context.Context, tx Tx, actor ActorContext, orgID int64, action, target, reason string) error {
	return uc.Audit.Append(ctx, tx, &AuditEvent{
		EventID: uc.IDs.NewID(), ActorUserID: actor.User.ID, ActorSessionID: actor.Session.ID,
		Action: action, Target: target, Reason: reason, Result: "success",
		RequestID: actor.RequestID, OccurredAt: uc.Clock.Now().UTC(), OrganizationID: orgID,
	})
}
