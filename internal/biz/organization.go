package biz

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

var orgCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

type OrganizationInput struct {
	Code string
	Name string
}

type MemberInput struct {
	Identifier   string
	Role         string
	DepartmentID *int64
}

type DepartmentInput struct {
	ParentID int64
	Code     string
	Name     string
}

func isPlatformAdmin(actor ActorContext) bool {
	for _, r := range actor.User.Roles {
		if r.Code == "root" || r.Code == "admin" {
			return true
		}
	}
	return false
}

func validateOrgInput(in OrganizationInput) error {
	in.Code = strings.ToLower(strings.TrimSpace(in.Code))
	if !orgCodePattern.MatchString(in.Code) {
		return Validation("组织 code 必须为 2-64 位小写字母、数字或短横线")
	}
	if strings.TrimSpace(in.Name) == "" || len([]rune(in.Name)) > 128 {
		return Validation("组织名称必须为 1-128 个字符")
	}
	return nil
}

func validOrgRole(role string) bool {
	return role == OrgRoleOwner || role == OrgRoleAdmin || role == OrgRoleMember
}

// orgAccess returns the organization and the actor's effective role. Platform
// administrators receive role "platform" and can inspect any active org.
func (uc *OrganizationUsecase) orgAccess(ctx context.Context, actor ActorContext, orgID int64) (*Organization, string, error) {
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil {
		return nil, "", ErrResourceNotFound
	}
	if isPlatformAdmin(actor) {
		if org.Status != OrgStatusActive {
			return nil, "", ErrResourceNotFound
		}
		return org, "platform", nil
	}
	if org.Status != OrgStatusActive {
		return nil, "", ErrResourceNotFound
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, actor.User.ID)
	if err != nil || member.Status != OrgMemberActive {
		return nil, "", ErrPermissionDenied
	}
	return org, member.Role, nil
}

func requireOrgManager(role string) error {
	if role == "platform" || role == OrgRoleOwner || role == OrgRoleAdmin {
		return nil
	}
	return ErrPermissionDenied
}

func requireOrgOwner(role string) error {
	if role == "platform" || role == OrgRoleOwner {
		return nil
	}
	return ErrPermissionDenied
}

func (uc *OrganizationUsecase) ListMine(ctx context.Context, actor ActorContext) ([]*Organization, error) {
	orgs, err := uc.Organizations.ListOrganizationsForUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	return orgs, nil
}

func (uc *OrganizationUsecase) Create(ctx context.Context, actor ActorContext, in OrganizationInput) (*Organization, error) {
	in.Code, in.Name = strings.ToLower(strings.TrimSpace(in.Code)), strings.TrimSpace(in.Name)
	if err := validateOrgInput(in); err != nil {
		return nil, err
	}
	if _, err := uc.Organizations.GetOrganizationByCode(ctx, nil, in.Code); err == nil {
		return nil, ConflictCode("ORGANIZATION_CODE_EXISTS", "组织 code 已存在")
	} else if !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	now := uc.Clock.Now().UTC()
	var created *Organization
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		org, err := uc.Organizations.CreateOrganization(ctx, tx, &Organization{Code: in.Code, Name: in.Name, CreatedBy: actor.User.ID})
		if err != nil {
			return err
		}
		created = org
		if _, err := uc.Organizations.AddMember(ctx, tx, &OrganizationMember{
			OrganizationID: org.ID, UserID: actor.User.ID, Role: OrgRoleOwner, InvitedBy: actor.User.ID,
		}); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "organization.create", itoa(org.ID), "{}", "{}", string(mustJSON(map[string]string{"code": org.Code, "name": org.Name})), "self-service organization creation", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"organization_id": org.ID, "code": org.Code, "created_at": now})
		return uc.emit(ctx, tx, "organization", org.ID, org.Revision, "organization.created", string(payload))
	})
	if err != nil {
		return nil, err
	}
	created.Role = OrgRoleOwner
	created.MemberCount = 1
	return created, nil
}

func (uc *OrganizationUsecase) Get(ctx context.Context, actor ActorContext, orgID int64) (*Organization, error) {
	org, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	org.Role = role
	count, _ := uc.Organizations.CountActiveMembers(ctx, nil, orgID)
	org.MemberCount = count
	return org, nil
}

func (uc *OrganizationUsecase) Update(ctx context.Context, actor ActorContext, orgID int64, name string, expected uint64, reason string) (*Organization, error) {
	org, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgManager(role); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 128 {
		return nil, Validation("组织名称必须为 1-128 个字符")
	}
	org.Name = name
	var updated *Organization
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Organizations.UpdateOrganization(ctx, tx, org, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "organization.update", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	updated.Role = role
	return updated, nil
}

func (uc *OrganizationUsecase) Archive(ctx context.Context, actor ActorContext, orgID int64, expected uint64, reason string) (*Organization, error) {
	org, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgOwner(role); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Organizations.ArchiveOrganization(ctx, tx, orgID, expected); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "organization.archive", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	org.Status, org.ArchivedAt, org.Revision, org.Role = OrgStatusArchived, &now, expected+1, role
	return org, nil
}

func (uc *OrganizationUsecase) AdminList(ctx context.Context, actor ActorContext, status string) ([]*Organization, error) {
	if !isPlatformAdmin(actor) {
		return nil, ErrPermissionDenied
	}
	orgs, err := uc.Organizations.ListAllOrganizations(ctx, nil, status)
	if err != nil {
		return nil, ErrDependency
	}
	for _, org := range orgs {
		org.Role = "platform"
	}
	return orgs, nil
}

func (uc *OrganizationUsecase) Members(ctx context.Context, actor ActorContext, orgID int64) ([]*OrganizationMember, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	members, err := uc.Organizations.ListMembers(ctx, nil, orgID)
	if err != nil {
		return nil, ErrDependency
	}
	if role == OrgRoleMember {
		for _, m := range members {
			m.Email = ""
		}
	}
	return members, nil
}

func (uc *OrganizationUsecase) AddMember(ctx context.Context, actor ActorContext, orgID int64, in MemberInput, reason string) (*OrganizationMember, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgManager(role); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if in.Role == "" {
		in.Role = OrgRoleMember
	}
	if !validOrgRole(in.Role) {
		return nil, Validation("组织角色只能是 owner/admin/member")
	}
	if in.Role == OrgRoleOwner && role != "platform" && role != OrgRoleOwner {
		return nil, ErrPermissionDenied
	}
	identifier := strings.TrimSpace(in.Identifier)
	if identifier == "" {
		return nil, Validation("成员用户名或邮箱不能为空")
	}
	var user *User
	if strings.Contains(identifier, "@") {
		user, err = uc.Users.GetByEmail(ctx, nil, NormalizeEmail(identifier))
	} else {
		user, err = uc.Users.GetByUsername(ctx, nil, NormalizeUsername(identifier))
	}
	if err != nil {
		return nil, ErrUserNotFound
	}
	if user.Status != UserStatusEnabled {
		return nil, Validation("目标账号不可用")
	}
	if in.DepartmentID != nil {
		if _, err := uc.Organizations.GetDepartment(ctx, nil, orgID, *in.DepartmentID); err != nil {
			return nil, Validation("部门不存在")
		}
	}
	if existing, err := uc.Organizations.GetMember(ctx, nil, orgID, user.ID); err == nil {
		if existing.Status == OrgMemberActive {
			return nil, Validation("用户已经是组织成员")
		}
		var restored *OrganizationMember
		err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
			row, err := uc.Organizations.RestoreMember(ctx, tx, orgID, user.ID, in.Role, in.DepartmentID, actor.User.ID)
			if err != nil {
				return err
			}
			restored = row
			return uc.audit(ctx, tx, actor, "organization.member.add", itoa(orgID), "{}", "{}", "{}", reason, "success")
		})
		if err != nil {
			return nil, err
		}
		restored.Username, restored.DisplayName, restored.Email = user.Username, user.DisplayName, user.Email
		return restored, nil
	}
	var created *OrganizationMember
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Organizations.AddMember(ctx, tx, &OrganizationMember{
			OrganizationID: orgID, UserID: user.ID, Role: in.Role,
			DepartmentID: in.DepartmentID, InvitedBy: actor.User.ID,
		})
		if err != nil {
			return err
		}
		created = row
		return uc.audit(ctx, tx, actor, "organization.member.add", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	created.Username, created.DisplayName, created.Email = user.Username, user.DisplayName, user.Email
	return created, nil
}

func (uc *OrganizationUsecase) UpdateMember(ctx context.Context, actor ActorContext, orgID, userID int64, role string, departmentID *int64, expected uint64, reason string) (*OrganizationMember, error) {
	_, actorRole, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgManager(actorRole); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, userID)
	if err != nil || member.Status != OrgMemberActive {
		return nil, ErrResourceNotFound
	}
	if !validOrgRole(role) {
		return nil, Validation("组织角色只能是 owner/admin/member")
	}
	if actorRole != "platform" && actorRole != OrgRoleOwner {
		if member.Role == OrgRoleOwner || role == OrgRoleOwner {
			return nil, ErrPermissionDenied
		}
		if member.Role == OrgRoleAdmin && actorRole == OrgRoleAdmin {
			return nil, ErrPermissionDenied
		}
	}
	if member.Role == OrgRoleOwner && role != OrgRoleOwner {
		if err := uc.ensureAnotherOwner(ctx, orgID); err != nil {
			return nil, err
		}
	}
	if departmentID != nil {
		if _, err := uc.Organizations.GetDepartment(ctx, nil, orgID, *departmentID); err != nil {
			return nil, Validation("部门不存在")
		}
	}
	member.Role, member.DepartmentID = role, departmentID
	var updated *OrganizationMember
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Organizations.UpdateMember(ctx, tx, member, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "organization.member.update", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *OrganizationUsecase) ensureAnotherOwner(ctx context.Context, orgID int64) error {
	count, err := uc.Organizations.CountActiveOwners(ctx, nil, orgID)
	if err != nil {
		return ErrDependency
	}
	if count <= 1 {
		return ErrOrganisationLastOwner
	}
	return nil
}

func (uc *OrganizationUsecase) RemoveMember(ctx context.Context, actor ActorContext, orgID, userID int64, expected uint64, reason string) error {
	_, actorRole, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return err
	}
	if err := requireOrgManager(actorRole); err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, userID)
	if err != nil || member.Status != OrgMemberActive {
		return ErrResourceNotFound
	}
	if actorRole != "platform" && actorRole != OrgRoleOwner {
		if member.Role != OrgRoleMember {
			return ErrPermissionDenied
		}
	}
	if member.Role == OrgRoleOwner {
		if err := uc.ensureAnotherOwner(ctx, orgID); err != nil {
			return err
		}
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Organizations.RemoveMember(ctx, tx, orgID, userID, expected); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "organization.member.remove", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
}

func (uc *OrganizationUsecase) Leave(ctx context.Context, actor ActorContext, orgID int64) error {
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, actor.User.ID)
	if err != nil || member.Status != OrgMemberActive {
		return ErrResourceNotFound
	}
	if member.Role == OrgRoleOwner {
		if err := uc.ensureAnotherOwner(ctx, orgID); err != nil {
			return err
		}
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Organizations.RemoveMember(ctx, tx, orgID, actor.User.ID, member.Revision); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "organization.member.leave", itoa(orgID), "{}", "{}", "{}", "self-service leave", "success")
	})
}

func (uc *OrganizationUsecase) Departments(ctx context.Context, actor ActorContext, orgID int64) ([]*Department, error) {
	if _, _, err := uc.orgAccess(ctx, actor, orgID); err != nil {
		return nil, err
	}
	return uc.Organizations.ListDepartments(ctx, nil, orgID)
}

func (uc *OrganizationUsecase) CreateDepartment(ctx context.Context, actor ActorContext, orgID int64, in DepartmentInput) (*Department, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgManager(role); err != nil {
		return nil, err
	}
	in.Code, in.Name = strings.ToLower(strings.TrimSpace(in.Code)), strings.TrimSpace(in.Name)
	if !orgCodePattern.MatchString(in.Code) || in.Name == "" {
		return nil, Validation("部门 code/名称不合法")
	}
	if in.ParentID != 0 {
		if _, err := uc.Organizations.GetDepartment(ctx, nil, orgID, in.ParentID); err != nil {
			return nil, Validation("上级部门不存在")
		}
	}
	var created *Department
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Organizations.CreateDepartment(ctx, tx, &Department{
			OrganizationID: orgID, ParentID: in.ParentID, Code: in.Code, Name: in.Name,
		})
		if err != nil {
			return err
		}
		created = row
		return uc.audit(ctx, tx, actor, "organization.department.create", itoa(orgID), "{}", "{}", "{}", "create department", "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *OrganizationUsecase) UpdateDepartment(ctx context.Context, actor ActorContext, orgID, deptID int64, in DepartmentInput, expected uint64, reason string) (*Department, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	if err := requireOrgManager(role); err != nil {
		return nil, err
	}
	dept, err := uc.Organizations.GetDepartment(ctx, nil, orgID, deptID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if in.ParentID != 0 {
		if in.ParentID == deptID {
			return nil, Validation("部门不能以自身为上级")
		}
		if _, err := uc.Organizations.GetDepartment(ctx, nil, orgID, in.ParentID); err != nil {
			return nil, Validation("上级部门不存在")
		}
		parent := in.ParentID
		for i := 0; i < 32 && parent != 0; i++ {
			if parent == deptID {
				return nil, Validation("部门层级不能形成环")
			}
			next, err := uc.Organizations.GetDepartment(ctx, nil, orgID, parent)
			if err != nil {
				break
			}
			parent = next.ParentID
		}
	}
	in.Code, in.Name = strings.ToLower(strings.TrimSpace(in.Code)), strings.TrimSpace(in.Name)
	if !orgCodePattern.MatchString(in.Code) || in.Name == "" {
		return nil, Validation("部门 code/名称不合法")
	}
	dept.ParentID, dept.Code, dept.Name = in.ParentID, in.Code, in.Name
	var updated *Department
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Organizations.UpdateDepartment(ctx, tx, dept, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "organization.department.update", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *OrganizationUsecase) ArchiveDepartment(ctx context.Context, actor ActorContext, orgID, deptID int64, expected uint64, reason string) error {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return err
	}
	if err := requireOrgManager(role); err != nil {
		return err
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Organizations.ArchiveDepartment(ctx, tx, orgID, deptID, expected); err != nil {
			return err
		}
		if err := uc.Organizations.ClearDepartmentMembers(ctx, tx, orgID, deptID); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "organization.department.archive", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
}

func (uc *OrganizationUsecase) AdminArchive(ctx context.Context, actor ActorContext, orgID int64, expected uint64, reason string) (*Organization, error) {
	if !isPlatformAdmin(actor) {
		return nil, ErrPermissionDenied
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Organizations.ArchiveOrganization(ctx, tx, orgID, expected); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "organization.admin_archive", itoa(orgID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	org.Status, org.ArchivedAt, org.Revision, org.Role = OrgStatusArchived, &now, expected+1, "platform"
	return org, nil
}

// OrgMemberRoleOf returns the caller's role; used by projections/tests.
func (uc *OrganizationUsecase) OrgMemberRoleOf(ctx context.Context, actor ActorContext, orgID int64) (string, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	return role, err
}
