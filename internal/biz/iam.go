package biz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type RoleMember struct {
	UserID       int64
	Username     string
	DisplayName  string
	AssignmentID int64
	AssignedAt   time.Time
	ExpiresAt    *time.Time
	Origin       string
}

type Reference struct {
	Kind   string
	ID     int64
	UserID int64
}

type RolePreview struct {
	Warnings          []string
	Added             []string
	Removed           []string
	AffectedUserCount int64
}

type BatchPreview struct {
	Eligible []int64
	Failures []BatchFailure
}

type BatchFailure struct {
	UserID int64
	Reason string
}

type ExplainResult struct {
	Allowed        bool
	Reason         string
	Sources        []authorization.GrantSource
	PolicyRevision uint64
	UserRevision   uint64
	ValidUntil     *time.Time
}

type SimulateResult struct {
	BeforeAllowed bool
	AfterAllowed  bool
	BeforeReason  string
	AfterReason   string
	Added         []string
	Removed       []string
}

func (uc *IAMUsecase) guard(ctx context.Context, actor ActorContext, operation string, stepUp bool) error {
	current, err := uc.currentIAMActor(ctx, actor)
	if err != nil {
		return err
	}
	actor = current
	if _, err := uc.Authorize(ctx, actor, operation, 0, true); err != nil {
		return err
	}
	if stepUp {
		return uc.RequireStepUp(ctx, actor)
	}
	return nil
}

func (uc *IAMUsecase) policyGuard(ctx context.Context, tx Tx, expected uint64) (uint64, error) {
	current, err := uc.Policy.PolicyRevision(ctx, tx)
	if err != nil {
		return 0, ErrDependency
	}
	if expected == 0 {
		return current, Validation("expected_policy_revision 必须为正整数")
	}
	if expected != current {
		return current, ConflictPolicy(current)
	}
	return current, nil
}

func (uc *IAMUsecase) Resources(ctx context.Context, actor ActorContext) ([]*Resource, error) {
	if err := uc.guard(ctx, actor, "iam.resource.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListResources(ctx, nil)
}

func (uc *IAMUsecase) Permissions(ctx context.Context, actor ActorContext, filter PermissionFilter) ([]*Permission, error) {
	if err := uc.guard(ctx, actor, "iam.permission.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListPermissions(ctx, nil, filter)
}

func (uc *IAMUsecase) Permission(ctx context.Context, actor ActorContext, id int64) (*Permission, error) {
	if err := uc.guard(ctx, actor, "iam.permission.read", false); err != nil {
		return nil, err
	}
	p, err := uc.IAM.GetPermission(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	return p, nil
}

func validatePermission(p *Permission) error {
	p.Code = strings.TrimSpace(p.Code)
	p.Name = strings.TrimSpace(p.Name)
	if p.Code == "" || p.Name == "" {
		return Validation("权限 code 和名称不能为空")
	}
	if strings.ContainsAny(p.Code, " \t\n") {
		return Validation("权限 code 不能包含空白字符")
	}
	if len(p.SupportedScopes) == 0 {
		p.SupportedScopes = []string{"all"}
	}
	for _, s := range p.SupportedScopes {
		if s != string(authorization.All) && s != string(authorization.Self) && s != string(authorization.Users) {
			return Validation("不支持的 scope: " + s)
		}
	}
	if p.RiskLevel == "" {
		p.RiskLevel = "low"
	}
	if p.Status == "" {
		p.Status = PermissionStatusActive
	}
	if p.Binding == "" {
		p.Binding = BindingUnbound
	}
	return nil
}

func (uc *IAMUsecase) CreatePermission(ctx context.Context, actor ActorContext, p *Permission, reason string, expectedPolicy uint64) (*Permission, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.permission.create", true); err != nil {
		return nil, err
	}
	if err := validatePermission(p); err != nil {
		return nil, err
	}
	resources, err := uc.IAM.ListResources(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	found := false
	for _, r := range resources {
		if r.ID == p.ResourceID {
			found = true
			break
		}
	}
	if !found {
		return nil, Validation("资源不存在")
	}
	var created *Permission
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.permission.create", true); err != nil {
			return err
		}
		c, err := uc.IAM.CreatePermission(ctx, tx, p)
		if err != nil {
			return err
		}
		created = c
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.permission.create", c.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *IAMUsecase) UpdatePermission(ctx context.Context, actor ActorContext, p *Permission, expected uint64, reason string, expectedPolicy uint64) (*Permission, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
		return nil, err
	}
	var updated *Permission
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
			return err
		}
		existing, err := uc.IAM.GetPermission(ctx, tx, p.ID)
		if err != nil {
			return ErrResourceNotFound
		}
		p.Code = existing.Code
		if existing.Binding == BindingBound && !slices.Equal(existing.SupportedScopes, p.SupportedScopes) {
			return Validation("已绑定权限的 scope 支持由执行点定义")
		}
		if err := validatePermission(p); err != nil {
			return err
		}
		existing.Name = p.Name
		existing.Category = p.Category
		existing.RiskLevel = p.RiskLevel
		existing.SupportedScopes = p.SupportedScopes
		existing.Description = p.Description
		existing.Sort = p.Sort
		u, err := uc.IAM.UpdatePermission(ctx, tx, existing, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.permission.update", existing.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) SetPermissionStatus(ctx context.Context, actor ActorContext, id int64, status string, expected uint64, reason string, expectedPolicy uint64) (*Permission, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if status != PermissionStatusActive && status != PermissionStatusDisabled {
		return nil, Validation("状态只能是 active 或 disabled")
	}
	if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
		return nil, err
	}
	var updated *Permission
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
			return err
		}
		p, err := uc.IAM.GetPermission(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if p.Protected && status == PermissionStatusDisabled {
			return ErrProtectedAccount
		}
		p.Status = status
		u, err := uc.IAM.UpdatePermission(ctx, tx, p, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.permission.status", p.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) ArchivePermission(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string, expectedPolicy uint64) (*Permission, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
		return nil, err
	}
	var updated *Permission
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.permission.update", true); err != nil {
			return err
		}
		p, err := uc.IAM.GetPermission(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if p.Protected {
			return ErrProtectedAccount
		}
		p.Status = PermissionStatusArchived
		u, err := uc.IAM.UpdatePermission(ctx, tx, p, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.permission.archive", p.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) PermissionReferences(ctx context.Context, actor ActorContext, id int64) ([]Reference, error) {
	if err := uc.guard(ctx, actor, "iam.permission.read", false); err != nil {
		return nil, err
	}
	p, err := uc.IAM.GetPermission(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	roles, err := uc.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	var out []Reference
	for _, r := range roles {
		for _, g := range r.Grants {
			if g.Operation == p.Code {
				out = append(out, Reference{Kind: "role", ID: r.ID})
			}
		}
	}
	return out, nil
}

func (uc *IAMUsecase) Roles(ctx context.Context, actor ActorContext, filter RoleFilter) ([]*Role, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListRoles(ctx, nil, filter)
}

func (uc *IAMUsecase) Role(ctx context.Context, actor ActorContext, id int64) (*Role, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, err
	}
	r, err := uc.IAM.GetRole(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	return r, nil
}

func validateGrants(ctx context.Context, repo IAMRepo, grants []Grant) error {
	permissions, err := repo.ListPermissions(ctx, nil, PermissionFilter{})
	if err != nil {
		return err
	}
	byCode := map[string]*Permission{}
	for _, p := range permissions {
		byCode[p.Code] = p
	}
	for _, g := range grants {
		p := byCode[g.Operation]
		if p == nil {
			return Validation("未知权限: " + g.Operation)
		}
		if p.Status == PermissionStatusArchived {
			return Validation("权限已归档: " + g.Operation)
		}
		if g.Effect != authorization.Allow && g.Effect != authorization.Deny {
			return Validation("effect 只能是 allow 或 deny")
		}
		if err := g.Scope.Validate(p.ScopeKinds()); err != nil {
			return Validation("权限 " + g.Operation + " 不支持该 scope")
		}
	}
	return nil
}

func (uc *IAMUsecase) CreateRole(ctx context.Context, actor ActorContext, role *Role, reason string, expectedPolicy uint64) (*Role, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.create", true); err != nil {
		return nil, err
	}
	role.Code = strings.TrimSpace(role.Code)
	role.Name = strings.TrimSpace(role.Name)
	if role.Code == "" || role.Name == "" {
		return nil, Validation("角色 code 和名称不能为空")
	}
	if role.Code == "root" || role.Builtin {
		return nil, ErrProtectedAccount
	}
	if strings.ContainsAny(role.Code, " \t\n") {
		return nil, Validation("角色 code 不能包含空白字符")
	}
	if role.Status == "" {
		role.Status = RoleStatusActive
	}
	if err := validateGrants(ctx, uc.IAM, role.Grants); err != nil {
		return nil, err
	}
	if err := uc.checkGrantAuthority(ctx, actor, role.Grants); err != nil {
		return nil, err
	}
	existingRoles, err := uc.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	if err := uc.checkInheritanceAuthority(ctx, actor, existingRoles, role.Inherits); err != nil {
		return nil, err
	}
	knownRoles := map[int64]bool{}
	for _, r := range existingRoles {
		knownRoles[r.ID] = true
	}
	for _, id := range role.Inherits {
		if !knownRoles[id] {
			return nil, Validation("继承角色不存在")
		}
	}
	var created *Role
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.create", true); err != nil {
			return err
		}
		if err := validateGrants(ctx, uc.IAM, role.Grants); err != nil {
			return err
		}
		if err := uc.checkGrantAuthority(ctx, actor, role.Grants); err != nil {
			return err
		}
		roles, err := uc.IAM.ListAllRolesWithGrants(ctx, tx)
		if err != nil {
			return ErrDependency
		}
		if err := uc.checkInheritanceAuthority(ctx, actor, roles, role.Inherits); err != nil {
			return err
		}
		c, err := uc.IAM.CreateRole(ctx, tx, role)
		if err != nil {
			return err
		}
		if len(role.Grants) > 0 {
			if _, err := uc.IAM.PutRoleGrants(ctx, tx, c.ID, role.Grants, 0); err != nil {
				return err
			}
		}
		if len(role.Inherits) > 0 {
			if _, err := uc.IAM.PutRoleInheritance(ctx, tx, c.ID, role.Inherits, 0); err != nil {
				return err
			}
		}
		created = c
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"role_id": c.ID, "code": c.Code})
		if err := uc.emit(ctx, tx, "role", c.ID, c.Revision, "authorization.changed", string(payload)); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.create", c.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return uc.IAM.GetRole(ctx, nil, created.ID)
}

func (uc *IAMUsecase) UpdateRole(ctx context.Context, actor ActorContext, id int64, name, description string, maxMembers int64, expected uint64, reason string, expectedPolicy uint64) (*Role, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 64 {
		return nil, Validation("角色名称必须为 1-64 个字符")
	}
	var updated *Role
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
			return err
		}
		r, err := uc.IAM.GetRole(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		r.Name, r.Description = name, description
		if maxMembers > 0 {
			r.MaxMembers = &maxMembers
		}
		u, err := uc.IAM.UpdateRole(ctx, tx, r, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.update", r.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) CopyRole(ctx context.Context, actor ActorContext, id int64, code, name, reason string, expected, expectedPolicy uint64) (*Role, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.create", true); err != nil {
		return nil, err
	}
	source, err := uc.IAM.GetRole(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if expected == 0 || source.Revision != expected {
		return nil, ConflictRevision(source.Revision)
	}
	if protectedRoot(source) {
		return nil, ErrProtectedAccount
	}
	copyRole := &Role{
		Code: code, Name: name, Description: source.Description,
		Status: RoleStatusActive, Grants: source.Grants, Inherits: source.Inherits,
	}
	return uc.CreateRole(ctx, actor, copyRole, reason, expectedPolicy)
}

func (uc *IAMUsecase) SetRoleStatus(ctx context.Context, actor ActorContext, id int64, status string, expected uint64, reason string, expectedPolicy uint64) (*Role, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if status != RoleStatusActive && status != RoleStatusDisabled {
		return nil, Validation("状态只能是 active 或 disabled")
	}
	if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
		return nil, err
	}
	var updated *Role
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
			return err
		}
		r, err := uc.IAM.GetRole(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if r.Builtin && r.Code == "root" && status != RoleStatusActive {
			return ErrProtectedAccount
		}
		r.Status = status
		u, err := uc.IAM.UpdateRole(ctx, tx, r, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.status", r.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) ArchiveRole(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string, expectedPolicy uint64) (*Role, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
		return nil, err
	}
	var updated *Role
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
			return err
		}
		r, err := uc.IAM.GetRole(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if r.Builtin {
			return ErrProtectedAccount
		}
		r.Status = RoleStatusArchived
		u, err := uc.IAM.UpdateRole(ctx, tx, r, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.archive", r.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) RoleMembers(ctx context.Context, actor ActorContext, id int64) ([]RoleMember, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListRoleMembers(ctx, nil, id)
}

func (uc *IAMUsecase) RolePermissions(ctx context.Context, actor ActorContext, id int64) ([]Grant, uint64, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, 0, err
	}
	r, err := uc.IAM.GetRole(ctx, nil, id)
	if err != nil {
		return nil, 0, ErrResourceNotFound
	}
	return r.Grants, r.Revision, nil
}

func (uc *IAMUsecase) PutRolePermissions(ctx context.Context, actor ActorContext, id int64, grants []Grant, expected, expectedPolicy uint64, reason string) ([]Grant, uint64, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, 0, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
		return nil, 0, err
	}
	if err := validateGrants(ctx, uc.IAM, grants); err != nil {
		return nil, 0, err
	}
	if err := uc.checkGrantAuthority(ctx, actor, grants); err != nil {
		return nil, 0, err
	}
	var revision uint64
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
			return err
		}
		if err := validateGrants(ctx, uc.IAM, grants); err != nil {
			return err
		}
		if err := uc.checkGrantAuthority(ctx, actor, grants); err != nil {
			return err
		}
		r, err := uc.IAM.GetRole(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if r.Builtin && r.Code == "root" {
			return ErrProtectedAccount
		}
		rev, err := uc.IAM.PutRoleGrants(ctx, tx, id, grants, expected)
		if err != nil {
			return err
		}
		revision = rev
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"role_id": id, "grants": len(grants)})
		if err := uc.emit(ctx, tx, "role", id, rev, "authorization.changed", string(payload)); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.permissions.update", r.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, 0, err
	}
	return grants, revision, nil
}

func (uc *IAMUsecase) RoleInheritance(ctx context.Context, actor ActorContext, id int64) ([]int64, uint64, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, 0, err
	}
	r, err := uc.IAM.GetRole(ctx, nil, id)
	if err != nil {
		return nil, 0, ErrResourceNotFound
	}
	return r.Inherits, r.Revision, nil
}

func (uc *IAMUsecase) PutRoleInheritance(ctx context.Context, actor ActorContext, id int64, inherits []int64, expected, expectedPolicy uint64, reason string) ([]int64, uint64, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, 0, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
		return nil, 0, err
	}
	roles, err := uc.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, 0, ErrDependency
	}
	if err := uc.checkInheritanceAuthority(ctx, actor, roles, inherits); err != nil {
		return nil, 0, err
	}
	edges := map[int64][]int64{}
	for _, r := range roles {
		edges[r.ID] = r.Inherits
	}
	for _, in := range inherits {
		if _, ok := edges[in]; !ok {
			return nil, 0, Validation("继承角色不存在")
		}
	}
	edges[id] = inherits
	if err := authorization.ValidateInheritance(edges); err != nil {
		return nil, 0, Validation("角色继承不能形成环")
	}
	var revision uint64
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.role.update", true); err != nil {
			return err
		}
		roles, err := uc.IAM.ListAllRolesWithGrants(ctx, tx)
		if err != nil {
			return ErrDependency
		}
		if err := uc.checkInheritanceAuthority(ctx, actor, roles, inherits); err != nil {
			return err
		}
		edges := map[int64][]int64{}
		for _, r := range roles {
			edges[r.ID] = r.Inherits
		}
		edges[id] = inherits
		if authorization.ValidateInheritance(edges) != nil {
			return Validation("角色继承不能形成环")
		}
		r, err := uc.IAM.GetRole(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if r.Builtin && r.Code == "root" {
			return ErrProtectedAccount
		}
		rev, err := uc.IAM.PutRoleInheritance(ctx, tx, id, inherits, expected)
		if err != nil {
			return err
		}
		revision = rev
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.role.inheritance.update", r.Code, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, 0, err
	}
	return inherits, revision, nil
}

func (uc *IAMUsecase) PreviewRoleChange(ctx context.Context, actor ActorContext, id int64, grants []Grant, inherits []int64) (*RolePreview, error) {
	if err := uc.guard(ctx, actor, "iam.role.read", false); err != nil {
		return nil, err
	}
	role, err := uc.IAM.GetRole(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	allRoles, err := uc.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	edges := map[int64][]int64{}
	byID := map[int64]*Role{}
	for _, r := range allRoles {
		edges[r.ID] = r.Inherits
		byID[r.ID] = r
	}
	edges[id] = inherits
	if err := authorization.ValidateInheritance(edges); err != nil {
		return nil, Validation("角色继承不能形成环")
	}
	if err := validateGrants(ctx, uc.IAM, grants); err != nil {
		return nil, err
	}
	before := effectiveOps(role, byID)
	proposed := &Role{ID: role.ID, Grants: grants, Inherits: inherits}
	after := effectiveOps(proposed, byID)
	out := &RolePreview{}
	for op := range after {
		if !before[op] {
			out.Added = append(out.Added, op)
		}
	}
	for op := range before {
		if !after[op] {
			out.Removed = append(out.Removed, op)
		}
	}
	slices.Sort(out.Added)
	slices.Sort(out.Removed)
	if len(out.Added) > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("将新增 %d 个权限", len(out.Added)))
	}
	out.AffectedUserCount, _ = uc.IAM.CountActiveAssignmentsForRole(ctx, nil, id)
	return out, nil
}

func effectiveOps(role *Role, byID map[int64]*Role) map[string]bool {
	out := map[string]bool{}
	seen := map[int64]bool{}
	var walk func(*Role)
	walk = func(r *Role) {
		if r == nil || seen[r.ID] {
			return
		}
		seen[r.ID] = true
		for _, g := range r.Grants {
			if g.Effect == authorization.Allow {
				out[g.Operation] = true
			}
		}
		for _, id := range r.Inherits {
			walk(byID[id])
		}
	}
	walk(role)
	return out
}

func (uc *IAMUsecase) UserAssignments(ctx context.Context, actor ActorContext, userID int64) ([]*Assignment, error) {
	if err := uc.guard(ctx, actor, "iam.assignment.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListAssignmentsForUser(ctx, nil, userID)
}

func (uc *IAMUsecase) CreateAssignment(ctx context.Context, actor ActorContext, a *Assignment, reason string, expectedPolicy uint64) (*Assignment, error) {
	currentActor, actorErr := uc.currentIAMActor(ctx, actor)
	if actorErr != nil {
		return nil, actorErr
	}
	actor = currentActor
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if _, err := uc.Authorize(ctx, actor, "iam.assignment.create", a.UserID, false); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if a.UserID <= 0 || a.RoleID <= 0 {
		return nil, Validation("用户和角色不能为空")
	}
	var err error
	a.Boundary, err = normalizeAssignmentScope(a.Boundary)
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	if a.StartsAt.IsZero() {
		a.StartsAt = now
	}
	if a.ExpiresAt != nil && (!a.StartsAt.Before(*a.ExpiresAt) || !now.Before(*a.ExpiresAt)) {
		return nil, Validation("有效期不合法")
	}
	a.Origin, a.AssignedBy, a.Revision, a.CreatedAt = OriginExplicit, actor.User.ID, 1, now
	var created *Assignment
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		currentActor, err := uc.currentIAMActor(ctx, actor)
		if err != nil {
			return err
		}
		actor = currentActor
		if _, err := uc.Authorize(ctx, actor, "iam.assignment.create", a.UserID, false); err != nil {
			return err
		}
		if err := uc.validateAssignment(ctx, tx, a); err != nil {
			return err
		}
		if err := uc.checkDelegation(ctx, actor, a.UserID, a.RoleID, "assign", a.Boundary, a.StartsAt, a.ExpiresAt); err != nil {
			return err
		}
		c, err := uc.IAM.CreateAssignment(ctx, tx, a)
		if err != nil {
			return err
		}
		created = c
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": a.UserID, "role_id": a.RoleID})
		if err := uc.emit(ctx, tx, "user", a.UserID, 0, "authorization.changed", string(payload)); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.assignment.create", fmt.Sprintf("%d/%d", a.UserID, a.RoleID), "{}", "{}", "{}", reason, "success")
	})
	return created, err
}

func (uc *IAMUsecase) checkRoleCapacity(ctx context.Context, tx Tx, role *Role) error {
	if role.MaxMembers == nil {
		return nil
	}
	count, err := uc.IAM.CountActiveAssignmentsForRole(ctx, tx, role.ID)
	if err != nil {
		return ErrDependency
	}
	if count >= *role.MaxMembers {
		return fmt.Errorf("%w: 角色成员数已达上限", ErrRoleConstraint)
	}
	return nil
}

func (uc *IAMUsecase) RevokeAssignment(ctx context.Context, actor ActorContext, id int64, reason string, expected, expectedPolicy uint64) (*Assignment, error) {
	currentActor, actorErr := uc.currentIAMActor(ctx, actor)
	if actorErr != nil {
		return nil, actorErr
	}
	actor = currentActor
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	a, err := uc.IAM.GetAssignment(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if _, err := uc.Authorize(ctx, actor, "iam.assignment.revoke", a.UserID, false); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	var out *Assignment
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		currentActor, err := uc.currentIAMActor(ctx, actor)
		if err != nil {
			return err
		}
		actor = currentActor
		a, err := uc.IAM.GetAssignment(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || a.Revision != expected {
			return ConflictRevision(a.Revision)
		}
		if a.Revoked {
			return Validation("授权已撤销")
		}
		role, err := uc.IAM.GetRole(ctx, tx, a.RoleID)
		if err != nil {
			return err
		}
		if protectedRoot(role) {
			return ErrProtectedAccount
		}
		if _, err := uc.Authorize(ctx, actor, "iam.assignment.revoke", a.UserID, false); err != nil {
			return err
		}
		if err := uc.checkDelegation(ctx, actor, a.UserID, a.RoleID, "revoke", a.Boundary, a.StartsAt, a.ExpiresAt); err != nil {
			return err
		}
		if err := uc.IAM.RevokeAssignment(ctx, tx, id, a.Revision, actor.User.ID); err != nil {
			return err
		}
		a.Revoked, a.Revision = true, a.Revision+1
		out = a
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": a.UserID, "role_id": a.RoleID})
		if err := uc.emit(ctx, tx, "user", a.UserID, 0, "authorization.changed", string(payload)); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.assignment.revoke", fmt.Sprintf("%d/%d", a.UserID, a.RoleID), "{}", "{}", "{}", reason, "success")
	})
	return out, err
}

func (uc *IAMUsecase) PreviewBatch(ctx context.Context, actor ActorContext, userIDs []int64, roleID int64, boundary authorization.Scope, expires *time.Time) (*BatchPreview, error) {
	currentActor, actorErr := uc.currentIAMActor(ctx, actor)
	if actorErr != nil {
		return nil, actorErr
	}
	actor = currentActor
	if len(userIDs) == 0 || len(userIDs) > 100 {
		return nil, Validation("每批必须为 1-100 个用户")
	}
	boundary, err := normalizeAssignmentScope(boundary)
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	if expires != nil && !now.Before(*expires) {
		return nil, Validation("有效期不合法")
	}
	out := &BatchPreview{}
	seen := map[int64]bool{}
	for _, uid := range userIDs {
		if uid <= 0 || seen[uid] {
			return nil, Validation("批量用户必须有效且不能重复")
		}
		seen[uid] = true
		if _, err := uc.Authorize(ctx, actor, "iam.assignment.create", uid, false); err != nil {
			return nil, err
		}
		if err := uc.checkDelegation(ctx, actor, uid, roleID, "assign", boundary, now, expires); err != nil {
			return nil, err
		}
		if err := uc.validateAssignment(ctx, nil, &Assignment{UserID: uid, RoleID: roleID, Boundary: boundary, StartsAt: now, ExpiresAt: expires}); err != nil {
			out.Failures = append(out.Failures, BatchFailure{UserID: uid, Reason: err.Error()})
			continue
		}
		out.Eligible = append(out.Eligible, uid)
	}
	return out, nil
}

func (uc *IAMUsecase) BatchAssign(ctx context.Context, actor ActorContext, userIDs []int64, roleID int64, boundary authorization.Scope, starts time.Time, expires *time.Time, reason string, expectedPolicy uint64) ([]*Assignment, error) {
	currentActor, actorErr := uc.currentIAMActor(ctx, actor)
	if actorErr != nil {
		return nil, actorErr
	}
	actor = currentActor
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	preview, err := uc.PreviewBatch(ctx, actor, userIDs, roleID, boundary, expires)
	if err != nil {
		return nil, err
	}
	if len(preview.Failures) > 0 {
		return nil, Validation(fmt.Sprintf("批量授权预检失败 %d 项，请先处理", len(preview.Failures)))
	}
	boundary, err = normalizeAssignmentScope(boundary)
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	if starts.IsZero() {
		starts = now
	}
	if expires != nil && !starts.Before(*expires) {
		return nil, Validation("有效期不合法")
	}
	var created []*Assignment
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		currentActor, err := uc.currentIAMActor(ctx, actor)
		if err != nil {
			return err
		}
		actor = currentActor
		for _, uid := range preview.Eligible {
			if _, err := uc.Authorize(ctx, actor, "iam.assignment.create", uid, false); err != nil {
				return err
			}
			if err := uc.checkDelegation(ctx, actor, uid, roleID, "assign", boundary, starts, expires); err != nil {
				return err
			}
			a := &Assignment{UserID: uid, RoleID: roleID, Boundary: boundary, StartsAt: starts, ExpiresAt: expires, Origin: OriginExplicit, Revision: 1, AssignedBy: actor.User.ID, CreatedAt: now}
			if err := uc.validateAssignment(ctx, tx, a); err != nil {
				return err
			}
			c, err := uc.IAM.CreateAssignment(ctx, tx, a)
			if err != nil {
				return err
			}
			created = append(created, c)
			payload, _ := jsonx.Marshal(map[string]any{"user_id": uid, "role_id": roleID})
			if err := uc.emit(ctx, tx, "user", uid, 0, "authorization.changed", string(payload)); err != nil {
				return err
			}
		}
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.assignment.batch_create", fmt.Sprintf("role:%d", roleID), "{}", "{}", string(mustJSON(map[string]int{"count": len(created)})), reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *IAMUsecase) Constraints(ctx context.Context, actor ActorContext) ([]*Constraint, error) {
	if err := uc.guard(ctx, actor, "iam.constraint.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListConstraints(ctx, nil)
}

func validateConstraint(c *Constraint) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.RoleIDs) == 0 {
		return Validation("约束名称和角色不能为空")
	}
	switch c.Kind {
	case "mutual_exclusion":
		if len(c.RoleIDs) < 2 {
			return Validation("互斥约束至少需要两个角色")
		}
	case "max_roles":
		if c.MaxCount <= 0 {
			return Validation("数量约束必须大于 0")
		}
	default:
		return Validation("不支持的约束类型")
	}
	return nil
}

func (uc *IAMUsecase) CreateConstraint(ctx context.Context, actor ActorContext, c *Constraint, reason string, expectedPolicy uint64) (*Constraint, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
		return nil, err
	}
	if err := validateConstraint(c); err != nil {
		return nil, err
	}
	roles, err := uc.IAM.ListRoles(ctx, nil, RoleFilter{})
	if err != nil {
		return nil, ErrDependency
	}
	known := map[int64]bool{}
	for _, r := range roles {
		known[r.ID] = true
	}
	for _, id := range c.RoleIDs {
		if !known[id] {
			return nil, Validation("约束包含未知角色")
		}
	}
	var created *Constraint
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
			return err
		}
		seen := map[int64]bool{}
		for _, id := range c.RoleIDs {
			if id <= 0 || seen[id] {
				return Validation("约束角色必须有效且不能重复")
			}
			seen[id] = true
			role, err := uc.IAM.GetRole(ctx, tx, id)
			if err != nil {
				return Validation("约束包含未知角色")
			}
			if protectedRoot(role) {
				return ErrProtectedAccount
			}
		}
		created0, err := uc.IAM.CreateConstraint(ctx, tx, c)
		if err != nil {
			return err
		}
		created = created0
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.constraint.create", c.Name, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *IAMUsecase) UpdateConstraint(ctx context.Context, actor ActorContext, c *Constraint, expected uint64, reason string, expectedPolicy uint64) (*Constraint, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
		return nil, err
	}
	var updated *Constraint
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
			return err
		}
		existing, err := uc.IAM.GetConstraint(ctx, tx, c.ID)
		if err != nil {
			return ErrResourceNotFound
		}
		c.Kind = existing.Kind
		if err := validateConstraint(c); err != nil {
			return err
		}
		seen := map[int64]bool{}
		for _, id := range c.RoleIDs {
			if id <= 0 || seen[id] {
				return Validation("约束角色必须有效且不能重复")
			}
			seen[id] = true
			role, err := uc.IAM.GetRole(ctx, tx, id)
			if err != nil {
				return Validation("约束包含未知角色")
			}
			if protectedRoot(role) {
				return ErrProtectedAccount
			}
		}
		u, err := uc.IAM.UpdateConstraint(ctx, tx, c, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.constraint.update", c.Name, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) DeleteConstraint(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string, expectedPolicy uint64) error {
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
		return err
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.constraint.update", true); err != nil {
			return err
		}
		current, err := uc.IAM.GetConstraint(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || current.Revision != expected {
			return ConflictRevision(current.Revision)
		}
		if err := uc.IAM.DeleteConstraint(ctx, tx, id); err != nil {
			return ErrResourceNotFound
		}
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.constraint.delete", itoa(id), "{}", "{}", "{}", reason, "success")
	})
}

func (uc *IAMUsecase) Menus(ctx context.Context, actor ActorContext) ([]*MenuItem, error) {
	if err := uc.guard(ctx, actor, "iam.menu.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListMenus(ctx, nil)
}

func validateMenu(m *MenuItem) error {
	m.RouteKey = strings.TrimSpace(m.RouteKey)
	m.Name = strings.TrimSpace(m.Name)
	if m.RouteKey == "" || m.Name == "" {
		return Validation("菜单路由和名称不能为空")
	}
	if !slices.Contains([]string{"account", "account/security", "account/sessions", "account/roles", "account/activity", "admin", "admin/users", "admin/iam/roles", "admin/iam/permissions", "admin/iam/assignments", "admin/iam/delegations", "admin/iam/constraints", "admin/iam/menus", "admin/iam/explain", "admin/audits", "admin/exports", "admin/integrations", "admin/settings/auth", "admin/settings/email"}, m.RouteKey) {
		return Validation("不支持的菜单路由")
	}
	return nil
}

func (uc *IAMUsecase) CreateMenu(ctx context.Context, actor ActorContext, m *MenuItem, reason string, expectedPolicy uint64) (*MenuItem, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
		return nil, err
	}
	if err := validateMenu(m); err != nil {
		return nil, err
	}
	var created *MenuItem
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
			return err
		}
		for _, code := range append(slices.Clone(m.RequiredAll), m.RequiredAny...) {
			if _, err := uc.IAM.GetPermissionByCode(ctx, tx, code); err != nil {
				return Validation("菜单包含未知权限")
			}
		}
		if m.ParentID > 0 {
			if _, err := uc.IAM.GetMenu(ctx, tx, m.ParentID); err != nil {
				return Validation("父菜单不存在")
			}
		}
		c, err := uc.IAM.CreateMenu(ctx, tx, m)
		if err != nil {
			return err
		}
		created = c
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.menu.create", m.RouteKey, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *IAMUsecase) UpdateMenu(ctx context.Context, actor ActorContext, m *MenuItem, expected uint64, reason string, expectedPolicy uint64) (*MenuItem, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
		return nil, err
	}
	var updated *MenuItem
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
			return err
		}
		existing, err := uc.IAM.GetMenu(ctx, tx, m.ID)
		if err != nil {
			return ErrResourceNotFound
		}
		m.RouteKey = existing.RouteKey
		if err := validateMenu(m); err != nil {
			return err
		}
		for _, code := range append(slices.Clone(m.RequiredAll), m.RequiredAny...) {
			if _, err := uc.IAM.GetPermissionByCode(ctx, tx, code); err != nil {
				return Validation("菜单包含未知权限")
			}
		}
		u, err := uc.IAM.UpdateMenu(ctx, tx, m, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.menu.update", m.RouteKey, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) ArchiveMenu(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string, expectedPolicy uint64) (*MenuItem, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
		return nil, err
	}
	var updated *MenuItem
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.menu.update", false); err != nil {
			return err
		}
		m, err := uc.IAM.GetMenu(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		m.Enabled = false
		u, err := uc.IAM.UpdateMenu(ctx, tx, m, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.menu.archive", m.RouteKey, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) Explain(ctx context.Context, actor ActorContext, userID int64, operation, resourceID, ownerUserID string) (*ExplainResult, error) {
	if err := uc.guard(ctx, actor, "iam.authorization.explain", false); err != nil {
		return nil, err
	}
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	assignments, err := uc.IAM.ListAssignmentsForUser(ctx, nil, userID)
	if err != nil {
		return nil, ErrDependency
	}
	var active []int64
	for _, a := range assignments {
		if a.Active(uc.Clock.Now()) {
			active = append(active, a.RoleID)
		}
	}
	facts, err := uc.LoadAuthzFacts(ctx, userID, active)
	if err != nil {
		return nil, ErrDependency
	}
	owner := userID
	if ownerUserID != "" {
		owner, err = ParseID(ownerUserID, "owner_user_id")
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(resourceID) != "" {
		// Resource-level facts live in the owner service; ignoring the parameter
		// would return an explanation that looks authoritative but is not.
		return nil, Validation("资源级解释需要在资源 owner 执行，本接口只解释平台策略")
	}
	now := uc.Clock.Now()
	actorCtx := ActorContext{
		User: user, Session: &Session{ID: "explain", UserID: userID, ActiveRoleIDs: active, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)},
		Actor: authorization.Actor{UserID: userID, SessionID: "explain", ExpiresAt: now.Add(time.Hour)},
	}
	decision, err := uc.decideWithFacts(ctx, facts, actorCtx, operation, owner, false)
	if err != nil {
		return nil, ErrDependency
	}
	return &ExplainResult{
		Allowed: decision.Allowed, Reason: decision.Reason, Sources: decision.Sources,
		PolicyRevision: facts.PolicyRevision, UserRevision: facts.UserRevision, ValidUntil: decision.ValidUntil,
	}, nil
}

func (uc *IAMUsecase) Simulate(ctx context.Context, actor ActorContext, userID int64, addRoleIDs, removeRoleIDs []int64, operation, ownerUserID string) (*SimulateResult, error) {
	if err := uc.guard(ctx, actor, "iam.authorization.explain", false); err != nil {
		return nil, err
	}
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	base, err := uc.LoadAuthzFacts(ctx, userID, nil)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	owner := userID
	if ownerUserID != "" {
		owner, err = ParseID(ownerUserID, "owner_user_id")
		if err != nil {
			return nil, err
		}
	}
	for _, id := range append(slices.Clone(addRoleIDs), removeRoleIDs...) {
		if base.Roles[id] == nil {
			return nil, Validation("模拟包含未知角色")
		}
	}
	for _, id := range addRoleIDs {
		if base.Roles[id].Status != RoleStatusActive {
			return nil, Validation("模拟不能新增已停用角色")
		}
		if slices.Contains(removeRoleIDs, id) {
			return nil, Validation("不能同时新增和移除同一角色")
		}
	}
	beforeAssignments := slices.Clone(base.Assignments)
	afterAssignments := []*Assignment{}
	assigned := map[int64]bool{}
	for _, assignment := range beforeAssignments {
		if slices.Contains(removeRoleIDs, assignment.RoleID) {
			continue
		}
		afterAssignments = append(afterAssignments, assignment)
		if assignment.Active(now) {
			assigned[assignment.RoleID] = true
		}
	}
	for _, id := range addRoleIDs {
		if !assigned[id] {
			afterAssignments = append(afterAssignments, &Assignment{UserID: userID, RoleID: id, Boundary: authorization.Scope{All: true}, StartsAt: now})
		}
	}
	permissions, err := uc.IAM.ListPermissions(ctx, nil, PermissionFilter{Status: PermissionStatusActive})
	if err != nil {
		return nil, ErrDependency
	}
	evaluate := func(assignments []*Assignment) (map[string]bool, authorization.Decision, error) {
		facts := *base
		facts.Assignments, facts.ActiveRoleIDs = assignments, []int64{}
		for _, assignment := range assignments {
			if assignment.Active(now) && !slices.Contains(facts.ActiveRoleIDs, assignment.RoleID) {
				facts.ActiveRoleIDs = append(facts.ActiveRoleIDs, assignment.RoleID)
			}
		}
		if err := facts.resolveSources(now); err != nil {
			return nil, authorization.Decision{}, err
		}
		actorCtx := ActorContext{
			User: user, Session: &Session{ID: "simulate", UserID: userID, ActiveRoleIDs: facts.ActiveRoleIDs, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)},
			Actor: authorization.Actor{UserID: userID, SessionID: "simulate", ExpiresAt: now.Add(time.Hour)},
		}
		requested, err := uc.decideWithFacts(ctx, &facts, actorCtx, operation, owner, false)
		if err != nil {
			return nil, authorization.Decision{}, err
		}
		out := map[string]bool{}
		for _, permission := range permissions {
			if permission.Binding != BindingBound {
				continue
			}
			decision, err := uc.decideWithFacts(ctx, &facts, actorCtx, permission.Code, owner, false)
			if err != nil {
				return nil, authorization.Decision{}, err
			}
			out[permission.Code] = decision.Allowed
		}
		return out, requested, nil
	}
	before, beforeDecision, err := evaluate(beforeAssignments)
	if err != nil {
		return nil, ErrDependency
	}
	after, afterDecision, err := evaluate(afterAssignments)
	if err != nil {
		return nil, ErrDependency
	}
	out := &SimulateResult{BeforeAllowed: beforeDecision.Allowed, AfterAllowed: afterDecision.Allowed, BeforeReason: beforeDecision.Reason, AfterReason: afterDecision.Reason}
	for op, allowed := range after {
		if allowed && !before[op] {
			out.Added = append(out.Added, op)
		}
		if !allowed && before[op] {
			out.Removed = append(out.Removed, op)
		}
	}
	slices.Sort(out.Added)
	slices.Sort(out.Removed)
	return out, nil
}

var _ = errors.Is

func (uc *IAMUsecase) Assignments(ctx context.Context, actor ActorContext, filter AssignmentFilter) ([]*AssignmentItem, int64, error) {
	if err := uc.guard(ctx, actor, "iam.assignment.read", false); err != nil {
		return nil, 0, err
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}
	return uc.IAM.ListAssignments(ctx, nil, filter)
}

func (uc *IAMUsecase) Delegation(ctx context.Context, actor ActorContext, id int64) (*Delegation, error) {
	if err := uc.guard(ctx, actor, "iam.delegation.read", false); err != nil {
		return nil, err
	}
	d, err := uc.IAM.GetDelegation(ctx, nil, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	return d, nil
}

func (uc *IAMUsecase) Delegations(ctx context.Context, actor ActorContext, filter DelegationFilter) ([]*Delegation, error) {
	if err := uc.guard(ctx, actor, "iam.delegation.read", false); err != nil {
		return nil, err
	}
	return uc.IAM.ListDelegations(ctx, nil, filter)
}

func validateDelegation(d *Delegation) error {
	if d.ManagerRoleID <= 0 || d.TargetRoleID <= 0 {
		return Validation("管理角色和目标角色不能为空")
	}
	if d.ManagerRoleID == d.TargetRoleID {
		return Validation("管理角色不能委派给自身")
	}
	if d.TargetKind == "" {
		d.TargetKind = "role"
	}
	if d.TargetKind != "role" {
		return Validation("V1 只支持角色委派")
	}
	if d.CanRedelegate {
		return Validation("V1 不支持继续委派")
	}
	if len(d.Actions) == 0 {
		return Validation("委派动作不能为空")
	}
	for _, a := range d.Actions {
		if a != "assign" && a != "revoke" {
			return Validation("委派动作只能是 assign 或 revoke")
		}
	}
	if d.TargetUserScope.Empty() {
		d.TargetUserScope = authorization.Scope{All: true}
	}
	if err := d.TargetUserScope.Validate([]authorization.ScopeKind{authorization.All, authorization.Self, authorization.Users}); err != nil {
		return Validation("委派目标用户范围不合法")
	}
	if d.StartsAt.IsZero() {
		d.StartsAt = time.Now().UTC()
	}
	if d.ExpiresAt != nil && !d.StartsAt.Before(*d.ExpiresAt) {
		return Validation("委派有效期不合法")
	}
	return nil
}

func (uc *IAMUsecase) CreateDelegation(ctx context.Context, actor ActorContext, d *Delegation, reason string, expectedPolicy uint64) (*Delegation, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
		return nil, err
	}
	if err := validateDelegation(d); err != nil {
		return nil, err
	}
	roles, err := uc.IAM.ListAllRolesWithGrants(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	byID := map[int64]*Role{}
	perms, err := uc.IAM.ListPermissions(ctx, nil, PermissionFilter{})
	if err != nil {
		return nil, ErrDependency
	}
	permByCode := map[string]*Permission{}
	for _, p := range perms {
		permByCode[p.Code] = p
	}
	for _, r := range roles {
		byID[r.ID] = r
	}
	manager, target := byID[d.ManagerRoleID], byID[d.TargetRoleID]
	if manager == nil || manager.Status != RoleStatusActive {
		return nil, Validation("管理角色不可用")
	}
	if target == nil || target.Status != RoleStatusActive {
		return nil, Validation("目标角色不可用")
	}
	if protectedRoot(target) {
		return nil, ErrProtectedAccount
	}
	for _, c := range d.GrantCeiling {
		if err := uc.checkGrantAuthority(ctx, actor, []Grant{{Operation: c.Operation, Effect: authorization.Allow, Scope: c.Scope}}); err != nil {
			return nil, err
		}
		p := permByCode[c.Operation]
		if p == nil {
			return nil, Validation("委派上限包含未知权限: " + c.Operation)
		}
		if err := c.Scope.Validate(p.ScopeKinds()); err != nil {
			return nil, Validation("委派上限 scope 不合法: " + c.Operation)
		}
	}
	d.CreatedBy = actor.User.ID
	var created *Delegation
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
			return err
		}
		c, err := uc.IAM.CreateDelegation(ctx, tx, d)
		if err != nil {
			return err
		}
		created = c
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.delegation.create", itoa(c.ID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *IAMUsecase) UpdateDelegation(ctx context.Context, actor ActorContext, d *Delegation, expected uint64, reason string, expectedPolicy uint64) (*Delegation, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
		return nil, err
	}
	if err := validateDelegation(d); err != nil {
		return nil, err
	}
	for _, c := range d.GrantCeiling {
		if err := validateGrants(ctx, uc.IAM, []Grant{{Operation: c.Operation, Effect: authorization.Allow, Scope: c.Scope}}); err != nil {
			return nil, err
		}
		if err := uc.checkGrantAuthority(ctx, actor, []Grant{{Operation: c.Operation, Effect: authorization.Allow, Scope: c.Scope}}); err != nil {
			return nil, err
		}
	}
	var updated *Delegation
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
			return err
		}
		u, err := uc.IAM.UpdateDelegation(ctx, tx, d, expected)
		if err != nil {
			return err
		}
		updated = u
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.delegation.update", itoa(d.ID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *IAMUsecase) RevokeDelegation(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string, expectedPolicy uint64) (*Delegation, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
		return nil, err
	}
	var out *Delegation
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.policyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.guard(ctx, actor, "iam.delegation.update", true); err != nil {
			return err
		}
		d, err := uc.IAM.GetDelegation(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if d.RevokedAt != nil {
			return Validation("委派已撤销")
		}
		if err := uc.IAM.RevokeDelegation(ctx, tx, id, expected, actor.User.ID); err != nil {
			return err
		}
		d.RevokedAt = ptrTime(uc.Clock.Now().UTC())
		d.Revision = expected + 1
		out = d
		if err := uc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "iam.delegation.revoke", itoa(id), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func ptrTime(t time.Time) *time.Time { return &t }
