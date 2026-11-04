package data

import (
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type seedPermission struct {
	Code, Name, Category, Risk, Description string
	Scopes                                  []string
	Sort                                    int32
}

var seededResources = []resourcePO{
	{Code: "identity", Name: "账号与身份", Owner: "user-center", Enabled: true},
	{Code: "iam", Name: "权限治理", Owner: "user-center", Enabled: true},
	{Code: "audit", Name: "审计", Owner: "user-center", Enabled: true},
	{Code: "settings", Name: "认证配置", Owner: "user-center", Enabled: true},
}

var seededPermissions = []seedPermission{
	{"identity.user.list", "查看用户列表", "identity", "medium", "按数据范围筛选用户", []string{"all", "self", "user_ids"}, 10},
	{"identity.user.read", "查看用户详情", "identity", "medium", "读取用户核心资料", []string{"all", "self", "user_ids"}, 20},
	{"identity.user.create", "创建用户", "identity", "high", "创建账号并授予默认角色", []string{"all"}, 30},
	{"identity.user.update", "修改用户资料", "identity", "medium", "修改昵称等非敏感资料", []string{"all", "user_ids"}, 40},
	{"identity.user.enable", "启用用户", "identity", "high", "恢复账号登录", []string{"all", "user_ids"}, 50},
	{"identity.user.disable", "禁用用户", "identity", "high", "禁用账号并撤销会话", []string{"all", "user_ids"}, 60},
	{"identity.user.archive", "归档用户", "identity", "critical", "归档账号并保留审计", []string{"all"}, 70},
	{"identity.user.contact.read", "读取联系方式", "identity", "high", "读取完整邮箱等联系方式", []string{"all", "user_ids"}, 80},
	{"identity.user.export", "导出用户", "identity", "high", "生成用户导出文件", []string{"all", "user_ids"}, 90},
	{"identity.user.credential.update", "重置用户凭据", "identity", "critical", "发起密码重置", []string{"all", "user_ids"}, 100},
	{"identity.user.email_binding.update", "变更用户邮箱", "identity", "critical", "受控修改已验证邮箱", []string{"all", "user_ids"}, 110},
	{"identity.user.mfa.reset", "重置用户 MFA", "identity", "critical", "移除用户第二因素", []string{"all", "user_ids"}, 120},
	{"identity.user.session.read", "查看用户会话", "identity", "medium", "读取用户登录会话", []string{"all", "self", "user_ids"}, 130},
	{"identity.user.session.revoke", "撤销用户会话", "identity", "high", "撤销用户登录会话", []string{"all", "self", "user_ids"}, 140},
	{"identity.user.authorization.read", "查看用户权限", "identity", "medium", "读取用户有效权限", []string{"all", "self", "user_ids"}, 150},

	{"iam.resource.read", "查看资源目录", "iam", "low", "读取资源目录", []string{"all"}, 200},
	{"iam.permission.read", "查看权限目录", "iam", "low", "读取权限目录", []string{"all"}, 210},
	{"iam.permission.create", "创建权限", "iam", "high", "登记新的操作权限", []string{"all"}, 220},
	{"iam.permission.update", "修改权限", "iam", "high", "修改权限元数据或状态", []string{"all"}, 230},
	{"iam.role.read", "查看角色", "iam", "low", "读取角色与成员", []string{"all"}, 240},
	{"iam.role.create", "创建角色", "iam", "high", "创建或复制角色", []string{"all"}, 250},
	{"iam.role.update", "修改角色", "iam", "high", "修改角色权限、继承与状态", []string{"all"}, 260},
	{"iam.assignment.read", "查看授权分配", "iam", "low", "读取用户角色分配", []string{"all"}, 270},
	{"iam.assignment.create", "分配角色", "iam", "high", "授予用户角色", []string{"all", "user_ids"}, 280},
	{"iam.assignment.revoke", "撤销授权", "iam", "high", "撤销用户角色分配", []string{"all", "user_ids"}, 290},
	{"iam.constraint.read", "查看职责分离", "iam", "low", "读取互斥与数量约束", []string{"all"}, 300},
	{"iam.constraint.update", "修改职责分离", "iam", "critical", "修改互斥与数量约束", []string{"all"}, 310},
	{"iam.menu.read", "查看菜单", "iam", "low", "读取菜单投影", []string{"all"}, 320},
	{"iam.menu.update", "修改菜单", "iam", "medium", "修改菜单投影", []string{"all"}, 330},
	{"iam.authorization.explain", "解释授权", "iam", "medium", "解释与模拟授权结果", []string{"all"}, 340},
	{"iam.delegation.read", "查看委派", "iam", "low", "读取角色委派", []string{"all"}, 350},
	{"iam.delegation.update", "管理委派", "iam", "critical", "创建、修改与撤销委派", []string{"all"}, 360},

	{"audit.read", "查看审计", "audit", "medium", "读取授权审计", []string{"all"}, 400},
	{"audit.export", "导出审计", "audit", "high", "导出授权审计", []string{"all"}, 410},

	{"settings.auth.read", "查看认证配置", "settings", "medium", "读取注册与安全策略", []string{"all"}, 500},
	{"settings.auth.update", "修改认证配置", "settings", "high", "修改注册与安全策略", []string{"all"}, 510},
	{"settings.email.read", "查看邮件配置", "settings", "medium", "读取邮件配置（不含密钥）", []string{"all"}, 520},
	{"settings.email.update", "修改邮件配置", "settings", "high", "修改邮件配置或轮换密钥", []string{"all"}, 530},
	{"integration.client.read", "查看接入服务", "settings", "medium", "读取接入客户端", []string{"all"}, 600},
	{"integration.client.update", "管理接入服务", "settings", "critical", "创建、轮换与停用接入客户端", []string{"all"}, 610},
	{"integration.delivery.read", "查看事件投递", "settings", "medium", "读取 Outbox 投递状态", []string{"all"}, 620},
	{"integration.delivery.update", "重试事件投递", "settings", "high", "重试失败的事件投递", []string{"all"}, 630},
	{"oidc.client.read", "查看 OIDC 应用", "settings", "medium", "读取 OIDC 客户端", []string{"all"}, 700},
	{"oidc.client.update", "管理 OIDC 应用", "settings", "critical", "创建、轮换与停用 OIDC 客户端", []string{"all"}, 710},
	{"organization.admin.read", "查看所有组织", "identity", "medium", "平台管理员查看组织目录", []string{"all"}, 800},
	{"organization.admin.update", "管理所有组织", "identity", "high", "平台管理员归档组织", []string{"all"}, 810},
}

var seededMenus = []menuPO{
	{RouteKey: "account", Name: "个人资料", IconKey: "user", Sort: 10, RequiredAny: "[]"},
	{RouteKey: "account/security", Name: "安全中心", IconKey: "shield", Sort: 20, RequiredAny: "[]"},
	{RouteKey: "account/sessions", Name: "会话管理", IconKey: "monitor", Sort: 30, RequiredAny: "[]"},
	{RouteKey: "account/roles", Name: "会话角色", IconKey: "key", Sort: 40, RequiredAny: "[]"},
	{RouteKey: "account/activity", Name: "登录记录", IconKey: "activity", Sort: 50, RequiredAny: "[]"},
	{RouteKey: "admin", Name: "控制台", IconKey: "layout", Sort: 100, RequiredAll: `["identity.user.list"]`},
	{RouteKey: "admin/users", Name: "用户管理", IconKey: "users", Sort: 110, RequiredAll: `["identity.user.list"]`},
	{RouteKey: "admin/iam/roles", Name: "角色管理", IconKey: "shield", Sort: 120, RequiredAll: `["iam.role.read"]`},
	{RouteKey: "admin/iam/permissions", Name: "权限目录", IconKey: "list", Sort: 130, RequiredAll: `["iam.permission.read"]`},
	{RouteKey: "admin/iam/assignments", Name: "授权分配", IconKey: "key", Sort: 140, RequiredAll: `["iam.assignment.read"]`},
	{RouteKey: "admin/iam/delegations", Name: "委派管理", IconKey: "share", Sort: 145, RequiredAll: `["iam.delegation.read"]`},
	{RouteKey: "admin/audits", Name: "审计", IconKey: "file", Sort: 150, RequiredAll: `["audit.read"]`},
	{RouteKey: "admin/settings/auth", Name: "认证配置", IconKey: "settings", Sort: 160, RequiredAll: `["settings.auth.read"]`},
	{RouteKey: "admin/integrations", Name: "接入服务", IconKey: "plug", Sort: 170, RequiredAll: `["integration.client.read"]`},
	{RouteKey: "admin/applications", Name: "OIDC 应用", IconKey: "app", Sort: 180, RequiredAll: `["oidc.client.read"]`},
	{RouteKey: "admin/organizations", Name: "组织管理", IconKey: "building", Sort: 190, RequiredAll: `["organization.admin.read"]`},
}

// SeedCatalog installs the platform resource/permission catalog and the three
// built-in roles. It is idempotent and safe to run on every migrate invocation.
func SeedCatalog(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		resources := map[string]int64{}
		for _, r := range seededResources {
			var existing resourcePO
			err := tx.Where("code = ?", r.Code).First(&existing).Error
			if err == gorm.ErrRecordNotFound {
				if err := tx.Create(&r).Error; err != nil {
					return err
				}
				existing = r
			} else if err != nil {
				return err
			}
			resources[r.Code] = existing.ID
		}
		permissions := make([]permissionPO, 0, len(seededPermissions))
		for _, p := range seededPermissions {
			scopes, _ := jsonx.Marshal(p.Scopes)
			contexts, _ := jsonx.Marshal([]string{"platform"})
			po := permissionPO{
				ResourceID: resources[p.Category], Code: p.Code, Name: p.Name,
				Category: p.Category, RiskLevel: p.Risk, Status: "active", Binding: "bound",
				SupportedScopes: string(scopes), ContextTypes: string(contexts),
				Description: p.Description, Sort: p.Sort, Revision: 1,
			}
			var existing permissionPO
			err := tx.Where("code = ?", p.Code).First(&existing).Error
			if err == gorm.ErrRecordNotFound {
				if err := tx.Create(&po).Error; err != nil {
					return err
				}
				existing = po
			} else if err != nil {
				return err
			} else {
				// Catalog metadata is owned by the seed. Status/binding remain
				// operator-controlled, but scope support must follow the binary.
				if err := tx.Model(&permissionPO{}).Where("id = ?", existing.ID).Updates(map[string]any{
					"resource_id": po.ResourceID, "name": po.Name, "category": po.Category,
					"risk_level": po.RiskLevel, "supported_scopes": po.SupportedScopes,
					"context_types": po.ContextTypes, "description": po.Description, "sort": po.Sort,
				}).Error; err != nil {
					return err
				}
				existing.SupportedScopes = po.SupportedScopes
			}
			permissions = append(permissions, existing)
		}

		root, err := ensureRole(tx, "root", "最高治理", "平台最高治理角色，受保护且不可删除", true, nil)
		if err != nil {
			return err
		}
		admin, err := ensureRole(tx, "admin", "管理员", "账号与权限治理管理员", true, nil)
		if err != nil {
			return err
		}
		member, err := ensureRole(tx, "member", "普通成员", "默认注册角色，仅可访问本人数据", true, nil)
		if err != nil {
			return err
		}

		// Root receives the full catalog; admin a curated subset; member only
		// self-service operations.
		for _, p := range permissions {
			if err := ensureGrant(tx, root.ID, p.Code, authorization.Allow, authorization.Scope{All: true}); err != nil {
				return err
			}
			if adminCodes[p.Code] {
				if err := ensureGrant(tx, admin.ID, p.Code, authorization.Allow, authorization.Scope{All: true}); err != nil {
					return err
				}
			}
			if memberCodes[p.Code] {
				if err := ensureGrant(tx, member.ID, p.Code, authorization.Allow, authorization.Scope{Self: true}); err != nil {
					return err
				}
			}
		}
		for _, m := range seededMenus {
			var existing menuPO
			err := tx.Where("route_key = ?", m.RouteKey).First(&existing).Error
			if err == gorm.ErrRecordNotFound {
				m.Enabled = true
				m.Revision = 1
				if err := tx.Create(&m).Error; err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
		var state policyStatePO
		err = tx.Where("id = 1").First(&state).Error
		if err == gorm.ErrRecordNotFound {
			if err := tx.Create(&policyStatePO{ID: 1, PolicyRevision: 1, CatalogRevision: 1, AuthorizationMode: "iam", CutoverState: "complete"}).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		return nil
	})
}

func ensureRole(tx *gorm.DB, code, name, description string, builtin bool, max *int64) (*rolePO, error) {
	var role rolePO
	err := tx.Where("code = ?", code).First(&role).Error
	if err == gorm.ErrRecordNotFound {
		role = rolePO{Code: code, Name: name, Description: description, Builtin: builtin, Status: "active", Revision: 1, MaxMembers: max}
		if err := tx.Create(&role).Error; err != nil {
			return nil, err
		}
		return &role, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func ensureGrant(tx *gorm.DB, roleID int64, operation string, effect authorization.Effect, scope authorization.Scope) error {
	raw, err := jsonx.Marshal(scope)
	if err != nil {
		return err
	}
	p := roleGrantPO{RoleID: roleID, Operation: operation, Effect: string(effect), Scope: string(raw)}
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&p).Error
}

var adminCodes = func() map[string]bool {
	out := map[string]bool{}
	for _, code := range []string{
		"identity.user.list", "identity.user.read", "identity.user.create", "identity.user.update",
		"identity.user.enable", "identity.user.disable", "identity.user.archive",
		"identity.user.contact.read", "identity.user.export", "identity.user.credential.update",
		"identity.user.mfa.reset", "identity.user.session.read", "identity.user.session.revoke",
		"identity.user.authorization.read",
		"iam.resource.read", "iam.permission.read", "iam.role.read", "iam.assignment.read",
		"iam.assignment.create", "iam.assignment.revoke", "iam.constraint.read",
		"iam.menu.read", "iam.authorization.explain", "audit.read", "oidc.client.read", "oidc.client.update",
		"organization.admin.read", "organization.admin.update",
		"settings.auth.read",
	} {
		out[code] = true
	}
	return out
}()

var memberCodes = func() map[string]bool {
	out := map[string]bool{}
	for _, code := range []string{
		"identity.user.read", "identity.user.update", "identity.user.session.read",
		"identity.user.session.revoke", "identity.user.authorization.read",
	} {
		out[code] = true
	}
	return out
}()

var _ = fmt.Sprintf
var _ = time.Now
