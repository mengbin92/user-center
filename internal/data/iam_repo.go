package data

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type iamRepo struct{ d *Data }

func NewIAMRepo(d *Data) biz.IAMRepo       { return &iamRepo{d: d} }
func NewPolicyRepo(d *Data) biz.PolicyRepo { return &iamRepo{d: d} }

func (r *iamRepo) PolicyRevision(ctx context.Context, tx biz.Tx) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var p policyStatePO
	err := db.Where("id = 1").First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row := &policyStatePO{ID: 1, PolicyRevision: 1, CatalogRevision: 1, AuthorizationMode: "iam", CutoverState: "complete"}
		if err := db.Create(row).Error; err != nil {
			// A concurrent bootstrap may have won the race.
			if err := db.Where("id = 1").First(&p).Error; err != nil {
				return 0, err
			}
			return p.PolicyRevision, nil
		}
		return row.PolicyRevision, nil
	}
	if err != nil {
		return 0, err
	}
	return p.PolicyRevision, nil
}

func (r *iamRepo) BumpPolicyRevision(ctx context.Context, tx biz.Tx) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	if _, err := r.PolicyRevision(ctx, tx); err != nil {
		return 0, err
	}
	if err := db.Model(&policyStatePO{}).Where("id = 1").Updates(map[string]any{
		"policy_revision": gorm.Expr("policy_revision + 1"),
	}).Error; err != nil {
		return 0, err
	}
	var p policyStatePO
	if err := db.Select("policy_revision").Where("id = 1").First(&p).Error; err != nil {
		return 0, err
	}
	return p.PolicyRevision, nil
}

func (r *iamRepo) UserRevision(ctx context.Context, tx biz.Tx, userID int64) (uint64, error) {
	var p userPO
	err := r.d.dbOr(tx).WithContext(ctx).Select("revision").Where("id = ?", userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, biz.ErrUserNotFound
	}
	return p.Revision, err
}

func (r *iamRepo) ListResources(ctx context.Context, tx biz.Tx) ([]*biz.Resource, error) {
	var rows []resourcePO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Resource, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.Resource{ID: p.ID, Code: p.Code, Name: p.Name, Owner: p.Owner, Enabled: p.Enabled})
	}
	return out, nil
}

func permissionToBiz(p permissionPO) *biz.Permission {
	scopes := []string{}
	_ = jsonx.Unmarshal([]byte(p.SupportedScopes), &scopes)
	contexts := []string{}
	_ = jsonx.Unmarshal([]byte(p.ContextTypes), &contexts)
	return &biz.Permission{
		ID: p.ID, ResourceID: p.ResourceID, Code: p.Code, Name: p.Name,
		Category: p.Category, RiskLevel: p.RiskLevel, Status: p.Status,
		Binding: p.Binding, SupportedScopes: scopes, ContextTypes: contexts,
		Protected: p.Protected, Description: p.Description, Sort: p.Sort,
		Revision: p.Revision,
	}
}

func permissionToPO(p *biz.Permission) *permissionPO {
	scopes, _ := jsonx.Marshal(p.SupportedScopes)
	contexts, _ := jsonx.Marshal(p.ContextTypes)
	return &permissionPO{
		ID: p.ID, ResourceID: p.ResourceID, Code: p.Code, Name: p.Name,
		Category: p.Category, RiskLevel: p.RiskLevel, Status: p.Status,
		Binding: p.Binding, SupportedScopes: string(scopes), ContextTypes: string(contexts),
		Protected: p.Protected, Description: p.Description, Sort: p.Sort,
		Revision: p.Revision,
	}
}

func (r *iamRepo) ListPermissions(ctx context.Context, tx biz.Tx, f biz.PermissionFilter) ([]*biz.Permission, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&permissionPO{})
	if f.Category != "" {
		db = db.Where("category = ?", f.Category)
	}
	if f.Status != "" {
		db = db.Where("status = ?", f.Status)
	}
	if f.Keyword != "" {
		like := "%" + strings.ToLower(f.Keyword) + "%"
		db = db.Where("LOWER(code) LIKE ? OR LOWER(name) LIKE ?", like, like)
	}
	var rows []permissionPO
	if err := db.Order("sort, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Permission, 0, len(rows))
	for _, p := range rows {
		out = append(out, permissionToBiz(p))
	}
	return out, nil
}

func (r *iamRepo) GetPermission(ctx context.Context, tx biz.Tx, id int64) (*biz.Permission, error) {
	var p permissionPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return permissionToBiz(p), nil
}

func (r *iamRepo) GetPermissionByCode(ctx context.Context, tx biz.Tx, code string) (*biz.Permission, error) {
	var p permissionPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("code = ?", code).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return permissionToBiz(p), nil
}

func (r *iamRepo) CreatePermission(ctx context.Context, tx biz.Tx, p *biz.Permission) (*biz.Permission, error) {
	po := permissionToPO(p)
	po.ID = 0
	if po.Revision == 0 {
		po.Revision = 1
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(po).Error; err != nil {
		return nil, err
	}
	return permissionToBiz(*po), nil
}

func (r *iamRepo) UpdatePermission(ctx context.Context, tx biz.Tx, p *biz.Permission, expected uint64) (*biz.Permission, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	po := permissionToPO(p)
	res := db.Model(&permissionPO{}).Where("id = ? AND revision = ?", p.ID, expected).Updates(map[string]any{
		"name": po.Name, "category": po.Category, "risk_level": po.RiskLevel,
		"status": po.Status, "description": po.Description, "sort": po.Sort,
		"supported_scopes": po.SupportedScopes, "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		var cur permissionPO
		if err := db.Select("revision").Where("id = ?", p.ID).First(&cur).Error; err != nil {
			return nil, biz.ErrResourceNotFound
		}
		return nil, biz.ConflictRevision(cur.Revision)
	}
	return r.GetPermission(ctx, tx, p.ID)
}

var _ = fmt.Sprintf

func (r *iamRepo) loadRoles(ctx context.Context, tx biz.Tx, filter biz.RoleFilter) ([]*biz.Role, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&rolePO{})
	if filter.Status != "" {
		db = db.Where("status = ?", filter.Status)
	}
	if filter.Keyword != "" {
		like := "%" + strings.ToLower(filter.Keyword) + "%"
		db = db.Where("LOWER(code) LIKE ? OR LOWER(name) LIKE ?", like, like)
	}
	var rows []rolePO
	if err := db.Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []*biz.Role{}, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, p := range rows {
		ids = append(ids, p.ID)
	}
	var grants []roleGrantPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id IN ?", ids).Find(&grants).Error; err != nil {
		return nil, err
	}
	var edges []roleInheritancePO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id IN ?", ids).Find(&edges).Error; err != nil {
		return nil, err
	}
	grantMap := map[int64][]biz.Grant{}
	for _, g := range grants {
		var scope authorization.Scope
		if err := jsonx.Unmarshal([]byte(g.Scope), &scope); err != nil {
			return nil, fmt.Errorf("decode role grant scope: %w", err)
		}
		grantMap[g.RoleID] = append(grantMap[g.RoleID], biz.Grant{Operation: g.Operation, Effect: authorization.Effect(g.Effect), Scope: scope})
	}
	inheritMap := map[int64][]int64{}
	for _, e := range edges {
		inheritMap[e.RoleID] = append(inheritMap[e.RoleID], e.InheritsID)
	}
	out := make([]*biz.Role, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.Role{
			ID: p.ID, Code: p.Code, Name: p.Name, Description: p.Description,
			Builtin: p.Builtin, Status: p.Status, MaxMembers: p.MaxMembers,
			Revision: p.Revision, CreationDelegationID: p.CreationDelegationID,
			Grants: grantMap[p.ID], Inherits: inheritMap[p.ID],
		})
	}
	return out, nil
}

func (r *iamRepo) ListRoles(ctx context.Context, tx biz.Tx, filter biz.RoleFilter) ([]*biz.Role, error) {
	return r.loadRoles(ctx, tx, filter)
}

func (r *iamRepo) ListAllRolesWithGrants(ctx context.Context, tx biz.Tx) ([]*biz.Role, error) {
	return r.loadRoles(ctx, tx, biz.RoleFilter{})
}

func (r *iamRepo) GetRole(ctx context.Context, tx biz.Tx, id int64) (*biz.Role, error) {
	var p rolePO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	roles, err := r.loadRoles(ctx, tx, biz.RoleFilter{})
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		if role.ID == id {
			return role, nil
		}
	}
	return nil, biz.ErrResourceNotFound
}

func (r *iamRepo) GetRoleByCode(ctx context.Context, tx biz.Tx, code string) (*biz.Role, error) {
	var p rolePO
	err := r.d.dbOr(tx).WithContext(ctx).Where("code = ?", code).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.GetRole(ctx, tx, p.ID)
}

func (r *iamRepo) CreateRole(ctx context.Context, tx biz.Tx, role *biz.Role) (*biz.Role, error) {
	p := &rolePO{
		Code: role.Code, Name: role.Name, Description: role.Description,
		Builtin: role.Builtin, Status: role.Status, MaxMembers: role.MaxMembers,
		Revision: 1, CreationDelegationID: role.CreationDelegationID,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	role.ID, role.Revision = p.ID, p.Revision
	return role, nil
}

func (r *iamRepo) UpdateRole(ctx context.Context, tx biz.Tx, role *biz.Role, expected uint64) (*biz.Role, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	res := db.Model(&rolePO{}).Where("id = ? AND revision = ?", role.ID, expected).Updates(map[string]any{
		"name": role.Name, "description": role.Description, "status": role.Status,
		"max_members": role.MaxMembers, "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		var cur rolePO
		if err := db.Select("revision").Where("id = ?", role.ID).First(&cur).Error; err != nil {
			return nil, biz.ErrResourceNotFound
		}
		return nil, biz.ConflictRevision(cur.Revision)
	}
	return r.GetRole(ctx, tx, role.ID)
}

func (r *iamRepo) PutRoleGrants(ctx context.Context, tx biz.Tx, roleID int64, grants []biz.Grant, expected uint64) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var role rolePO
	if err := db.Where("id = ?", roleID).First(&role).Error; err != nil {
		return 0, biz.ErrResourceNotFound
	}
	if expected == 0 {
		expected = role.Revision
	}
	if role.Revision != expected {
		return role.Revision, biz.ConflictRevision(role.Revision)
	}
	if err := db.Where("role_id = ?", roleID).Delete(&roleGrantPO{}).Error; err != nil {
		return 0, err
	}
	for _, g := range grants {
		scope, err := jsonx.Marshal(g.Scope)
		if err != nil {
			return 0, err
		}
		if err := db.Create(&roleGrantPO{RoleID: roleID, Operation: g.Operation, Effect: string(g.Effect), Scope: string(scope)}).Error; err != nil {
			return 0, err
		}
	}
	if err := db.Model(&rolePO{}).Where("id = ?", roleID).Update("revision", gorm.Expr("revision + 1")).Error; err != nil {
		return 0, err
	}
	return expected + 1, nil
}

func (r *iamRepo) PutRoleInheritance(ctx context.Context, tx biz.Tx, roleID int64, inherits []int64, expected uint64) (uint64, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	var role rolePO
	if err := db.Where("id = ?", roleID).First(&role).Error; err != nil {
		return 0, biz.ErrResourceNotFound
	}
	if expected == 0 {
		expected = role.Revision
	}
	if role.Revision != expected {
		return role.Revision, biz.ConflictRevision(role.Revision)
	}
	if err := db.Where("role_id = ?", roleID).Delete(&roleInheritancePO{}).Error; err != nil {
		return 0, err
	}
	for _, id := range inherits {
		if err := db.Create(&roleInheritancePO{RoleID: roleID, InheritsID: id}).Error; err != nil {
			return 0, err
		}
	}
	if err := db.Model(&rolePO{}).Where("id = ?", roleID).Update("revision", gorm.Expr("revision + 1")).Error; err != nil {
		return 0, err
	}
	return expected + 1, nil
}

func assignmentToBiz(p assignmentPO) (*biz.Assignment, error) {
	var scope authorization.Scope
	if err := jsonx.Unmarshal([]byte(p.Boundary), &scope); err != nil {
		return nil, err
	}
	return &biz.Assignment{
		ID: p.ID, UserID: p.UserID, RoleID: p.RoleID, Boundary: scope,
		StartsAt: p.StartsAt.UTC(), ExpiresAt: p.ExpiresAt, Revoked: p.Status != "active",
		Origin: p.Origin, Revision: p.Revision, AssignedBy: p.AssignedBy, CreatedAt: p.CreatedAt.UTC(),
	}, nil
}

func (r *iamRepo) ListAssignmentsForUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.Assignment, error) {
	var rows []assignmentPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Assignment, 0, len(rows))
	for _, p := range rows {
		a, err := assignmentToBiz(p)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *iamRepo) GetAssignment(ctx context.Context, tx biz.Tx, id int64) (*biz.Assignment, error) {
	var p assignmentPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return assignmentToBiz(p)
}

func (r *iamRepo) CreateAssignment(ctx context.Context, tx biz.Tx, a *biz.Assignment) (*biz.Assignment, error) {
	scope, err := jsonx.Marshal(a.Boundary)
	if err != nil {
		return nil, err
	}
	p := &assignmentPO{
		UserID: a.UserID, RoleID: a.RoleID, Boundary: string(scope),
		StartsAt: a.StartsAt, ExpiresAt: a.ExpiresAt, Status: "active",
		Origin: a.Origin, Revision: 1, AssignedBy: a.AssignedBy, CreatedAt: a.CreatedAt,
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.StartsAt.IsZero() {
		p.StartsAt = p.CreatedAt
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return assignmentToBiz(*p)
}

func (r *iamRepo) RevokeAssignment(ctx context.Context, tx biz.Tx, id int64, expected uint64, by int64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).Where("id = ? AND revision = ?", id, expected).Updates(map[string]any{
		"status": "revoked", "revision": expected + 1, "assigned_by": by,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

func (r *iamRepo) ListAssignmentsForRole(ctx context.Context, tx biz.Tx, roleID int64) ([]*biz.Assignment, error) {
	var rows []assignmentPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id = ?", roleID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Assignment, 0, len(rows))
	for _, p := range rows {
		a, err := assignmentToBiz(p)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *iamRepo) CountActiveAssignmentsForRole(ctx context.Context, tx biz.Tx, roleID int64) (int64, error) {
	now := time.Now().UTC()
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).
		Where("role_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)", roleID, "active", now).Count(&n).Error
	return n, err
}

func (r *iamRepo) ListRoleMembers(ctx context.Context, tx biz.Tx, roleID int64) ([]biz.RoleMember, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	type row struct {
		UserID       int64
		Username     string
		DisplayName  string
		AssignmentID int64
		CreatedAt    time.Time
		ExpiresAt    *time.Time
		Origin       string
	}
	var rows []row
	err := db.Table("iam_user_roles AS ur").
		Select("ur.user_id, u.username, u.display_name, ur.id AS assignment_id, ur.created_at, ur.expires_at, ur.origin").
		Joins("JOIN users AS u ON u.id = ur.user_id").
		Where("ur.role_id = ? AND ur.status = ?", roleID, "active").
		Order("ur.id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]biz.RoleMember, 0, len(rows))
	for _, x := range rows {
		out = append(out, biz.RoleMember{
			UserID: x.UserID, Username: x.Username, DisplayName: x.DisplayName,
			AssignmentID: x.AssignmentID, AssignedAt: x.CreatedAt.UTC(),
			ExpiresAt: x.ExpiresAt, Origin: x.Origin,
		})
	}
	return out, nil
}

func constraintToBiz(p constraintPO) *biz.Constraint {
	var ids []int64
	_ = jsonx.Unmarshal([]byte(p.RoleIDs), &ids)
	return &biz.Constraint{ID: p.ID, Kind: p.Kind, Name: p.Name, RoleIDs: ids, MaxCount: p.MaxCount, Enabled: p.Enabled, Revision: p.Revision}
}

func (r *iamRepo) ListConstraints(ctx context.Context, tx biz.Tx) ([]*biz.Constraint, error) {
	var rows []constraintPO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Constraint, 0, len(rows))
	for _, p := range rows {
		out = append(out, constraintToBiz(p))
	}
	return out, nil
}

func (r *iamRepo) GetConstraint(ctx context.Context, tx biz.Tx, id int64) (*biz.Constraint, error) {
	var p constraintPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return constraintToBiz(p), nil
}

func (r *iamRepo) CreateConstraint(ctx context.Context, tx biz.Tx, c *biz.Constraint) (*biz.Constraint, error) {
	ids, _ := jsonx.Marshal(c.RoleIDs)
	p := &constraintPO{Kind: c.Kind, Name: c.Name, RoleIDs: string(ids), MaxCount: c.MaxCount, Enabled: c.Enabled, Revision: 1}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return constraintToBiz(*p), nil
}

func (r *iamRepo) UpdateConstraint(ctx context.Context, tx biz.Tx, c *biz.Constraint, expected uint64) (*biz.Constraint, error) {
	ids, _ := jsonx.Marshal(c.RoleIDs)
	res := r.d.dbOr(tx).WithContext(ctx).Model(&constraintPO{}).Where("id = ? AND revision = ?", c.ID, expected).Updates(map[string]any{
		"name": c.Name, "role_ids": string(ids), "max_count": c.MaxCount, "enabled": c.Enabled, "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetConstraint(ctx, tx, c.ID)
}

func (r *iamRepo) DeleteConstraint(ctx context.Context, tx biz.Tx, id int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).Delete(&constraintPO{}).Error
}

func (r *iamRepo) ListMenus(ctx context.Context, tx biz.Tx) ([]*biz.MenuItem, error) {
	var rows []menuPO
	if err := r.d.dbOr(tx).WithContext(ctx).Order("parent_id, sort, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.MenuItem, 0, len(rows))
	for _, p := range rows {
		out = append(out, menuToBiz(p))
	}
	return out, nil
}

func menuToBiz(p menuPO) *biz.MenuItem {
	var all, any []string
	_ = jsonx.Unmarshal([]byte(p.RequiredAll), &all)
	_ = jsonx.Unmarshal([]byte(p.RequiredAny), &any)
	return &biz.MenuItem{
		ID: p.ID, ParentID: p.ParentID, RouteKey: p.RouteKey, Name: p.Name,
		IconKey: p.IconKey, Sort: p.Sort, Enabled: p.Enabled,
		RequiredAll: all, RequiredAny: any, Revision: p.Revision,
	}
}

func (r *iamRepo) GetMenu(ctx context.Context, tx biz.Tx, id int64) (*biz.MenuItem, error) {
	var p menuPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return menuToBiz(p), nil
}

func (r *iamRepo) CreateMenu(ctx context.Context, tx biz.Tx, m *biz.MenuItem) (*biz.MenuItem, error) {
	all, _ := jsonx.Marshal(m.RequiredAll)
	anyJSON, _ := jsonx.Marshal(m.RequiredAny)
	p := &menuPO{
		ParentID: m.ParentID, RouteKey: m.RouteKey, Name: m.Name, IconKey: m.IconKey,
		Sort: m.Sort, Enabled: true, RequiredAll: string(all), RequiredAny: string(anyJSON), Revision: 1,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return menuToBiz(*p), nil
}

func (r *iamRepo) UpdateMenu(ctx context.Context, tx biz.Tx, m *biz.MenuItem, expected uint64) (*biz.MenuItem, error) {
	all, _ := jsonx.Marshal(m.RequiredAll)
	anyJSON, _ := jsonx.Marshal(m.RequiredAny)
	res := r.d.dbOr(tx).WithContext(ctx).Model(&menuPO{}).Where("id = ? AND revision = ?", m.ID, expected).Updates(map[string]any{
		"name": m.Name, "icon_key": m.IconKey, "sort": m.Sort, "enabled": m.Enabled,
		"required_all": string(all), "required_any": string(anyJSON), "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetMenu(ctx, tx, m.ID)
}
