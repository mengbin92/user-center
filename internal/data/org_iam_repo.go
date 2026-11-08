package data

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// orgIAMRepo implements tenant-scoped role and assignment storage. Every query
// carries the authorization context, so a caller that passes another tenant's
// identifiers can never read or mutate the row.
type orgIAMRepo struct{ d *Data }

func NewOrgIAMRepo(d *Data) biz.OrgIAMRepo { return &orgIAMRepo{d: d} }

func contextScope(c authorization.Context) (string, int64, error) {
	c = c.Normalize()
	if err := c.Validate(); err != nil {
		return "", 0, err
	}
	return c.Type, c.OrganizationID, nil
}

func roleContextFromPO(p *rolePO) authorization.Context {
	if p.ContextType == authorization.ContextTypeOrganization && p.ContextID > 0 {
		return authorization.Organization(p.ContextID)
	}
	return authorization.Platform()
}

func assignmentContextFromPO(p *assignmentPO) authorization.Context {
	if p.ContextType == authorization.ContextTypeOrganization && p.ContextID > 0 {
		return authorization.Organization(p.ContextID)
	}
	return authorization.Platform()
}

func (r *orgIAMRepo) scoped(ctx context.Context, tx biz.Tx, c authorization.Context, model any) (*gorm.DB, error) {
	typ, id, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	return r.d.dbOr(tx).WithContext(ctx).Model(model).
		Where("context_type = ? AND context_id = ?", typ, id), nil
}

func (r *orgIAMRepo) loadGrants(ctx context.Context, tx biz.Tx, roleIDs []int64) (map[int64][]biz.Grant, error) {
	out := map[int64][]biz.Grant{}
	if len(roleIDs) == 0 {
		return out, nil
	}
	var rows []roleGrantPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id IN ?", roleIDs).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, g := range rows {
		var scope authorization.Scope
		if err := jsonx.Unmarshal([]byte(g.Scope), &scope); err != nil {
			return nil, fmt.Errorf("decode role grant scope: %w", err)
		}
		out[g.RoleID] = append(out[g.RoleID], biz.Grant{
			Operation: g.Operation, Effect: authorization.Effect(g.Effect), Scope: scope,
		})
	}
	return out, nil
}

func (r *orgIAMRepo) ListRoles(ctx context.Context, tx biz.Tx, c authorization.Context) ([]*biz.Role, error) {
	db, err := r.scoped(ctx, tx, c, &rolePO{})
	if err != nil {
		return nil, err
	}
	var rows []rolePO
	if err := db.Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(rows))
	for i := range rows {
		ids = append(ids, rows[i].ID)
	}
	grants, err := r.loadGrants(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	var edges []roleInheritancePO
	if len(ids) > 0 {
		if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id IN ?", ids).Find(&edges).Error; err != nil {
			return nil, err
		}
	}
	inherits := map[int64][]int64{}
	for _, e := range edges {
		inherits[e.RoleID] = append(inherits[e.RoleID], e.InheritsID)
	}
	out := make([]*biz.Role, 0, len(rows))
	for i := range rows {
		p := rows[i]
		out = append(out, &biz.Role{
			ID: p.ID, Code: p.Code, Name: p.Name, Description: p.Description,
			Builtin: p.Builtin, Status: p.Status, MaxMembers: p.MaxMembers,
			Revision: p.Revision, CreationDelegationID: p.CreationDelegationID,
			Grants: grants[p.ID], Inherits: inherits[p.ID], Context: c.Normalize(),
		})
	}
	return out, nil
}

func (r *orgIAMRepo) GetRole(ctx context.Context, tx biz.Tx, c authorization.Context, id int64) (*biz.Role, error) {
	return r.getRole(ctx, tx, c, id, false)
}

// GetRoleForUpdate takes a row lock so concurrent assignments of the same role
// serialize their max_members and duplicate checks.
func (r *orgIAMRepo) GetRoleForUpdate(ctx context.Context, tx biz.Tx, c authorization.Context, id int64) (*biz.Role, error) {
	return r.getRole(ctx, tx, c, id, true)
}

func (r *orgIAMRepo) getRole(ctx context.Context, tx biz.Tx, c authorization.Context, id int64, lock bool) (*biz.Role, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	db := r.d.dbOr(tx).WithContext(ctx)
	if lock && (db.Dialector == nil || db.Dialector.Name() != "sqlite") {
		db = db.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate})
	}
	var p rolePO
	if err := db.Where("id = ? AND context_type = ? AND context_id = ?", id, typ, ctxID).First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, biz.ErrResourceNotFound
		}
		return nil, err
	}
	var grants []roleGrantPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id = ?", p.ID).Find(&grants).Error; err != nil {
		return nil, err
	}
	var edges []roleInheritancePO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("role_id = ?", p.ID).Find(&edges).Error; err != nil {
		return nil, err
	}
	out := &biz.Role{
		ID: p.ID, Code: p.Code, Name: p.Name, Description: p.Description,
		Builtin: p.Builtin, Status: p.Status, MaxMembers: p.MaxMembers,
		Revision: p.Revision, CreationDelegationID: p.CreationDelegationID,
		Context: c.Normalize(),
	}
	for _, g := range grants {
		var scope authorization.Scope
		if err := jsonx.Unmarshal([]byte(g.Scope), &scope); err != nil {
			return nil, fmt.Errorf("decode role grant scope: %w", err)
		}
		out.Grants = append(out.Grants, biz.Grant{Operation: g.Operation, Effect: authorization.Effect(g.Effect), Scope: scope})
	}
	for _, e := range edges {
		out.Inherits = append(out.Inherits, e.InheritsID)
	}
	return out, nil
}

func (r *orgIAMRepo) GetRoleByCode(ctx context.Context, tx biz.Tx, c authorization.Context, code string) (*biz.Role, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	var p rolePO
	err = r.d.dbOr(tx).WithContext(ctx).
		Where("context_type = ? AND context_id = ? AND code = ?", typ, ctxID, code).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.GetRole(ctx, tx, c, p.ID)
}

func (r *orgIAMRepo) CreateRole(ctx context.Context, tx biz.Tx, c authorization.Context, role *biz.Role) (*biz.Role, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	p := &rolePO{
		Code: role.Code, Name: role.Name, Description: role.Description,
		Builtin: role.Builtin, Status: role.Status, MaxMembers: role.MaxMembers,
		Revision: 1, ContextType: typ, ContextID: ctxID,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		// A concurrent first-write may have created the same (context, code).
		// Map it to the domain conflict so callers never see driver errors.
		if isDuplicateKeyError(err) {
			return nil, biz.ErrOrgRoleExists
		}
		return nil, err
	}
	role.ID, role.Revision, role.Context = p.ID, p.Revision, c.Normalize()
	return role, nil
}

func (r *orgIAMRepo) UpdateRole(ctx context.Context, tx biz.Tx, c authorization.Context, role *biz.Role, expected uint64) (*biz.Role, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	res := r.d.dbOr(tx).WithContext(ctx).Model(&rolePO{}).
		Where("id = ? AND context_type = ? AND context_id = ? AND revision = ?", role.ID, typ, ctxID, expected).
		Updates(map[string]any{
			"name": role.Name, "description": role.Description, "status": role.Status,
			"max_members": role.MaxMembers, "revision": expected + 1,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetRole(ctx, tx, c, role.ID)
}

func (r *orgIAMRepo) PutRoleGrants(ctx context.Context, tx biz.Tx, c authorization.Context, roleID int64, grants []biz.Grant, expected uint64) (uint64, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return 0, biz.ErrAuthorizationDown
	}
	db := r.d.dbOr(tx).WithContext(ctx)
	var role rolePO
	if err := db.Where("id = ? AND context_type = ? AND context_id = ?", roleID, typ, ctxID).First(&role).Error; err != nil {
		return 0, biz.ErrResourceNotFound
	}
	if expected == 0 {
		expected = role.Revision
	}
	res := db.Model(&rolePO{}).
		Where("id = ? AND context_type = ? AND context_id = ? AND revision = ?", roleID, typ, ctxID, expected).
		Update("revision", expected+1)
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
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
		if err := db.Create(&roleGrantPO{
			RoleID: roleID, Operation: g.Operation, Effect: string(g.Effect), Scope: string(scope),
		}).Error; err != nil {
			return 0, err
		}
	}
	return expected + 1, nil
}

func (r *orgIAMRepo) ListAssignments(ctx context.Context, tx biz.Tx, c authorization.Context, userID int64) ([]*biz.AssignmentItem, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	db := r.d.dbOr(tx).WithContext(ctx).Table("iam_user_roles AS ur").
		Joins("JOIN users AS u ON u.id = ur.user_id").
		Joins("JOIN iam_roles AS r ON r.id = ur.role_id").
		Where("ur.context_type = ? AND ur.context_id = ?", typ, ctxID).
		Where("r.context_type = ? AND r.context_id = ?", typ, ctxID)
	if userID > 0 {
		db = db.Where("ur.user_id = ?", userID)
	}
	type row struct {
		ID, UserID, RoleID                        int64
		Username, DisplayName, RoleCode, RoleName string
		Boundary                                  string
		StartsAt                                  time.Time
		ExpiresAt                                 *time.Time
		Status, Origin                            string
		Revision                                  uint64
		AssignedBy                                int64
		CreatedAt                                 time.Time
	}
	var rows []row
	err = db.Select("ur.id, ur.user_id, ur.role_id, u.username, u.display_name, r.code AS role_code, r.name AS role_name, ur.boundary, ur.starts_at, ur.expires_at, ur.status, ur.origin, ur.revision, ur.assigned_by, ur.created_at").
		Order("ur.id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*biz.AssignmentItem, 0, len(rows))
	for _, x := range rows {
		var scope authorization.Scope
		if err := jsonx.Unmarshal([]byte(x.Boundary), &scope); err != nil {
			return nil, err
		}
		out = append(out, &biz.AssignmentItem{
			Username: x.Username, DisplayName: x.DisplayName,
			RoleCode: x.RoleCode, RoleName: x.RoleName,
			Assignment: &biz.Assignment{
				ID: x.ID, UserID: x.UserID, RoleID: x.RoleID, Boundary: scope,
				StartsAt: x.StartsAt.UTC(), ExpiresAt: x.ExpiresAt, Revoked: x.Status != "active",
				Origin: x.Origin, Revision: x.Revision, AssignedBy: x.AssignedBy,
				CreatedAt: x.CreatedAt.UTC(), Context: c.Normalize(),
			},
		})
	}
	return out, nil
}

func (r *orgIAMRepo) GetAssignment(ctx context.Context, tx biz.Tx, c authorization.Context, id int64) (*biz.Assignment, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	var p assignmentPO
	err = r.d.dbOr(tx).WithContext(ctx).
		Where("id = ? AND context_type = ? AND context_id = ?", id, typ, ctxID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return assignmentToBiz(p)
}

func (r *orgIAMRepo) CreateAssignment(ctx context.Context, tx biz.Tx, c authorization.Context, a *biz.Assignment) (*biz.Assignment, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return nil, biz.ErrAuthorizationDown
	}
	scope, err := jsonx.Marshal(a.Boundary)
	if err != nil {
		return nil, err
	}
	p := &assignmentPO{
		UserID: a.UserID, RoleID: a.RoleID, Boundary: string(scope),
		StartsAt: a.StartsAt, ExpiresAt: a.ExpiresAt, Status: "active",
		Origin: a.Origin, Revision: 1, AssignedBy: a.AssignedBy, CreatedAt: a.CreatedAt,
		ContextType: typ, ContextID: ctxID,
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

func (r *orgIAMRepo) RevokeAssignment(ctx context.Context, tx biz.Tx, c authorization.Context, id int64, expected uint64, by int64) error {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return biz.ErrAuthorizationDown
	}
	res := r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).
		Where("id = ? AND context_type = ? AND context_id = ? AND revision = ?", id, typ, ctxID, expected).
		Updates(map[string]any{"status": "revoked", "revision": expected + 1, "assigned_by": by})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

// RevokeMemberAssignments revokes the member's active assignments in the
// context. A non-empty roleIDs restricts the operation to those roles, which is
// how a membership role change replaces only the built-in role.
func (r *orgIAMRepo) RevokeMemberAssignments(ctx context.Context, tx biz.Tx, c authorization.Context, userID int64, roleIDs []int64, by int64) (int64, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return 0, biz.ErrAuthorizationDown
	}
	db := r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).
		Where("user_id = ? AND context_type = ? AND context_id = ? AND status = ?", userID, typ, ctxID, "active")
	if len(roleIDs) > 0 {
		db = db.Where("role_id IN ?", roleIDs)
	}
	res := db.Updates(map[string]any{"status": "revoked", "revision": gorm.Expr("revision + 1"), "assigned_by": by})
	return res.RowsAffected, res.Error
}

func (r *orgIAMRepo) CountActiveAssignments(ctx context.Context, tx biz.Tx, c authorization.Context, roleID int64) (int64, error) {
	typ, ctxID, err := contextScope(c)
	if err != nil {
		return 0, biz.ErrAuthorizationDown
	}
	var n int64
	err = r.d.dbOr(tx).WithContext(ctx).Model(&assignmentPO{}).
		Where("role_id = ? AND context_type = ? AND context_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)", roleID, typ, ctxID, "active", time.Now().UTC()).
		Count(&n).Error
	return n, err
}

// RevokeDelegationsForUser soft-invalidates the delegations that involve a user
// in this organization, in both directions.
//
// Target side: the delegation names the user in target_user_scope. The scope is
// parsed and compared by ID, not by LIKE: `target_user_scope LIKE '%2%'` also
// matched the delegation that only mentioned user 21, silently cutting off a
// third party.
//
// Manager side: a delegation is issued *from a role*, so it is revoked when the
// removal leaves that role with no active holder in the tenant -- the delegation
// can no longer authorise anything, and leaving it alive would let the removed
// member reactivate it simply by rejoining and being granted the same role
// again (D10: re-joining must not restore a delegation).
//
// What this deliberately does NOT do:
//
//   - revoke a shared role's delegation just because one holder left; the other
//     holders still need it (that was the "created_by == userID" shortcut, which
//     also conflated the issuer with the manager -- an owner issuing a delegation
//     for somebody else's role never matched);
//   - overwrite created_by, which is the record of who issued it.
//
// Delegations are revoked, not deleted (D10): an incident review needs to see
// that the delegation existed and when it stopped being valid.
func (r *orgIAMRepo) RevokeDelegationsForUser(ctx context.Context, tx biz.Tx, c authorization.Context, userID int64, managerRoleIDs []int64, by int64) (int64, error) {
	if userID == 0 || !c.IsOrganization() {
		return 0, nil
	}
	db := r.d.dbOr(tx).WithContext(ctx)

	// Which of the removed roles have no holder left? Computed after the
	// assignments were revoked, in the same transaction.
	orphaned := make(map[int64]bool, len(managerRoleIDs))
	for _, roleID := range managerRoleIDs {
		var holders int64
		if err := db.Model(&assignmentPO{}).
			Where("role_id = ? AND context_type = ? AND context_id = ? AND status = ?",
				roleID, authorization.ContextTypeOrganization, c.OrganizationID, "active").
			Count(&holders).Error; err != nil {
			return 0, err
		}
		orphaned[roleID] = holders == 0
	}

	// Candidates are read per context, then filtered in Go: an exact match
	// against a JSON column has no portable SQL form (MySQL and SQLite spell the
	// JSON functions differently), and a tenant's delegation set is small.
	var rows []delegationPO
	if err := db.Where("context_type = ? AND context_id = ? AND revoked_at IS NULL",
		authorization.ContextTypeOrganization, c.OrganizationID).Find(&rows).Error; err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	ids := make([]int64, 0, 4)
	for i := range rows {
		targets, err := delegationTargetsUser(rows[i].TargetUserScope, userID)
		if err != nil {
			// A malformed scope must not authorise a revocation. Skip it and let
			// the operator see the broken row rather than widen the blast radius.
			continue
		}
		if targets || orphaned[rows[i].ManagerRoleID] {
			ids = append(ids, rows[i].ID)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res := db.Model(&delegationPO{}).Where("id IN ?", ids).
		Updates(map[string]any{"revoked_at": now})
	return res.RowsAffected, res.Error
}

// delegationTargetsUser reports whether the scope names userID exactly.
func delegationTargetsUser(raw string, userID int64) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, nil
	}
	var scope authorization.Scope
	if err := jsonx.Unmarshal([]byte(raw), &scope); err != nil {
		return false, err
	}
	if scope.All {
		// "everyone in the tenant" includes this user by construction.
		return true, nil
	}
	return slices.Contains(scope.UserIDs, userID), nil
}
