package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
)

type organizationRepo struct{ d *Data }

func NewOrganizationRepo(d *Data) biz.OrganizationRepo { return &organizationRepo{d: d} }

func orgToBiz(p *organizationPO) *biz.Organization {
	return &biz.Organization{
		ID: p.ID, Code: p.Code, Name: p.Name, Status: p.Status,
		Revision: p.Revision, CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt.UTC(),
		UpdatedAt: p.UpdatedAt.UTC(), ArchivedAt: p.ArchivedAt,
	}
}

func (r *organizationRepo) CreateOrganization(ctx context.Context, tx biz.Tx, org *biz.Organization) (*biz.Organization, error) {
	now := time.Now().UTC()
	p := &organizationPO{
		Code: org.Code, Name: org.Name, Status: biz.OrgStatusActive,
		Revision: 1, CreatedBy: org.CreatedBy, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return orgToBiz(p), nil
}

func (r *organizationRepo) GetOrganization(ctx context.Context, tx biz.Tx, id int64) (*biz.Organization, error) {
	var p organizationPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return orgToBiz(&p), nil
}

func (r *organizationRepo) GetOrganizationByCode(ctx context.Context, tx biz.Tx, code string) (*biz.Organization, error) {
	var p organizationPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("code = ?", code).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return orgToBiz(&p), nil
}

func (r *organizationRepo) ListOrganizationsForUser(ctx context.Context, tx biz.Tx, userID int64) ([]*biz.Organization, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	type row struct {
		ID          int64
		Code        string
		Name        string
		Status      string
		Revision    uint64
		CreatedBy   int64
		CreatedAt   time.Time
		UpdatedAt   time.Time
		ArchivedAt  *time.Time
		Role        string
		MemberCount int64
	}
	var rows []row
	err := db.Table("organization_members AS m").
		Select("o.id, o.code, o.name, o.status, o.revision, o.created_by, o.created_at, o.updated_at, o.archived_at, m.role, (SELECT COUNT(*) FROM organization_members mm WHERE mm.organization_id = o.id AND mm.status = 'active') AS member_count").
		Joins("JOIN organizations AS o ON o.id = m.organization_id").
		Where("m.user_id = ? AND m.status = ? AND o.status = ?", userID, biz.OrgMemberActive, biz.OrgStatusActive).
		Order("o.id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*biz.Organization, 0, len(rows))
	for _, x := range rows {
		out = append(out, &biz.Organization{
			ID: x.ID, Code: x.Code, Name: x.Name, Status: x.Status, Revision: x.Revision,
			CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt.UTC(), UpdatedAt: x.UpdatedAt.UTC(),
			ArchivedAt: x.ArchivedAt, Role: x.Role, MemberCount: x.MemberCount,
		})
	}
	return out, nil
}

func (r *organizationRepo) ListAllOrganizations(ctx context.Context, tx biz.Tx, status string) ([]*biz.Organization, error) {
	db := r.d.dbOr(tx).WithContext(ctx).Model(&organizationPO{})
	if status != "" {
		db = db.Where("status = ?", status)
	}
	var rows []organizationPO
	if err := db.Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Organization, 0, len(rows))
	for i := range rows {
		org := orgToBiz(&rows[i])
		_ = r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
			Where("organization_id = ? AND status = ?", org.ID, biz.OrgMemberActive).Count(&org.MemberCount).Error
		out = append(out, org)
	}
	return out, nil
}

func (r *organizationRepo) UpdateOrganization(ctx context.Context, tx biz.Tx, org *biz.Organization, expected uint64) (*biz.Organization, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationPO{}).Where("id = ? AND revision = ?", org.ID, expected).Updates(map[string]any{
		"name": org.Name, "revision": expected + 1, "updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetOrganization(ctx, tx, org.ID)
}

func (r *organizationRepo) ArchiveOrganization(ctx context.Context, tx biz.Tx, id int64, expected uint64) error {
	now := time.Now().UTC()
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationPO{}).Where("id = ? AND revision = ? AND status = ?", id, expected, biz.OrgStatusActive).Updates(map[string]any{
		"status": biz.OrgStatusArchived, "archived_at": now, "revision": expected + 1, "updated_at": now,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

func (r *organizationRepo) CountOrganizations(ctx context.Context, tx biz.Tx) (int64, error) {
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&organizationPO{}).Count(&n).Error
	return n, err
}

func (r *organizationRepo) GetMember(ctx context.Context, tx biz.Tx, orgID, userID int64) (*biz.OrganizationMember, error) {
	var p organizationMemberPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("organization_id = ? AND user_id = ?", orgID, userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return memberToBiz(&p), nil
}

func memberToBiz(p *organizationMemberPO) *biz.OrganizationMember {
	return &biz.OrganizationMember{
		ID: p.ID, OrganizationID: p.OrganizationID, UserID: p.UserID,
		Role: p.Role, DepartmentID: p.DepartmentID, Status: p.Status,
		Revision: p.Revision, InvitedBy: p.InvitedBy, JoinedAt: p.JoinedAt.UTC(),
	}
}

func (r *organizationRepo) ListMembers(ctx context.Context, tx biz.Tx, orgID int64) ([]*biz.OrganizationMember, error) {
	db := r.d.dbOr(tx).WithContext(ctx)
	type row struct {
		organizationMemberPO
		Username    string
		DisplayName string
		Email       *string
	}
	var rows []row
	err := db.Table("organization_members AS m").
		Select("m.*, u.username, u.display_name, u.email").
		Joins("JOIN users AS u ON u.id = m.user_id").
		Where("m.organization_id = ? AND m.status = ?", orgID, biz.OrgMemberActive).
		Order("CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.id").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*biz.OrganizationMember, 0, len(rows))
	for i := range rows {
		m := memberToBiz(&rows[i].organizationMemberPO)
		m.Username, m.DisplayName = rows[i].Username, rows[i].DisplayName
		if rows[i].Email != nil {
			m.Email = *rows[i].Email
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *organizationRepo) AddMember(ctx context.Context, tx biz.Tx, m *biz.OrganizationMember) (*biz.OrganizationMember, error) {
	now := time.Now().UTC()
	p := &organizationMemberPO{
		OrganizationID: m.OrganizationID, UserID: m.UserID, Role: m.Role,
		DepartmentID: m.DepartmentID, Status: biz.OrgMemberActive,
		Revision: 1, InvitedBy: m.InvitedBy, JoinedAt: now, UpdatedAt: now,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return memberToBiz(p), nil
}

func (r *organizationRepo) RestoreMember(ctx context.Context, tx biz.Tx, orgID, userID int64, role string, departmentID *int64, by int64) (*biz.OrganizationMember, error) {
	now := time.Now().UTC()
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND user_id = ? AND status = ?", orgID, userID, biz.OrgMemberRemoved).
		Updates(map[string]any{
			"status": biz.OrgMemberActive, "role": role, "department_id": departmentID,
			"revision": gorm.Expr("revision + 1"), "invited_by": by,
			"joined_at": now, "updated_at": now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ErrResourceNotFound
	}
	return r.GetMember(ctx, tx, orgID, userID)
}

func (r *organizationRepo) UpdateMember(ctx context.Context, tx biz.Tx, m *biz.OrganizationMember, expected uint64) (*biz.OrganizationMember, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND user_id = ? AND revision = ?", m.OrganizationID, m.UserID, expected).
		Updates(map[string]any{
			"role": m.Role, "department_id": m.DepartmentID,
			"revision": expected + 1, "updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetMember(ctx, tx, m.OrganizationID, m.UserID)
}

func (r *organizationRepo) RemoveMember(ctx context.Context, tx biz.Tx, orgID, userID int64, expected uint64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND user_id = ? AND revision = ? AND status = ?", orgID, userID, expected, biz.OrgMemberActive).
		Updates(map[string]any{"status": biz.OrgMemberRemoved, "revision": expected + 1, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}

func (r *organizationRepo) CountActiveOwners(ctx context.Context, tx biz.Tx, orgID int64) (int64, error) {
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND role = ? AND status = ?", orgID, biz.OrgRoleOwner, biz.OrgMemberActive).Count(&n).Error
	return n, err
}

func (r *organizationRepo) CountActiveMembers(ctx context.Context, tx biz.Tx, orgID int64) (int64, error) {
	var n int64
	err := r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND status = ?", orgID, biz.OrgMemberActive).Count(&n).Error
	return n, err
}

func deptToBiz(p *organizationDepartmentPO) *biz.Department {
	return &biz.Department{
		ID: p.ID, OrganizationID: p.OrganizationID, ParentID: p.ParentID,
		Code: p.Code, Name: p.Name, Status: p.Status, Revision: p.Revision,
		CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
	}
}

func (r *organizationRepo) ListDepartments(ctx context.Context, tx biz.Tx, orgID int64) ([]*biz.Department, error) {
	var rows []organizationDepartmentPO
	if err := r.d.dbOr(tx).WithContext(ctx).Where("organization_id = ? AND status = ?", orgID, "active").Order("parent_id, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.Department, 0, len(rows))
	for i := range rows {
		out = append(out, deptToBiz(&rows[i]))
	}
	return out, nil
}

func (r *organizationRepo) GetDepartment(ctx context.Context, tx biz.Tx, orgID, id int64) (*biz.Department, error) {
	var p organizationDepartmentPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ? AND organization_id = ?", id, orgID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return deptToBiz(&p), nil
}

func (r *organizationRepo) CreateDepartment(ctx context.Context, tx biz.Tx, d *biz.Department) (*biz.Department, error) {
	now := time.Now().UTC()
	p := &organizationDepartmentPO{
		OrganizationID: d.OrganizationID, ParentID: d.ParentID, Code: d.Code,
		Name: d.Name, Status: "active", Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return deptToBiz(p), nil
}

func (r *organizationRepo) UpdateDepartment(ctx context.Context, tx biz.Tx, d *biz.Department, expected uint64) (*biz.Department, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationDepartmentPO{}).
		Where("id = ? AND organization_id = ? AND revision = ?", d.ID, d.OrganizationID, expected).
		Updates(map[string]any{
			"parent_id": d.ParentID, "code": d.Code, "name": d.Name,
			"revision": expected + 1, "updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetDepartment(ctx, tx, d.OrganizationID, d.ID)
}

func (r *organizationRepo) ClearDepartmentMembers(ctx context.Context, tx biz.Tx, orgID, deptID int64) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&organizationMemberPO{}).
		Where("organization_id = ? AND department_id = ? AND status = ?", orgID, deptID, biz.OrgMemberActive).
		Update("department_id", nil).Error
}

func (r *organizationRepo) ArchiveDepartment(ctx context.Context, tx biz.Tx, orgID, id int64, expected uint64) error {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&organizationDepartmentPO{}).
		Where("id = ? AND organization_id = ? AND revision = ? AND status = ?", id, orgID, expected, "active").
		Updates(map[string]any{"status": "archived", "revision": expected + 1, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return biz.ConflictRevision(expected)
	}
	return nil
}
