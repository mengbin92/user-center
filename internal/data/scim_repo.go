package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
)

// scimRepo owns every SCIM table. All reads and writes carry the organization
// id that came from the authenticated bearer token; there is no method here
// that can enumerate across tenants.
type scimRepo struct{ d *Data }

func NewSCIMRepo(d *Data) biz.SCIMRepo { return &scimRepo{d: d} }

func scimTokenToBiz(p scimTokenPO) *biz.SCIMToken {
	return &biz.SCIMToken{
		ID: p.ID, OrganizationID: p.OrganizationID, Name: p.Name,
		TokenHash: p.TokenHash, Status: p.Status,
		CredentialVersion: p.CredentialVersion, Revision: p.Revision,
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
		LastUsedAt: p.LastUsedAt, DisabledAt: p.DisabledAt,
	}
}

func (r *scimRepo) CreateToken(ctx context.Context, tx biz.Tx, t *biz.SCIMToken) (*biz.SCIMToken, error) {
	p := &scimTokenPO{
		OrganizationID: t.OrganizationID, Name: t.Name, TokenHash: t.TokenHash,
		Status: t.Status, CredentialVersion: t.CredentialVersion, Revision: t.Revision,
		CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return scimTokenToBiz(*p), nil
}

func (r *scimRepo) GetToken(ctx context.Context, tx biz.Tx, id int64) (*biz.SCIMToken, error) {
	var p scimTokenPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return scimTokenToBiz(p), nil
}

func (r *scimRepo) FindTokenByHash(ctx context.Context, tx biz.Tx, hash string) (*biz.SCIMToken, error) {
	var p scimTokenPO
	err := r.d.dbOr(tx).WithContext(ctx).Where("token_hash = ?", hash).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return scimTokenToBiz(p), nil
}

func (r *scimRepo) ListTokens(ctx context.Context, tx biz.Tx, orgID int64) ([]*biz.SCIMToken, error) {
	var rows []scimTokenPO
	if err := r.d.dbOr(tx).WithContext(ctx).
		Where("organization_id = ?", orgID).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.SCIMToken, 0, len(rows))
	for _, p := range rows {
		out = append(out, scimTokenToBiz(p))
	}
	return out, nil
}

func (r *scimRepo) UpdateToken(ctx context.Context, tx biz.Tx, t *biz.SCIMToken, expected uint64) (*biz.SCIMToken, error) {
	res := r.d.dbOr(tx).WithContext(ctx).Model(&scimTokenPO{}).
		Where("id = ? AND revision = ?", t.ID, expected).Updates(map[string]any{
		"name": t.Name, "token_hash": t.TokenHash, "status": t.Status,
		"credential_version": t.CredentialVersion, "disabled_at": t.DisabledAt,
		"updated_at": t.UpdatedAt, "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetToken(ctx, tx, t.ID)
}

func (r *scimRepo) TouchToken(ctx context.Context, tx biz.Tx, id int64, at time.Time) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&scimTokenPO{}).
		Where("id = ?", id).Update("last_used_at", at).Error
}

func scimIdentityToBiz(p scimIdentityPO) *biz.SCIMIdentity {
	return &biz.SCIMIdentity{
		ID: p.ID, OrganizationID: p.OrganizationID, Kind: p.Kind,
		ExternalID: p.ExternalID, LocalID: p.LocalID, Revision: p.Revision,
	}
}

func (r *scimRepo) GetIdentityByExternal(ctx context.Context, tx biz.Tx, orgID int64, kind, externalID string) (*biz.SCIMIdentity, error) {
	var p scimIdentityPO
	err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("organization_id = ? AND kind = ? AND external_id = ?", orgID, kind, externalID).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return scimIdentityToBiz(p), nil
}

func (r *scimRepo) GetIdentityByLocal(ctx context.Context, tx biz.Tx, orgID int64, kind string, localID int64) (*biz.SCIMIdentity, error) {
	var p scimIdentityPO
	err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("organization_id = ? AND kind = ? AND local_id = ?", orgID, kind, localID).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return scimIdentityToBiz(p), nil
}

func (r *scimRepo) ListIdentities(ctx context.Context, tx biz.Tx, orgID int64, kind string) ([]*biz.SCIMIdentity, error) {
	var rows []scimIdentityPO
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("organization_id = ? AND kind = ?", orgID, kind).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.SCIMIdentity, 0, len(rows))
	for _, p := range rows {
		out = append(out, scimIdentityToBiz(p))
	}
	return out, nil
}

func (r *scimRepo) UpsertIdentity(ctx context.Context, tx biz.Tx, in *biz.SCIMIdentity) (*biz.SCIMIdentity, error) {
	db := r.d.tenantOr(ctx, tx).WithContext(ctx)
	now := time.Now().UTC()
	var existing scimIdentityPO
	err := db.Where("organization_id = ? AND kind = ? AND local_id = ?", in.OrganizationID, in.Kind, in.LocalID).
		First(&existing).Error
	if err == nil {
		res := db.Model(&scimIdentityPO{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"external_id": in.ExternalID, "revision": existing.Revision + 1, "updated_at": now,
		})
		if res.Error != nil {
			return nil, res.Error
		}
		existing.ExternalID = in.ExternalID
		existing.Revision++
		return scimIdentityToBiz(existing), nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	p := &scimIdentityPO{
		OrganizationID: in.OrganizationID, Kind: in.Kind, ExternalID: in.ExternalID,
		LocalID: in.LocalID, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(p).Error; err != nil {
		return nil, err
	}
	return scimIdentityToBiz(*p), nil
}

func (r *scimRepo) DeleteIdentity(ctx context.Context, tx biz.Tx, orgID int64, kind string, localID int64) error {
	return r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("organization_id = ? AND kind = ? AND local_id = ?", orgID, kind, localID).
		Delete(&scimIdentityPO{}).Error
}

func scimGroupToBiz(p scimGroupPO) *biz.SCIMGroup {
	return &biz.SCIMGroup{
		ID: p.ID, OrganizationID: p.OrganizationID, DisplayName: p.DisplayName, Revision: p.Revision,
	}
}

func (r *scimRepo) CreateGroup(ctx context.Context, tx biz.Tx, g *biz.SCIMGroup) (*biz.SCIMGroup, error) {
	now := time.Now().UTC()
	p := &scimGroupPO{
		OrganizationID: g.OrganizationID, DisplayName: g.DisplayName,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return scimGroupToBiz(*p), nil
}

func (r *scimRepo) GetGroup(ctx context.Context, tx biz.Tx, orgID, id int64) (*biz.SCIMGroup, error) {
	var p scimGroupPO
	err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("id = ? AND organization_id = ?", id, orgID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return scimGroupToBiz(p), nil
}

func (r *scimRepo) ListGroups(ctx context.Context, tx biz.Tx, orgID int64) ([]*biz.SCIMGroup, error) {
	var rows []scimGroupPO
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("organization_id = ?", orgID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.SCIMGroup, 0, len(rows))
	for _, p := range rows {
		out = append(out, scimGroupToBiz(p))
	}
	return out, nil
}

func (r *scimRepo) UpdateGroup(ctx context.Context, tx biz.Tx, g *biz.SCIMGroup, expected uint64) (*biz.SCIMGroup, error) {
	res := r.d.tenantOr(ctx, tx).WithContext(ctx).Model(&scimGroupPO{}).
		Where("id = ? AND organization_id = ? AND revision = ?", g.ID, g.OrganizationID, expected).
		Updates(map[string]any{
			"display_name": g.DisplayName, "revision": expected + 1, "updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetGroup(ctx, tx, g.OrganizationID, g.ID)
}

func (r *scimRepo) DeleteGroup(ctx context.Context, tx biz.Tx, orgID, id int64) error {
	return r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("id = ? AND organization_id = ?", id, orgID).Delete(&scimGroupPO{}).Error
}

func (r *scimRepo) SetGroupMembers(ctx context.Context, tx biz.Tx, groupID int64, ids []int64) error {
	db := r.d.tenantOr(ctx, tx).WithContext(ctx)
	if err := db.Where("group_id = ?", groupID).Delete(&scimGroupMemberPO{}).Error; err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	seen := map[int64]bool{}
	rows := make([]scimGroupMemberPO, 0, len(ids))
	for _, uid := range ids {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		rows = append(rows, scimGroupMemberPO{GroupID: groupID, UserID: uid})
	}
	return db.Create(&rows).Error
}

func (r *scimRepo) GroupMembers(ctx context.Context, tx biz.Tx, groupID int64) ([]int64, error) {
	var rows []scimGroupMemberPO
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("group_id = ?", groupID).Order("user_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(rows))
	for _, p := range rows {
		out = append(out, p.UserID)
	}
	return out, nil
}
