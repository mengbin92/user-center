package data

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type directoryRepo struct{ d *Data }

func NewDirectoryRepo(d *Data) biz.DirectoryRepo { return &directoryRepo{d: d} }

func directorySourceToBiz(p directorySourcePO) (*biz.DirectorySource, error) {
	var cfg biz.DirectoryConfig
	if err := jsonx.Unmarshal([]byte(p.ConfigJSON), &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	return &biz.DirectorySource{
		ID: p.ID, OrganizationID: p.OrganizationID, Kind: p.Kind, Name: p.Name,
		Config: cfg, SecretEnc: p.SecretEnc, Status: p.Status, Cursor: p.CursorValue,
		Revision: p.Revision, CreatedBy: p.CreatedBy,
		CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(), LastRunAt: p.LastRunAt,
	}, nil
}

func (r *directoryRepo) CreateSource(ctx context.Context, tx biz.Tx, s *biz.DirectorySource) (*biz.DirectorySource, error) {
	cfg, err := jsonx.Marshal(s.Config)
	if err != nil {
		return nil, err
	}
	p := &directorySourcePO{
		OrganizationID: s.OrganizationID, Kind: s.Kind, Name: s.Name,
		ConfigJSON: string(cfg), SecretEnc: s.SecretEnc, Status: s.Status,
		CursorValue: s.Cursor, Revision: 1, CreatedBy: s.CreatedBy,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	if err := r.d.dbOr(tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return directorySourceToBiz(*p)
}

func (r *directoryRepo) GetSource(ctx context.Context, tx biz.Tx, id int64) (*biz.DirectorySource, error) {
	var p directorySourcePO
	err := r.d.dbOr(tx).WithContext(ctx).Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return directorySourceToBiz(p)
}

func (r *directoryRepo) ListSources(ctx context.Context, tx biz.Tx, orgID int64) ([]*biz.DirectorySource, error) {
	var rows []directorySourcePO
	if err := r.d.dbOr(tx).WithContext(ctx).
		Where("organization_id = ?", orgID).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.DirectorySource, 0, len(rows))
	for _, p := range rows {
		s, err := directorySourceToBiz(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// DueSources returns active sources whose interval has elapsed, or that never
// ran. A NULL last_run_at sorts first in MySQL and SQLite, so a newly created
// source is picked up on the next tick.
func (r *directoryRepo) DueSources(ctx context.Context, tx biz.Tx, now time.Time, limit int) ([]*biz.DirectorySource, error) {
	var rows []directorySourcePO
	if err := r.d.dbOr(tx).WithContext(ctx).
		Where("status = ? AND (last_run_at IS NULL OR last_run_at <= ?)", biz.DirectoryStatusActive, now).
		Order("last_run_at ASC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.DirectorySource, 0, len(rows))
	for _, p := range rows {
		s, err := directorySourceToBiz(p)
		if err != nil {
			continue
		}
		interval := time.Duration(s.Config.Interval) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		if s.LastRunAt != nil && now.Sub(s.LastRunAt.UTC()) < interval {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *directoryRepo) UpdateSource(ctx context.Context, tx biz.Tx, s *biz.DirectorySource, expected uint64) (*biz.DirectorySource, error) {
	cfg, err := jsonx.Marshal(s.Config)
	if err != nil {
		return nil, err
	}
	res := r.d.dbOr(tx).WithContext(ctx).Model(&directorySourcePO{}).
		Where("id = ? AND revision = ?", s.ID, expected).Updates(map[string]any{
		"config_json": string(cfg), "secret_enc": s.SecretEnc, "status": s.Status,
		"cursor_value": s.Cursor, "updated_at": s.UpdatedAt, "revision": expected + 1,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, biz.ConflictRevision(expected)
	}
	return r.GetSource(ctx, tx, s.ID)
}

func (r *directoryRepo) UpdateCursor(ctx context.Context, tx biz.Tx, id int64, cursor string, at time.Time) error {
	return r.d.dbOr(tx).WithContext(ctx).Model(&directorySourcePO{}).
		Where("id = ?", id).Updates(map[string]any{
		"cursor_value": cursor, "last_run_at": at, "updated_at": at,
	}).Error
}

func directoryRunToBiz(p directoryRunPO) (*biz.DirectoryRun, error) {
	out := &biz.DirectoryRun{
		ID: p.ID, SourceID: p.SourceID, OrganizationID: p.OrganizationID,
		Mode: p.Mode, Status: p.Status, StartedAt: p.StartedAt.UTC(), FinishedAt: p.FinishedAt,
		Fetched: p.Fetched, Created: p.CreatedCount, Updated: p.UpdatedCount,
		Disabled: p.DisabledCount, Unchanged: p.UnchangedCount, Failed: p.FailedCount,
		CursorBefore: p.CursorBefore, CursorAfter: p.CursorAfter, ErrorText: p.ErrorText,
	}
	if p.ReportJSON != "" {
		if err := jsonx.Unmarshal([]byte(p.ReportJSON), &out.Report); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *directoryRepo) CreateRun(ctx context.Context, tx biz.Tx, run *biz.DirectoryRun) (*biz.DirectoryRun, error) {
	p := &directoryRunPO{
		SourceID: run.SourceID, OrganizationID: run.OrganizationID,
		Mode: run.Mode, Status: run.Status, StartedAt: run.StartedAt,
		CursorBefore: run.CursorBefore,
	}
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).Create(p).Error; err != nil {
		return nil, err
	}
	return directoryRunToBiz(*p)
}

func (r *directoryRepo) FinishRun(ctx context.Context, tx biz.Tx, run *biz.DirectoryRun) error {
	report, err := jsonx.Marshal(run.Report)
	if err != nil {
		return err
	}
	return r.d.tenantOr(ctx, tx).WithContext(ctx).Model(&directoryRunPO{}).
		Where("id = ?", run.ID).Updates(map[string]any{
		"status": run.Status, "finished_at": run.FinishedAt,
		"fetched": run.Fetched, "created_count": run.Created, "updated_count": run.Updated,
		"disabled_count": run.Disabled, "unchanged_count": run.Unchanged, "failed_count": run.Failed,
		"cursor_before": run.CursorBefore, "cursor_after": run.CursorAfter,
		"report_json": string(report), "error_text": run.ErrorText,
	}).Error
}

func (r *directoryRepo) ListRuns(ctx context.Context, tx biz.Tx, sourceID int64, limit int) ([]*biz.DirectoryRun, error) {
	var rows []directoryRunPO
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("source_id = ?", sourceID).Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.DirectoryRun, 0, len(rows))
	for _, p := range rows {
		run, err := directoryRunToBiz(p)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, nil
}

func (r *directoryRepo) GetObject(ctx context.Context, tx biz.Tx, sourceID int64, externalID string) (*biz.DirectoryObject, error) {
	var p directoryObjectPO
	err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("source_id = ? AND external_id = ?", sourceID, externalID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, biz.ErrResourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &biz.DirectoryObject{
		ID: p.ID, SourceID: p.SourceID, OrganizationID: p.OrganizationID,
		ExternalID: p.ExternalID, LocalID: p.LocalID,
		LastSeenAt: p.LastSeenAt.UTC(), Revision: p.Revision,
	}, nil
}

func (r *directoryRepo) UpsertObject(ctx context.Context, tx biz.Tx, o *biz.DirectoryObject) error {
	db := r.d.tenantOr(ctx, tx).WithContext(ctx)
	var existing directoryObjectPO
	err := db.Where("source_id = ? AND external_id = ?", o.SourceID, o.ExternalID).First(&existing).Error
	if err == nil {
		return db.Model(&directoryObjectPO{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"local_id": o.LocalID, "last_seen_at": o.LastSeenAt, "revision": existing.Revision + 1,
		}).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return db.Create(&directoryObjectPO{
		SourceID: o.SourceID, OrganizationID: o.OrganizationID,
		ExternalID: o.ExternalID, LocalID: o.LocalID, LastSeenAt: o.LastSeenAt, Revision: 1,
	}).Error
}

func (r *directoryRepo) ListObjects(ctx context.Context, tx biz.Tx, sourceID int64) ([]*biz.DirectoryObject, error) {
	var rows []directoryObjectPO
	if err := r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("source_id = ?", sourceID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*biz.DirectoryObject, 0, len(rows))
	for _, p := range rows {
		out = append(out, &biz.DirectoryObject{
			ID: p.ID, SourceID: p.SourceID, OrganizationID: p.OrganizationID,
			ExternalID: p.ExternalID, LocalID: p.LocalID,
			LastSeenAt: p.LastSeenAt.UTC(), Revision: p.Revision,
		})
	}
	return out, nil
}

func (r *directoryRepo) DeleteObject(ctx context.Context, tx biz.Tx, sourceID int64, externalID string) error {
	return r.d.tenantOr(ctx, tx).WithContext(ctx).
		Where("source_id = ? AND external_id = ?", sourceID, externalID).
		Delete(&directoryObjectPO{}).Error
}
