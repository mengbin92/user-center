package biz

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// writeAuditExport is the single CSV export path for platform and tenant
// audits. Tenant exports pin organization_id in the filter and on the job so a
// download can never widen to another tenant.
func (uc *AuditUsecase) writeAuditExport(ctx context.Context, actor ActorContext, filter AuditFilter, fields []string, reason, action, kind string, orgID int64) (*ExportJob, error) {
	snapshot, err := uc.exportSnapshot(ctx, actor)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		fields = []string{"event_id", "occurred_at", "actor_user_id", "action", "target", "result", "reason", "request_id"}
	}
	allowed := map[string]bool{"event_id": true, "occurred_at": true, "actor_user_id": true, "actor_session_id": true, "action": true, "target": true, "result": true, "reason": true, "request_id": true, "before": true, "after": true, "diff": true}
	for _, f := range fields {
		if !allowed[f] {
			return nil, Validation("不支持的导出字段: " + f)
		}
	}
	if orgID > 0 {
		filter.OrganizationID = orgID
	}
	filter.Limit = 100000
	events, _, err := uc.Audit.List(ctx, nil, filter)
	if err != nil {
		return nil, ErrDependency
	}
	if err := os.MkdirAll(uc.ArtifactDir, 0o750); err != nil {
		return nil, ErrDependency
	}
	job := &ExportJob{
		Kind: kind, ScopeSnapshot: snapshot, ActorUserID: actor.User.ID, ActorSessionID: actor.Session.ID,
		RequestedFields: fields, Status: ExportPending, CreatedAt: uc.Clock.Now().UTC(),
		ExpiresAt: uc.Clock.Now().Add(24 * time.Hour), ArtifactName: uc.IDs.NewID() + ".csv",
		OrganizationID: orgID,
	}
	path := filepath.Join(uc.ArtifactDir, job.ArtifactName)
	keepArtifact := false
	defer func() {
		if !keepArtifact {
			_ = os.Remove(path)
		}
	}()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, ErrDependency
	}
	w := csv.NewWriter(f)
	_ = w.Write(fields)
	for _, e := range events {
		row := make([]string, 0, len(fields))
		for _, field := range fields {
			switch field {
			case "event_id":
				row = append(row, e.EventID)
			case "occurred_at":
				row = append(row, e.OccurredAt.Format(time.RFC3339))
			case "actor_user_id":
				row = append(row, itoa(e.ActorUserID))
			case "actor_session_id":
				row = append(row, e.ActorSessionID)
			case "action":
				row = append(row, e.Action)
			case "target":
				row = append(row, e.Target)
			case "result":
				row = append(row, e.Result)
			case "reason":
				row = append(row, e.Reason)
			case "request_id":
				row = append(row, e.RequestID)
			case "before":
				row = append(row, e.Before)
			case "after":
				row = append(row, e.After)
			case "diff":
				row = append(row, e.Diff)
			}
		}
		_ = w.Write(csvSafeRow(row))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return nil, ErrDependency
	}
	if err := f.Close(); err != nil {
		return nil, ErrDependency
	}
	job.Status = ExportReady
	var saved *ExportJob
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		saved, err = uc.Exports.Create(ctx, tx, job)
		if err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, action, kind, "{}", "{}", string(mustJSON(map[string]any{"fields": fields})), reason, "success")
	})
	if err != nil {
		return nil, err
	}
	keepArtifact = true
	return saved, nil
}

// ValidateExportAuthority re-checks the authorization snapshot recorded when
// the job was created. A policy or session change invalidates old exports.
func (s *Services) ValidateExportAuthority(ctx context.Context, actor ActorContext, job *ExportJob) error {
	if !s.Clock.Now().Before(job.ExpiresAt) {
		return ErrResourceNotFound
	}
	var authority exportAuthority
	if jsonx.Unmarshal([]byte(job.ScopeSnapshot), &authority) != nil || authority.PolicyRevision == 0 {
		return ErrPermissionDenied
	}
	policy, err := s.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return ErrDependency
	}
	if policy != authority.PolicyRevision || actor.Session.Revision != authority.SessionRevision || !s.Clock.Now().Before(authority.ValidUntil) {
		return ErrPermissionDenied
	}
	return nil
}

func (uc *UserUsecase) authorizeExport(ctx context.Context, actor ActorContext, job *ExportJob) error {
	if err := uc.ValidateExportAuthority(ctx, actor, job); err != nil {
		return err
	}
	switch job.Kind {
	case "users":
		if _, err := uc.ListScope(ctx, actor, "identity.user.export"); err != nil {
			return err
		}
		if slices.Contains(job.RequestedFields, "email") || slices.Contains(job.RequestedFields, "email_verified") {
			if _, err := uc.ListScope(ctx, actor, "identity.user.contact.read"); err != nil {
				return err
			}
		}
	case "audits":
		if _, err := uc.Authorize(ctx, actor, "audit.export", 0, true); err != nil {
			return err
		}
	case "org_audits":
		// Tenant jobs are only reachable through the tenant download route,
		// which re-evaluates organization.audit.read in the tenant context.
		if job.OrganizationID <= 0 {
			return ErrResourceNotFound
		}
	default:
		return ErrResourceNotFound
	}
	return nil
}

// AuditCSVFields returns the platform export column list, used by the tenant
// UI so both exports stay identical.
func AuditCSVFields() []string {
	return []string{"event_id", "occurred_at", "actor_user_id", "action", "target", "result", "reason", "request_id"}
}
