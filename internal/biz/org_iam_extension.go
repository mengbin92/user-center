package biz

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// OrgExplainResult is the tenant-scoped authorization explanation. It is
// produced by the same authorization.Evaluate + Input construction used by the
// platform explain endpoint; only the facts differ (tenant roles/assignments).
type OrgExplainResult struct {
	Allowed        bool
	Reason         string
	Sources        []authorization.GrantSource
	Context        string
	Scope          string
	ValidUntil     *time.Time
	Missing        []string
	PolicyRevision uint64
	UserRevision   uint64
}

func (uc *OrgIAMUsecase) Explain(ctx context.Context, actor ActorContext, orgID, targetUserID int64, operation string) (*OrgExplainResult, error) {
	// Either read permission is sufficient to ask "why", but the caller must
	// still be a member of this tenant.
	if _, err := uc.orgGuard(ctx, actor, orgID, PermOrgAssignmentRead, 0, true); err != nil {
		if !errors.Is(err, ErrPermissionDenied) {
			return nil, err
		}
		if _, err := uc.orgGuard(ctx, actor, orgID, PermOrgRoleRead, 0, true); err != nil {
			return nil, err
		}
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, targetUserID)
	if err != nil || member.Status != OrgMemberActive {
		return nil, ErrResourceNotFound
	}
	target, err := uc.Users.Get(ctx, nil, targetUserID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	authCtx := authorization.Organization(orgID)
	facts, err := uc.LoadAuthzFactsIn(ctx, authCtx, targetUserID, nil)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	targetActor := ActorContext{
		User: target,
		Session: &Session{
			ID: "explain", UserID: targetUserID, ActiveRoleIDs: facts.ActiveRoleIDs,
			ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		},
		Actor: authorization.Actor{UserID: targetUserID, SessionID: "explain", ExpiresAt: now.Add(time.Hour)},
	}
	decision, err := uc.decideWithFacts(ctx, facts, targetActor, strings.TrimSpace(operation), targetUserID, false)
	if err != nil {
		return nil, ErrDependency
	}
	out := &OrgExplainResult{
		Allowed: decision.Allowed, Reason: decision.Reason, Sources: decision.Sources,
		Context: authCtx.String(), ValidUntil: decision.ValidUntil,
		PolicyRevision: facts.PolicyRevision, UserRevision: facts.UserRevision,
	}
	all := false
	denies := 0
	for _, src := range decision.Sources {
		if src.Effect == authorization.Deny {
			denies++
			continue
		}
		effective := authorization.IntersectForActor(src.RoleScope, src.Boundary, targetUserID)
		if effective.All {
			all = true
		}
	}
	switch {
	case all:
		out.Scope = "all"
	case denies > 0:
		out.Scope = "deny overrides allow"
	default:
		out.Scope = "self or restricted"
	}
	if !decision.Allowed && decision.Reason != "" {
		out.Missing = append(out.Missing, decision.Reason)
	}
	return out, nil
}

// ExportAudits reuses the platform CSV/task/download pipeline, pinning the
// tenant on both the query filter and the job row.
func (uc *OrgIAMUsecase) ExportAudits(ctx context.Context, actor ActorContext, orgID int64, filter AuditFilter, fields []string, reason string) (*ExportJob, error) {
	if _, err := uc.orgGuard(ctx, actor, orgID, PermOrgAuditRead, 0, true); err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	audits := &AuditUsecase{Services: uc.Services}
	return audits.writeAuditExport(ctx, actor, filter, fields, reason, "organization.audit.export", "org_audits", orgID)
}

// GetAuditExport is the tenant download guard. A job of another tenant, of
// another actor, or with a stale policy snapshot is indistinguishable from a
// missing job.
func (uc *OrganizationUsecase) GetAuditExport(ctx context.Context, actor ActorContext, orgID, jobID int64) (*ExportJob, error) {
	job, err := uc.Exports.Get(ctx, jobID)
	if err != nil || job.Kind != "org_audits" || job.OrganizationID != orgID ||
		job.ActorUserID != actor.User.ID || job.ActorSessionID != actor.Session.ID {
		return nil, ErrResourceNotFound
	}
	if err := uc.orgPermission(ctx, actor, orgID, PermOrgAuditRead, 0, true); err != nil {
		return nil, err
	}
	if err := uc.ValidateExportAuthority(ctx, actor, job); err != nil {
		return nil, err
	}
	return job, nil
}

// orgEvent emits a minimal, PII-free organization event inside the business
// transaction. Payloads carry IDs, revisions and role codes only.
func orgEvent(ctx context.Context, s *Services, tx Tx, orgID int64, revision uint64, eventType string, payload map[string]any) error {
	raw, err := jsonx.Marshal(payload)
	if err != nil {
		return ErrDependency
	}
	return s.emit(ctx, tx, "organization", orgID, revision, eventType, string(raw))
}
