package biz

import (
	"context"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// R14 personal-data retention. The job is idempotent (anonymized_at), supports
// dry-run, honours legal holds, emits an audit trail that contains only the
// irreversible user id, and never removes audit rows or outbox events.

const DefaultRetentionDays = 365

type RetentionUsecase struct {
	*Services
	repo RetentionRepo
}

func NewRetentionUsecase(s *Services, repo RetentionRepo) *RetentionUsecase {
	return &RetentionUsecase{Services: s, repo: repo}
}

type RetentionOptions struct {
	DryRun        bool
	RetentionDays int
	Limit         int
}

type RetentionReport struct {
	DryRun        bool      `json:"dry_run"`
	RetentionDays int       `json:"retention_days"`
	Cutoff        time.Time `json:"cutoff"`
	Scanned       int       `json:"scanned"`
	Eligible      int       `json:"eligible"`
	Cleaned       int       `json:"cleaned"`
	SkippedHold   int       `json:"skipped_legal_hold"`
	Failed        int       `json:"failed"`
	CandidateIDs  []string  `json:"candidate_user_ids,omitempty"`
}

func (uc *RetentionUsecase) Hold(ctx context.Context, userID int64, reason string) error {
	if reason == "" {
		return Validation("legal hold 原因不能为空")
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.repo.AddLegalHold(ctx, tx, &LegalHold{UserID: userID, Reason: reason}); err != nil {
			return ErrDependency
		}
		return uc.systemAudit(ctx, tx, "identity.retention.hold", userID, reason)
	})
}

func (uc *RetentionUsecase) Release(ctx context.Context, userID int64, reason string) error {
	if reason == "" {
		return Validation("解除 legal hold 需要原因")
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.repo.ReleaseLegalHold(ctx, tx, userID); err != nil {
			return ErrDependency
		}
		return uc.systemAudit(ctx, tx, "identity.retention.hold_release", userID, reason)
	})
}

func (uc *RetentionUsecase) systemAudit(ctx context.Context, tx Tx, action string, userID int64, reason string) error {
	return uc.audit(ctx, tx, ActorContext{
		Actor: authorization.Actor{ServiceID: "retention-job"},
	}, action, itoa(userID), "{}", "{}", "{}", reason, "success")
}

func (uc *RetentionUsecase) Run(ctx context.Context, in RetentionOptions) (*RetentionReport, error) {
	days := in.RetentionDays
	if days <= 0 {
		days = DefaultRetentionDays
	}
	limit := in.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	now := uc.Clock.Now().UTC()
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	report := &RetentionReport{DryRun: in.DryRun, RetentionDays: days, Cutoff: cutoff}
	candidates, err := uc.repo.ListRetentionCandidates(ctx, nil, cutoff, limit)
	if err != nil {
		return nil, ErrDependency
	}
	report.Scanned = len(candidates)
	for _, user := range candidates {
		held, err := uc.repo.HasLegalHold(ctx, nil, user.ID)
		if err != nil {
			report.Failed++
			continue
		}
		if held {
			report.SkippedHold++
			continue
		}
		report.Eligible++
		report.CandidateIDs = append(report.CandidateIDs, itoa(user.ID))
		if in.DryRun {
			continue
		}
		if err := uc.anonymize(ctx, user.ID, now); err != nil {
			report.Failed++
			continue
		}
		report.Cleaned++
	}
	return report, nil
}

func (uc *RetentionUsecase) anonymize(ctx context.Context, userID int64, at time.Time) error {
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		// Re-check the hold inside the transaction so a hold added between the
		// scan and the write still wins.
		held, err := uc.repo.HasLegalHold(ctx, tx, userID)
		if err != nil {
			return ErrDependency
		}
		if held {
			return ErrPermissionDenied
		}
		for _, purge := range []func(context.Context, Tx, int64) error{
			uc.repo.PurgeExternalIdentities,
			uc.repo.PurgeSessions,
			uc.repo.PurgeMFA,
			uc.repo.PurgeCredentials,
			uc.repo.PurgeWebAuthn,
		} {
			if err := purge(ctx, tx, userID); err != nil {
				return ErrDependency
			}
		}
		if err := uc.repo.AnonymizeUser(ctx, tx, userID, at); err != nil {
			return ErrDependency
		}
		if err := uc.systemAudit(ctx, tx, "identity.retention.cleanup", userID, "retention policy"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": userID, "at": at})
		return uc.emit(ctx, tx, "user", userID, 0, "user.anonymized", string(payload))
	})
}
