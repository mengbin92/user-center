package server_test

import (
	"context"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/data"
)

func retentionUsecase(h *harness) *biz.RetentionUsecase {
	return biz.NewRetentionUsecase(h.svc, data.NewRetentionRepo(h.d))
}

func archiveAt(t *testing.T, h *harness, id int64, at time.Time) {
	t.Helper()
	u, err := h.svc.Users.Get(context.Background(), nil, id)
	require.NoError(t, err)
	u.Status = biz.UserStatusArchived
	u.ArchivedAt = &at
	_, err = h.svc.Users.Update(context.Background(), nil, u, u.Revision)
	require.NoError(t, err)
}

func seedPersonalData(t *testing.T, h *harness, id int64) {
	t.Helper()
	ctx := context.Background()
	_, err := h.svc.Identities.Create(ctx, nil, &biz.ExternalIdentity{
		UserID: id, Provider: "github", ProviderSubject: "subject-" + strconv.FormatInt(id, 10),
		Issuer: "github", Display: "Linked Account", CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, h.d.DB().Exec(
		"INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)",
		id, "fixture-digest", time.Now().UTC(),
	).Error)
	require.NoError(t, h.svc.Sessions.Create(ctx, nil, &biz.Session{
		ID: "retention-session-" + strconv.FormatInt(id, 10), UserID: id,
		ApplicationCode: biz.ApplicationCode, TokenHash: biz.HashToken("retention-session-token"),
		IssuedAt: time.Now(), LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		IdleExpiresAt: time.Now().Add(time.Hour), IdentityVersion: 1, Revision: 1,
	}))
	_, err = h.svc.WebAuthn.Create(ctx, nil, &biz.WebAuthnCredential{
		UserID: id, CredentialID: "retention-cred-" + strconv.FormatInt(id, 10),
		Name: "Passkey", PublicKey: []byte{0xa0}, Revision: 1,
	})
	require.NoError(t, err)
}

func TestRetentionDryRunHoldAndIdempotentCleanup(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u := fixtureUserWithEmail(t, h, "retention_user", "retention@example.com")
	fixtureUserWithEmail(t, h, "anon_"+strconv.FormatInt(u.ID, 10), "reserved-old-form@example.com")
	seedPersonalData(t, h, u.ID)
	archiveAt(t, h, u.ID, time.Now().UTC().Add(-400*24*time.Hour))
	uc := retentionUsecase(h)

	// Dry-run reports candidates but writes nothing.
	dry, err := uc.Run(ctx, biz.RetentionOptions{DryRun: true, RetentionDays: 365, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, 1, dry.Eligible)
	require.Equal(t, 0, dry.Cleaned)
	kept, err := h.svc.Users.Get(ctx, nil, u.ID)
	require.NoError(t, err)
	require.Equal(t, "retention@example.com", kept.Email)

	// An active legal hold wins, including for an -apply run.
	require.NoError(t, uc.Hold(ctx, u.ID, "legal investigation"))
	held, err := uc.Run(ctx, biz.RetentionOptions{DryRun: false, RetentionDays: 365, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, 1, held.SkippedHold)
	require.Equal(t, 0, held.Cleaned)

	require.NoError(t, uc.Release(ctx, u.ID, "investigation closed"))
	applied, err := uc.Run(ctx, biz.RetentionOptions{DryRun: false, RetentionDays: 365, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, 1, applied.Cleaned)

	clean, err := h.svc.Users.Get(ctx, nil, u.ID)
	require.NoError(t, err)
	require.Equal(t, "anon~"+strconv.FormatInt(u.ID, 10), clean.Username)
	require.Empty(t, clean.Email)
	require.NotNil(t, clean.AnonymizedAt)
	// Sensitive linked data is purged.
	_, err = h.svc.Credentials.Get(ctx, nil, u.ID)
	require.Error(t, err)
	var history int64
	require.NoError(t, h.d.DB().Table("password_history").Where("user_id = ?", u.ID).Count(&history).Error)
	require.Zero(t, history)
	_, err = h.svc.WebAuthn.Get(ctx, nil, u.ID, 1)
	require.Error(t, err)
	identities, err := h.svc.Identities.ListByUser(ctx, nil, u.ID)
	require.NoError(t, err)
	require.Empty(t, identities)

	// Audit stays traceable and contains no personal data.
	events, _, err := h.svc.Audit.List(ctx, nil, biz.AuditFilter{
		Action: "identity.retention.cleanup", Limit: 20,
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, strconv.FormatInt(u.ID, 10), events[0].Target)
	require.NotContains(t, events[0].Before+events[0].After+events[0].Diff, "retention@example.com")

	// Re-running is a no-op.
	again, err := uc.Run(ctx, biz.RetentionOptions{DryRun: false, RetentionDays: 365, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, 0, again.Scanned)
	require.Equal(t, 0, again.Cleaned)
}

func TestRetentionBatchMakesProgressPastLegalHolds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	held := fixtureUserWithEmail(t, h, "held_archive", "held@example.com")
	eligible := fixtureUserWithEmail(t, h, "eligible_archive", "eligible@example.com")
	now := time.Now().UTC()
	archiveAt(t, h, held.ID, now.AddDate(0, 0, -500))
	archiveAt(t, h, eligible.ID, now.AddDate(0, 0, -400))
	uc := retentionUsecase(h)
	require.NoError(t, uc.Hold(ctx, held.ID, "legal investigation"))

	report, err := uc.Run(ctx, biz.RetentionOptions{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []string{strconv.FormatInt(eligible.ID, 10)}, report.CandidateIDs)
	require.Equal(t, 1, report.Cleaned)
	require.Error(t, uc.Hold(ctx, eligible.ID, "data already deleted"))
}

func TestRetentionDoesNotTouchRecentOrActiveAccounts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	recent := fixtureUserWithEmail(t, h, "recent_archive", "recent@example.com")
	archiveAt(t, h, recent.ID, time.Now().UTC().Add(-time.Hour))
	active := fixtureUserWithEmail(t, h, "still_active", "active@example.com")
	_ = active
	uc := retentionUsecase(h)
	_, err := uc.Run(ctx, biz.RetentionOptions{RetentionDays: math.MaxInt})
	require.Error(t, err)
	report, err := uc.Run(ctx, biz.RetentionOptions{DryRun: false, RetentionDays: 365, Limit: 100})
	require.NoError(t, err)
	require.Equal(t, 0, report.Scanned)
	require.Equal(t, 0, report.Cleaned)
	kept, err := h.svc.Users.Get(ctx, nil, recent.ID)
	require.NoError(t, err)
	require.Equal(t, "recent@example.com", kept.Email)
}
