package server_test

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/totp"
)

// Session recycling must be reported by every issuance path, not only by the
// password branch: a user who completes an MFA challenge and loses their other
// devices needs the same explanation, and the security event is what makes the
// eviction visible to an incident review.
func TestMFALoginReportsRecycledSessionsAndRecordsTheEvent(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "cap.mfa", "email": "cap.mfa@example.com",
		"initial_password": "CapMfa-12345", "reason": "cap fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.login("cap.mfa", "CapMfa-12345").Code)
	secret := enrollMFA(t, h, "CapMfa-12345")
	h.setAuthSettings(func(s *biz.AuthSettings) { s.MaxSessionsPerUser = 1 })

	user, err := h.svc.Users.GetByUsername(t.Context(), nil, "cap.mfa")
	require.NoError(t, err)
	require.NoError(t, h.svc.Sessions.RevokeAllForUser(t.Context(), nil, user.ID, nil))

	completeMFA := func() map[string]any {
		h.jar, _ = cookiejar.New(nil)
		h.refreshCSRF()
		rec := h.login("cap.mfa", "CapMfa-12345")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		login := decode[map[string]any](t, rec)
		require.Equal(t, "mfa_required", login["status"])
		// Replay protection is not what this test is about, and the TOTP window
		// only accepts steps near now; reset the high-water mark so the same
		// (current) step can be used twice.
		require.NoError(t, h.d.DB().Exec(
			"UPDATE identity_mfa SET last_step = 0 WHERE user_id = ?", user.ID).Error)
		code, err := totp.Code(secret, time.Now().Unix()/30, 6)
		require.NoError(t, err)
		rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
			"challenge_id": login["challenge_id"], "code": code,
		}, "", true)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return decode[map[string]any](t, rec)
	}

	first := completeMFA()
	require.EqualValues(t, 0, first["recycled_sessions"], "nothing to reclaim yet")
	second := completeMFA()
	require.EqualValues(t, 1, second["recycled_sessions"],
		"the MFA reply must report the reclaimed session")

	var evicts int64
	require.NoError(t, h.d.DB().Table("security_events").
		Where("user_id = ? AND kind = ?", user.ID, "session_evict").Count(&evicts).Error)
	require.GreaterOrEqual(t, evicts, int64(1),
		"an eviction during an MFA login must be recorded, not only during a password login")
}
