package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// A tenant administrator without a second factor must still be able to confirm
// sensitive operations; otherwise every step-up-protected organization write is
// permanently blocked for that account.
func TestStepUpAcceptsPasswordOnlyWithoutMFA(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	rec := h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{
		"current_password": "ChangeMe-12345",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "step-up-org", "name": "Step Up"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	orgID := decode[map[string]any](t, rec)["id"].(string)

	iamFixtureUser(t, h, "step_up_member")
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "step_up_member", "role": "member", "reason": "add",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// Once MFA is enrolled the password alone is no longer a valid step-up proof.
func TestStepUpRequiresCodeWhenMFAEnabled(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	enrollMFA(t, h, "ChangeMe-12345")

	rec := h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{
		"current_password": "ChangeMe-12345",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "CHALLENGE_INVALID")
}

// A wrong password never yields a proof, with or without MFA.
func TestStepUpRejectsWrongPassword(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	rec := h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{
		"current_password": "not-the-password",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}
