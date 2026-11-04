package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The password-change gate must cover tenant routes too; it used to be checked
// inside a branch that excluded /api/v1/orgs, so an initial-password account
// could create organizations before changing its password.
func TestPasswordChangeGateCoversOrganizationRoutes(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "gated", "email": "gated@example.com", "initial_password": "GatedPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.login("gated", "GatedPass-123").Code)

	rec = h.do(http.MethodGet, "/api/v1/orgs", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PASSWORD_CHANGE_REQUIRED")

	rec = h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "gated-org", "name": "Gated"}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PASSWORD_CHANGE_REQUIRED")

	// The security center stays reachable so the user can actually complete the
	// change.
	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}
