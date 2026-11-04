package server_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/totp"
)

func integrationClientForAuth(t *testing.T, h *harness, code string) *biz.IntegrationClient {
	t.Helper()
	client, err := h.svc.IntegrationClients.Create(context.Background(), nil, &biz.IntegrationClient{
		ClientID: code + "-client", Code: code, ServiceOwner: "bff", Status: "active",
		CredentialHash: "unused",
		AllowedMethods: []string{
			"/api.usercenter.v1.IntegrationService/Authenticate",
			"/api.usercenter.v1.IntegrationService/CompleteMFA",
			"/api.usercenter.v1.IntegrationService/ValidateSession",
		},
	})
	require.NoError(t, err)
	return client
}

func TestIntegrationAuthenticateBindsSessionToApplication(t *testing.T) {
	h := newHarness(t)
	client := integrationClientForAuth(t, h, "bff-app")
	uc := biz.NewIntegrationUsecase(h.svc)
	ctx := biz.WithIntegrationClient(context.Background(), client)

	result, err := uc.Authenticate(ctx, "bff-app", "root", "ChangeMe-12345", "10.0.0.1", "grpc", "req-1")
	require.NoError(t, err)
	require.Equal(t, "authenticated", result.Status)
	require.NotEmpty(t, result.SessionToken)

	// The session audience is the calling application; another app is refused.
	_, _, err = uc.ValidateSession(ctx, result.SessionToken, "bff-app")
	require.NoError(t, err)
	_, _, err = uc.ValidateSession(ctx, result.SessionToken, "other-app")
	require.True(t, errors.Is(err, biz.ErrUnauthenticated))

	// Failures use the same generic credential error as the HTTP path.
	_, err = uc.Authenticate(ctx, "bff-app", "root", "wrong-password", "10.0.0.1", "grpc", "req-2")
	require.True(t, errors.Is(err, biz.ErrInvalidCredentials))
	_, err = uc.Authenticate(ctx, "other-app", "root", "ChangeMe-12345", "10.0.0.1", "grpc", "req-3")
	require.True(t, errors.Is(err, biz.ErrPermissionDenied))

	// A disabled account cannot log in over gRPC either.
	disabled := fixtureUserWithEmail(t, h, "grpc_disabled", "disabled@example.com")
	_, err = h.svc.Users.Update(context.Background(), nil, &biz.User{
		ID: disabled.ID, Username: "grpc_disabled", UsernameNormalized: "grpc_disabled",
		DisplayName: "grpc_disabled", Email: "disabled@example.com", EmailNormalized: "disabled@example.com",
		Status: biz.UserStatusDisabled, Revision: disabled.Revision, IdentityVersion: 1,
	}, disabled.Revision)
	require.NoError(t, err)
	_, err = uc.Authenticate(ctx, "bff-app", "grpc_disabled", "InvitePass-123", "10.0.0.1", "grpc", "req-4")
	require.Error(t, err)
}

func TestIntegrationCompleteMFAChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	client := integrationClientForAuth(t, h, "mfa-app")
	uc := biz.NewIntegrationUsecase(h.svc)
	ctx := biz.WithIntegrationClient(context.Background(), client)

	u := fixtureUserWithEmail(t, h, "grpc_mfa", "grpc_mfa@example.com")
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := h.svc.Secrets.Encrypt(secret)
	require.NoError(t, err)
	require.NoError(t, h.svc.MFA.Save(context.Background(), nil, &biz.MFAState{
		UserID: u.ID, Secret: encrypted, KeyVersion: 1, Revision: 1,
	}))

	challenge, err := uc.Authenticate(ctx, "mfa-app", "grpc_mfa", "InvitePass-123", "10.0.0.1", "grpc", "req-5")
	require.NoError(t, err)
	require.Equal(t, "mfa_required", challenge.Status)
	require.NotEmpty(t, challenge.ChallengeID)

	code, err := totp.Code(secret, time.Now().Unix()/30, 6)
	require.NoError(t, err)
	result, err := uc.CompleteMFA(ctx, challenge.ChallengeID, code, "10.0.0.1", "grpc", "req-6")
	require.NoError(t, err)
	require.Equal(t, "authenticated", result.Status)
	require.NotEmpty(t, result.SessionToken)

	// Replaying the same challenge is refused.
	_, err = uc.CompleteMFA(ctx, challenge.ChallengeID, code, "10.0.0.1", "grpc", "req-7")
	require.Error(t, err)
}

func TestUpdateUsernameRulesAndOldLogin(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	me := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me", nil, "", false))
	revision := me["revision"].(string)

	// Step-up is mandatory.
	missing := h.do(http.MethodPost, "/api/v1/me/username:update", map[string]any{
		"username": "renamed_root", "current_password": "ChangeMe-12345",
		"expected_revision": revision, "reason": "rename",
	}, "", true)
	require.Equal(t, http.StatusForbidden, missing.Code)
	require.Contains(t, missing.Body.String(), "STEP_UP_REQUIRED")
	fixtureStepUp(h)

	// Reserved words and existing usernames are stable validation errors.
	for _, name := range []string{"admin", "root"} {
		rec := h.do(http.MethodPost, "/api/v1/me/username:update", map[string]any{
			"username": name, "current_password": "ChangeMe-12345",
			"expected_revision": revision, "reason": "rename",
		}, "", true)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	changed := h.do(http.MethodPost, "/api/v1/me/username:update", map[string]any{
		"username": "Renamed_Root", "current_password": "ChangeMe-12345",
		"expected_revision": revision, "reason": "rename",
	}, "", true)
	require.Equal(t, http.StatusOK, changed.Code, changed.Body.String())
	require.Equal(t, "Renamed_Root", decode[map[string]any](t, changed)["username"])

	// Old username no longer authenticates; the normalized new one does.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusUnauthorized, h.login("root", "ChangeMe-12345").Code)
	require.Equal(t, http.StatusOK, h.login("renamed_root", "ChangeMe-12345").Code)
}

func TestPreviewAssignmentAndQuotaSettings(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)

	// Provider configuration never returns credentials.
	providers := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/providers", nil, "", false))
	items := providers["items"].([]any)
	require.Len(t, items, 2)
	require.NotContains(t, h.do(http.MethodGet, "/api/v1/admin/settings/providers", nil, "", false).Body.String(), "CLIENT_SECRET\":")

	// Single preview reports eligibility and the resulting grants without writes.
	role := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/iam/roles", nil, "", false))
	_ = role
	preview := h.do(http.MethodPost, "/api/v1/admin/iam/assignments:preview", map[string]any{
		"user_id": "1", "role_id": "1", "boundary": map[string]any{"all": true},
	}, "", true)
	require.Equal(t, http.StatusOK, preview.Code, preview.Body.String())
	previewBody := decode[map[string]any](t, preview)
	require.Contains(t, previewBody, "eligible")
	require.Contains(t, previewBody, "permissions")

	// Quota is off by default and can be enabled with an explicit revision.
	current := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/organization", nil, "", false))
	require.Equal(t, false, current["quota_enabled"])
	updated := h.do(http.MethodPatch, "/api/v1/admin/settings/organization", map[string]any{
		"quota_enabled": true, "max_owned_per_user": 2, "count_archived": false,
		"update_mask":       "quota_enabled,max_owned_per_user,count_archived",
		"expected_revision": current["revision"], "reason": "enable quota",
	}, "", true)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())

	// Platform administrators are exempt.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs",
		map[string]any{"code": "admin-org", "name": "Admin"}, "", true).Code)

	// A normal account is capped at 2 owned organizations.
	fixtureUserWithEmail(t, h, "quota_user", "quota@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("quota_user", "InvitePass-123").Code)
	require.NotEmpty(t, createTestOrg(t, h, "quota-a"))
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs",
		map[string]any{"code": "quota-b", "name": "B"}, "", true).Code)
	third := h.do(http.MethodPost, "/api/v1/orgs",
		map[string]any{"code": "quota-c", "name": "C"}, "", true)
	require.Equal(t, http.StatusConflict, third.Code)
	require.Contains(t, third.Body.String(), "ORGANIZATION_QUOTA_EXCEEDED")
}
