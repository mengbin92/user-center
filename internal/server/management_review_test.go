package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

type rejectedAudit struct{ biz.AuditRepo }

func (rejectedAudit) Append(context.Context, biz.Tx, *biz.AuditEvent) error {
	return errors.New("SQL driver failed with confidential database details")
}

func TestManagementSettingsMasksAndStepUp(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	settings, err := h.svc.Settings.GetAuth(context.Background(), nil)
	require.NoError(t, err)
	body := map[string]any{"registration_enabled": false, "update_mask": "registration_enabled", "expected_revision": strconv.FormatUint(settings.Revision, 10), "reason": "review"}
	rec := h.do(http.MethodPatch, "/api/v1/admin/settings/auth", body, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "STEP_UP_REQUIRED")
	fixtureStepUp(h)
	rec = h.do(http.MethodPatch, "/api/v1/admin/settings/auth", body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	updated, err := h.svc.Settings.GetAuth(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, updated.RegistrationEnabled)
	require.Equal(t, settings.PasswordMinLength, updated.PasswordMinLength)
	require.Equal(t, settings.SessionTTLMinutes, updated.SessionTTLMinutes)
	require.Equal(t, settings.EmailVerificationRequired, updated.EmailVerificationRequired)
	for _, mask := range []string{"registration_enabled_extra", "password_hash"} {
		body["update_mask"] = mask
		body["expected_revision"] = strconv.FormatUint(updated.Revision, 10)
		rec = h.do(http.MethodPatch, "/api/v1/admin/settings/auth", body, "", true)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	rec = h.do(http.MethodPatch, "/api/v1/admin/settings/auth", map[string]any{"password_min_length": 73, "update_mask": "password_min_length", "expected_revision": strconv.FormatUint(updated.Revision, 10), "reason": "review"}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	email, _, err := h.svc.Settings.GetEmail(context.Background(), nil)
	require.NoError(t, err)
	rec = h.do(http.MethodPatch, "/api/v1/admin/settings/email", map[string]any{"from": "updated@example.com", "smtp_password": "ignored-secret", "update_mask": "from", "expected_revision": strconv.FormatUint(email.Revision, 10), "reason": "review"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	newEmail, secret, err := h.svc.Settings.GetEmail(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, email.Driver, newEmail.Driver)
	require.Equal(t, email.SMTPPort, newEmail.SMTPPort)
	require.Empty(t, secret, "fields outside the mask must not be written")
	rec = h.do(http.MethodPatch, "/api/v1/me", map[string]any{"display_name": "changed", "update_mask": "email", "expected_revision": "1"}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestSessionRevocationAndAuditAreAtomicAndDoNotExposeDriverErrors(t *testing.T) {
	h := newHarness(t)
	member := iamFixtureUser(t, h, "revoke_member")
	require.Equal(t, http.StatusOK, h.login(member.Username, "FixturePass-123").Code)
	sessions, err := h.svc.Sessions.ListByUser(context.Background(), nil, member.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	h.svc.Audit = rejectedAudit{h.svc.Audit}
	rec := h.management(http.MethodPost, "/api/v1/admin/users/"+strconv.FormatInt(member.ID, 10)+"/sessions:revoke", map[string]any{"revoke_all": true, "reason": "review"}, "", true)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DEPENDENCY_UNAVAILABLE")
	require.NotContains(t, rec.Body.String(), "confidential")
	unchanged, err := h.svc.Sessions.Get(context.Background(), nil, sessions[0].ID)
	require.NoError(t, err)
	require.Nil(t, unchanged.RevokedAt, "the revocation must roll back when audit persistence fails")
}

func TestNonRootAdministratorCannotTakeOverRootCredentials(t *testing.T) {
	h := newHarness(t)
	u := iamFixtureUser(t, h, "credential_admin")
	admin, err := h.svc.IAM.GetRoleByCode(context.Background(), nil, "admin")
	require.NoError(t, err)
	iamFixtureAssign(t, h, u.ID, admin.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(u.Username, "FixturePass-123").Code)
	fixtureStepUp(h)
	for _, action := range []string{"/mfa:reset", "/password-reset-requests", "/email-changes"} {
		body := map[string]any{"reason": "review"}
		if action == "/email-changes" {
			body["new_email"] = "attacker@example.com"
		}
		rec := h.management(http.MethodPost, "/api/v1/admin/users/1"+action, body, "", true)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "PROTECTED_ACCOUNT")
	}
}

func TestUserSearchDoesNotRevealHiddenEmailOrInterpretSQLWildcards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	viewer := iamFixtureUser(t, h, "keyword_viewer")
	target := iamFixtureUser(t, h, "keyword_target")
	target.Email, target.EmailNormalized, target.DisplayName = "hidden@example.com", "hidden@example.com", "literal%_!name"
	_, err := h.svc.Users.Update(ctx, nil, target, target.Revision)
	require.NoError(t, err)
	reader := iamFixtureRole(t, h, "keyword_reader", biz.Grant{Operation: "identity.user.list", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, viewer.ID, reader.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(viewer.Username, "FixturePass-123").Code)
	rec := h.do(http.MethodGet, "/api/v1/admin/users?keyword="+url.QueryEscape(target.Email), nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	result := decode[map[string]any](t, rec)
	require.Empty(t, result["items"])
	require.Equal(t, "0", result["meta"].(map[string]any)["total_size"])
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	for _, keyword := range []string{target.Email, "%_!"} {
		rec = h.do(http.MethodGet, "/api/v1/admin/users?keyword="+url.QueryEscape(keyword), nil, "", false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		result = decode[map[string]any](t, rec)
		require.Len(t, result["items"], 1)
	}
}
