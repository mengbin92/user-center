package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/totp"
)

type failingMail struct{}

func (failingMail) Send(context.Context, string, string, string) error {
	return errors.New("smtp unavailable")
}

func TestQuotaDenialAuditSurvivesRollback(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	current := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/organization", nil, "", false))
	require.Equal(t, http.StatusOK, h.do(http.MethodPatch, "/api/v1/admin/settings/organization", map[string]any{
		"quota_enabled": true, "max_owned_per_user": 1,
		"update_mask":       "quota_enabled,max_owned_per_user",
		"expected_revision": current["revision"], "reason": "audit review",
	}, "", true).Code)
	fixtureUserWithEmail(t, h, "quota_audit", "quota_audit@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("quota_audit", "InvitePass-123").Code)
	require.NotEmpty(t, createTestOrg(t, h, "quota-audit-a"))
	denied := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "quota-audit-b", "name": "B"}, "", true)
	require.Equal(t, http.StatusConflict, denied.Code)
	events, _, err := h.svc.Audit.List(context.Background(), nil, biz.AuditFilter{
		Action: "organization.create.denied", Limit: 20,
	})
	require.NoError(t, err)
	require.Len(t, events, 1, "the denial audit must not be rolled back")
	require.Equal(t, "denied", events[0].Result)
	require.Contains(t, events[0].Diff, "limit")
}

func TestIntegrationSessionCannotBeUsedAsBrowserCookie(t *testing.T) {
	h := newHarness(t)
	client := integrationClientForAuth(t, h, "cookie-app")
	uc := biz.NewIntegrationUsecase(h.svc)
	ctx := biz.WithIntegrationClient(context.Background(), client)
	result, err := uc.Authenticate(ctx, "cookie-app", "root", "ChangeMe-12345", "10.0.0.2", "grpc", "req-audience")
	require.NoError(t, err)
	require.NotEmpty(t, result.SessionToken)
	_, _, err = uc.ValidateSession(ctx, result.SessionToken, "cookie-app")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/me", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.AddCookie(&http.Cookie{Name: "uc_session", Value: result.SessionToken})
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a third-party session must not become a browser session")

	// A real user-center session still works through the same middleware.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
}

func TestIntegrationMFAChallengeCannotBeRedeemedOverHTTP(t *testing.T) {
	h := newHarness(t)
	client := integrationClientForAuth(t, h, "challenge-app")
	uc := biz.NewIntegrationUsecase(h.svc)
	ctx := biz.WithIntegrationClient(context.Background(), client)
	u := fixtureUserWithEmail(t, h, "challenge_mfa", "challenge_mfa@example.com")
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := h.svc.Secrets.Encrypt(secret)
	require.NoError(t, err)
	require.NoError(t, h.svc.MFA.Save(context.Background(), nil, &biz.MFAState{
		UserID: u.ID, Secret: encrypted, KeyVersion: 1, Revision: 1,
	}))
	challenge, err := uc.Authenticate(ctx, "challenge-app", "challenge_mfa", "InvitePass-123", "10.0.0.3", "grpc", "req-challenge")
	require.NoError(t, err)
	require.Equal(t, "mfa_required", challenge.Status)
	code, err := totp.Code(secret, time.Now().Unix()/30, 6)
	require.NoError(t, err)
	rec := h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
		"challenge_id": challenge.ChallengeID, "code": code,
	}, "", true)
	require.NotEqual(t, http.StatusOK, rec.Code, "an integration challenge must not mint a user-center session")
}

func TestProviderDisableAllSentinel(t *testing.T) {
	h := newHarness(t)
	h.svc.OAuth["github"] = mockOAuthProvider{}
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	auth := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/auth", nil, "", false))
	// Empty list means every configured provider is enabled (legacy default).
	require.Contains(t, h.do(http.MethodGet, "/api/v1/auth/context", nil, "", false).Body.String(), "github")
	disabled := h.do(http.MethodPatch, "/api/v1/admin/settings/auth", map[string]any{
		"providers": []string{biz.ProvidersDisabledAll}, "update_mask": "providers",
		"expected_revision": auth["revision"], "reason": "disable all",
	}, "", true)
	require.Equal(t, http.StatusOK, disabled.Code, disabled.Body.String())
	contextBody := h.do(http.MethodGet, "/api/v1/auth/context", nil, "", false).Body.String()
	require.NotContains(t, contextBody, "github")
	require.NotContains(t, contextBody, "mock")
	view := h.do(http.MethodGet, "/api/v1/admin/settings/providers", nil, "", false).Body.String()
	require.Contains(t, view, `"enabled":false`)
}

func TestConsentStateLengthAndRevokeMissing(t *testing.T) {
	h := newHarness(t)
	consentClient(t, h, []string{"openid"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	q := consentQuery("openid", "")
	q.Set("state", strings.Repeat("s", 513))
	rec := h.do(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil, "", false)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "invalid_request", loc.Query().Get("error"))

	missing := h.do(http.MethodDelete, "/api/v1/me/oidc-consents/unknown_client", nil, "", true)
	require.Equal(t, http.StatusNotFound, missing.Code)
	events, _, err := h.svc.Audit.List(context.Background(), nil, biz.AuditFilter{
		Action: "oidc.consent.revoke", Limit: 20,
	})
	require.NoError(t, err)
	require.Empty(t, events, "revoking a non-existent consent must not write a success audit")
}

func TestTenantExportViaPlatformRouteStillChecksTenantPermission(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "platform-route")
	fixtureStepUp(h)
	admin := fixtureUserWithEmail(t, h, "route_admin", "route_admin@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "route_admin", "role": "admin", "reason": "tenant export",
	}, "", true).Code)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("route_admin", "InvitePass-123").Code)
	job := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/audits:export",
		map[string]any{"reason": "route review"}, "", true))
	platformPath := "/api/v1/admin/exports/" + job["id"].(string) + "/download"
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, platformPath, nil, "", false).Code)

	// Revoke the tenant assignment: the platform route must now fail closed
	// instead of relying only on job ownership.
	_, err := h.svc.OrgIAM.RevokeMemberAssignments(context.Background(), nil,
		authorization.Organization(parseID(t, orgID)), admin.ID, nil, admin.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, h.do(http.MethodGet, platformPath, nil, "", false).Code)
}

func TestInvitationExpiryFilteringAndMailFailureCleanup(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "invite-review")
	fixtureStepUp(h)
	ctx := context.Background()
	_, err := h.svc.Organizations.CreateInvitation(ctx, nil, &biz.OrganizationInvitation{
		OrganizationID: parseID(t, orgID), Email: "old@example.com", EmailNormalized: "old@example.com",
		Role: biz.OrgRoleMember, TokenHash: biz.HashToken("old-token"),
		InvitedBy: 1, ExpiresAt: time.Now().UTC().Add(-time.Minute),
	})
	require.NoError(t, err)
	expired := decode[map[string]any](t, h.do(http.MethodGet,
		"/api/v1/orgs/"+orgID+"/invitations?status=expired", nil, "", false))
	require.Len(t, expired["items"], 1)
	pending := decode[map[string]any](t, h.do(http.MethodGet,
		"/api/v1/orgs/"+orgID+"/invitations?status=pending", nil, "", false))
	require.Empty(t, pending["items"])

	before, err := h.svc.Organizations.CountPendingInvitations(ctx, nil, parseID(t, orgID), time.Now().UTC())
	require.NoError(t, err)
	h.svc.Mail = failingMail{}
	failed := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "never@example.com", "reason": "mail failure",
	}, "", true)
	require.Equal(t, http.StatusServiceUnavailable, failed.Code)
	after, err := h.svc.Organizations.CountPendingInvitations(ctx, nil, parseID(t, orgID), time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, before, after, "a failed delivery must not leave a pending invitation")
}

func TestInvitationRequiresVerifiedEmailAndOrgAdminMayInviteAdmin(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "invite-admin")
	fixtureStepUp(h)

	// An org admin (not owner) can invite another admin, matching AddMember.
	admin := fixtureUserWithEmail(t, h, "invite_org_admin", "invite_org_admin@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "invite_org_admin", "role": "admin", "reason": "admin invite",
	}, "", true).Code)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("invite_org_admin", "InvitePass-123").Code)
	fixtureStepUp(h)
	invite := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "newadmin@example.com", "role": "admin", "reason": "admin invite",
	}, "", true)
	require.Equal(t, http.StatusOK, invite.Code, invite.Body.String())
	_ = admin

	// An unverified account cannot accept an invitation for its address.
	unverified := fixtureUserWithEmail(t, h, "unverified", "unverified@example.com")
	unverified.EmailVerified = false
	_, err := h.svc.Users.Update(context.Background(), nil, unverified, unverified.Revision)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	created := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "unverified@example.com", "reason": "verify",
	}, "", true))
	require.Equal(t, "pending", created["status"])
	token := invitationTokenPattern.FindStringSubmatch(h.mail.last().body)
	require.Len(t, token, 2)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("unverified", "InvitePass-123").Code)
	rejected := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept",
		map[string]any{"token": token[1]}, "", true)
	require.Equal(t, http.StatusNotFound, rejected.Code)
}
