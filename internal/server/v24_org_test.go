package server_test

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
)

var invitationTokenPattern = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

func fixtureUserWithEmail(t *testing.T, h *harness, name, email string) *biz.User {
	t.Helper()
	ctx := context.Background()
	u, err := h.svc.Users.Create(ctx, nil, &biz.User{
		Username: name, UsernameNormalized: name, DisplayName: name,
		Email: email, EmailNormalized: email, EmailVerified: true,
		Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	hash, err := biz.HashPassword("InvitePass-123")
	require.NoError(t, err)
	require.NoError(t, h.svc.Credentials.Create(ctx, nil, &biz.Credential{
		UserID: u.ID, PasswordHash: hash, Algorithm: "bcrypt", Revision: 1, UpdatedAt: time.Now(),
	}))
	role, err := h.svc.IAM.GetRoleByCode(ctx, nil, "member")
	require.NoError(t, err)
	_, err = h.svc.IAM.CreateAssignment(ctx, nil, &biz.Assignment{
		UserID: u.ID, RoleID: role.ID, StartsAt: time.Now().Add(-time.Minute),
		Origin: biz.OriginDefault, Revision: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	return u
}

func createTestOrg(t *testing.T, h *harness, code string) string {
	t.Helper()
	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": code, "name": code}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)["id"].(string)
}

func TestOrganizationInvitationLifecycle(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "invite-org")
	fixtureStepUp(h)

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "Invitee@Example.com", "role": "member", "reason": "onboarding",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	inv := decode[map[string]any](t, rec)
	require.Equal(t, "invitee@example.com", inv["email"])
	require.Equal(t, "pending", inv["status"])
	require.Empty(t, inv["token"], "the raw token must never be returned by the API")
	token := invitationTokenPattern.FindStringSubmatch(h.mail.last().body)
	require.Len(t, token, 2)
	require.Contains(t, h.mail.last().body, "请先注册")

	list := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/invitations", nil, "", false))
	require.Len(t, list["items"], 1)

	// A different e-mail cannot accept the invitation, and the response does
	// not disclose whether the token exists.
	fixtureUserWithEmail(t, h, "wrong", "wrong@example.com")
	invitee := fixtureUserWithEmail(t, h, "invitee", "invitee@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("wrong", "InvitePass-123").Code)
	mismatch := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept", map[string]any{"token": token[1]}, "", true)
	require.Equal(t, http.StatusNotFound, mismatch.Code)

	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("invitee", "InvitePass-123").Code)
	accepted := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept", map[string]any{"token": token[1]}, "", true)
	require.Equal(t, http.StatusOK, accepted.Code, accepted.Body.String())
	member := decode[map[string]any](t, accepted)
	require.Equal(t, "member", member["role"])
	require.Equal(t, strconv.FormatInt(invitee.ID, 10), member["user_id"])

	// Replay is rejected with a stable code.
	again := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept", map[string]any{"token": token[1]}, "", true)
	require.Equal(t, http.StatusConflict, again.Code)
	require.Contains(t, again.Body.String(), biz.InvitationErrUsed)

	// The accepted invitation is visible in the tenant list.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	list = decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/invitations", nil, "", false))
	require.Equal(t, "accepted", list["items"].([]any)[0].(map[string]any)["status"])
}

func TestOrganizationInvitationRevokeAndQuota(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "revoke-org")
	fixtureStepUp(h)
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "revoked@example.com", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	inv := decode[map[string]any](t, rec)
	token := invitationTokenPattern.FindStringSubmatch(h.mail.last().body)
	require.Len(t, token, 2)
	revoke := h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/invitations/"+inv["id"].(string)+
		"?expected_revision=1&reason=revoke-test", nil, "", true)
	require.Equal(t, http.StatusOK, revoke.Code, revoke.Body.String())

	u := fixtureUserWithEmail(t, h, "revoked", "revoked@example.com")
	_ = u
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("revoked", "InvitePass-123").Code)
	accept := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept", map[string]any{"token": token[1]}, "", true)
	require.Equal(t, http.StatusConflict, accept.Code)
	require.Contains(t, accept.Body.String(), biz.InvitationErrRevoked)
}

func TestOrgExplainUsesTenantFactsOnly(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "explain-org")
	fixtureStepUp(h)
	memberUser := fixtureUserWithEmail(t, h, "explain_member", "explain@example.com")
	memberID := strconv.FormatInt(memberUser.ID, 10)
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "explain_member", "role": "member", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/authorization:explain?"+
		"user_id="+memberID+"&operation=organization.department.manage", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	reply := decode[map[string]any](t, rec)
	require.False(t, reply["allowed"].(bool), "a plain member must not manage departments")
	require.Equal(t, "organization:"+orgID, reply["context"])
	require.NotContains(t, rec.Body.String(), "root")
	require.NotContains(t, rec.Body.String(), "platform")

	// A non-member is a missing resource, not a platform user to explain.
	other := fixtureUserWithEmail(t, h, "explain_other", "other2@example.com")
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/authorization:explain?"+
		"user_id="+strconv.FormatInt(other.ID, 10)+"&operation=organization.member.read", nil, "", false)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOrgAuditExportIsTenantScoped(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgA := createTestOrg(t, h, "export-a")
	orgB := createTestOrg(t, h, "export-b")
	fixtureStepUp(h)
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgA+"/audits:export", map[string]any{"reason": "compliance"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	job := decode[map[string]any](t, rec)
	require.Equal(t, "org_audits", job["kind"])
	jobID := job["id"].(string)

	// A download through another tenant's path is indistinguishable from a
	// missing job.
	cross := h.do(http.MethodGet, "/api/v1/orgs/"+orgB+"/audits/exports/"+jobID+"/download", nil, "", false)
	require.Equal(t, http.StatusNotFound, cross.Code)

	own := h.do(http.MethodGet, "/api/v1/orgs/"+orgA+"/audits/exports/"+jobID+"/download", nil, "", false)
	require.Equal(t, http.StatusOK, own.Code, own.Body.String())
	csv := own.Body.String()
	require.Contains(t, csv, "organization.create")
	require.True(t, strings.Contains(csv, "event_id"), "columns must match the platform export")
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	require.Greater(t, len(lines), 1)
	for _, line := range lines[1:] {
		columns := strings.Split(line, ",")
		require.Greater(t, len(columns), 4)
		require.Equal(t, orgA, columns[4], "every exported row must belong to this tenant")
		require.NotEqual(t, orgB, columns[4])
	}
}

func TestOrgEventsArePIIFreeAndSubscriptionFiltered(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	// Subscribe before the domain writes: the outbox only offers events created
	// after the subscription exists.
	ctx := context.Background()
	client, err := h.svc.IntegrationClients.Create(ctx, nil, &biz.IntegrationClient{
		ClientID: "org-events", Code: "org-events", ServiceOwner: "test", Status: "active",
		CredentialHash: "unused", EventSubscriptions: []string{"organization.member.added"},
	})
	require.NoError(t, err)
	other, err := h.svc.IntegrationClients.Create(ctx, nil, &biz.IntegrationClient{
		ClientID: "user-events", Code: "user-events", ServiceOwner: "test", Status: "active",
		CredentialHash: "unused", EventSubscriptions: []string{"user.created"},
	})
	require.NoError(t, err)
	orgID := createTestOrg(t, h, "event-org")
	fixtureStepUp(h)
	fixtureUserWithEmail(t, h, "event_member", "event@example.com")
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "event_member", "role": "member", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	events, err := h.svc.Outbox.PendingEventsForClient(ctx, nil, client, 100)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	for _, event := range events {
		require.Equal(t, "organization.member.added", event.EventType)
		require.NotContains(t, event.Payload, "@")
		require.NotContains(t, event.Payload, "email")
		require.NotContains(t, event.Payload, "event_member")
	}

	// A subscriber that did not opt into organization events sees none.
	filtered, err := h.svc.Outbox.PendingEventsForClient(ctx, nil, other, 100)
	require.NoError(t, err)
	for _, event := range filtered {
		require.NotEqual(t, "organization.member.added", event.EventType)
	}
}
