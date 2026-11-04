package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

func TestInvitationExpiryQuotaAndTenantBoundary(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "invite-guards")
	fixtureStepUp(h)
	ctx := context.Background()

	// Expired token: a stable conflict code instead of a driver error.
	expiredUser := fixtureUserWithEmail(t, h, "expired_user", "expired@example.com")
	_, err := h.svc.Organizations.CreateInvitation(ctx, nil, &biz.OrganizationInvitation{
		OrganizationID: parseID(t, orgID), Email: "expired@example.com", EmailNormalized: "expired@example.com",
		Role: biz.OrgRoleMember, TokenHash: biz.HashToken("expired-token"),
		InvitedBy: 1, ExpiresAt: time.Now().UTC().Add(-time.Hour),
	})
	require.NoError(t, err)
	_ = expiredUser

	// Quota: 50 pending invitations blocks the next one.
	for i := 0; i < biz.MaxPendingInvitationsPerOrg; i++ {
		_, err := h.svc.Organizations.CreateInvitation(ctx, nil, &biz.OrganizationInvitation{
			OrganizationID: parseID(t, orgID), Email: "bulk@example.com", EmailNormalized: "bulk@example.com",
			Role: biz.OrgRoleMember, TokenHash: biz.HashToken("bulk-token-" + itoa(int64(i))),
			InvitedBy: 1, ExpiresAt: time.Now().UTC().Add(time.Hour),
		})
		require.NoError(t, err)
	}
	full := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "one-more@example.com", "reason": "quota",
	}, "", true)
	require.Equal(t, http.StatusConflict, full.Code)
	require.Contains(t, full.Body.String(), biz.InvitationErrQuota)

	// A user outside the tenant cannot invite into it.
	fixtureUserWithEmail(t, h, "outsider", "outsider@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("outsider", "InvitePass-123").Code)
	cross := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/invitations", map[string]any{
		"email": "another@example.com", "reason": "cross tenant",
	}, "", true)
	require.Equal(t, http.StatusForbidden, cross.Code)

	// Expired accept returns the stable expiry code.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("expired_user", "InvitePass-123").Code)
	expired := h.do(http.MethodPost, "/api/v1/orgs/invitations:accept",
		map[string]any{"token": "expired-token"}, "", true)
	require.Equal(t, http.StatusConflict, expired.Code)
	require.Contains(t, expired.Body.String(), biz.InvitationErrExpired)
}

func parseID(t *testing.T, raw string) int64 {
	t.Helper()
	id, err := biz.ParseID(raw, "id")
	require.NoError(t, err)
	return id
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

func TestOrgAuditExportDenialAndCSVInjection(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "csv-org")
	fixtureStepUp(h)
	ctx := context.Background()

	// A formula-looking cell is escaped in the CSV artifact.
	require.NoError(t, h.svc.Audit.Append(ctx, nil, &biz.AuditEvent{
		EventID: "csv-injection-event", Action: "organization.member.add",
		Target: orgID, Result: "success", Reason: "=HYPERLINK(\"http://evil\")",
		OccurredAt: time.Now().UTC(), OrganizationID: parseID(t, orgID),
	}))
	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/audits:export", map[string]any{
		"reason": "injection review", "fields": []string{"event_id", "action", "reason"},
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	job := decode[map[string]any](t, rec)
	csv := h.do(http.MethodGet,
		"/api/v1/orgs/"+orgID+"/audits/exports/"+job["id"].(string)+"/download", nil, "", false)
	require.Equal(t, http.StatusOK, csv.Code)
	require.Contains(t, csv.Body.String(), "'=HYPERLINK")
	require.NotContains(t, csv.Body.String(), "\"=HYPERLINK")

	// A non-member is denied with 403, not an empty export.
	fixtureUserWithEmail(t, h, "export_denied", "denied@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("export_denied", "InvitePass-123").Code)
	denied := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/audits:export",
		map[string]any{"reason": "deny"}, "", true)
	require.Equal(t, http.StatusForbidden, denied.Code)
}

func TestOrgEventsRollbackAndEventIDDedupe(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "event-rollback")
	fixtureStepUp(h)
	ctx := context.Background()
	client, err := h.svc.IntegrationClients.Create(ctx, nil, &biz.IntegrationClient{
		ClientID: "rollback-events", Code: "rollback-events", ServiceOwner: "test",
		Status: "active", CredentialHash: "unused",
		EventSubscriptions: []string{"organization.member.added"},
	})
	require.NoError(t, err)

	// A failed member write must not leave an event in the outbox.
	failed := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "does-not-exist", "role": "member", "reason": "rollback",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, failed.Code)
	events, err := h.svc.Outbox.PendingEventsForClient(ctx, nil, client, 100)
	require.NoError(t, err)
	require.Empty(t, events)

	// event_id is the outbox primary key: a duplicate cannot be inserted.
	require.NoError(t, h.svc.Outbox.Append(ctx, nil, &biz.Event{
		EventID: "unique-org-event", AggregateType: "organization",
		AggregateID: parseID(t, orgID), EventType: "organization.member.added",
		SchemaVersion: 1, Payload: `{}`, OccurredAt: time.Now().UTC(),
	}))
	require.Error(t, h.svc.Outbox.Append(ctx, nil, &biz.Event{
		EventID: "unique-org-event", AggregateType: "organization",
		AggregateID: parseID(t, orgID), EventType: "organization.member.added",
		SchemaVersion: 1, Payload: `{}`, OccurredAt: time.Now().UTC(),
	}))
}

func TestUpdateUsernameDuplicateAndRevisionConflict(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	me := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me", nil, "", false))
	revision := me["revision"].(string)
	fixtureStepUp(h)
	body := map[string]any{
		"username": "renamed_root", "current_password": "ChangeMe-12345",
		"expected_revision": revision, "reason": "rename",
	}
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/me/username:update", body, "", true).Code)
	// Same revision twice is a 409, not a silent overwrite.
	stale := h.do(http.MethodPost, "/api/v1/me/username:update", body, "", true)
	require.Equal(t, http.StatusConflict, stale.Code)
	require.Contains(t, stale.Body.String(), "REVISION_CONFLICT")

	// A normalized collision maps to the stable USERNAME_EXISTS code.
	fixtureUserWithEmail(t, h, "dupe_user", "dupe@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("dupe_user", "InvitePass-123").Code)
	fixtureStepUp(h)
	dupeMe := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me", nil, "", false))
	dupe := h.do(http.MethodPost, "/api/v1/me/username:update", map[string]any{
		"username": "Renamed_Root", "current_password": "InvitePass-123",
		"expected_revision": dupeMe["revision"], "reason": "collision",
	}, "", true)
	require.Equal(t, http.StatusConflict, dupe.Code)
	require.Contains(t, dupe.Body.String(), "USERNAME_EXISTS")
	require.True(t, strings.Contains(dupe.Body.String(), "USERNAME_EXISTS"))
}

func TestOrgExplainAllowAndExpiredAssignment(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "explain-more")
	fixtureStepUp(h)
	ctx := context.Background()
	orgIDNum := parseID(t, orgID)
	authCtx := authorization.Organization(orgIDNum)

	// The owner holds the built-in grant, so the same explain path allows.
	allowed := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/authorization:explain?"+
		"user_id=1&operation=organization.department.manage", nil, "", false)
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
	require.Equal(t, true, decode[map[string]any](t, allowed)["allowed"])

	// An expired custom assignment no longer contributes a source.
	member := fixtureUserWithEmail(t, h, "expired_assign", "expired_assign@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "expired_assign", "role": "member", "reason": "explain test",
	}, "", true).Code)
	role, err := h.svc.OrgIAM.CreateRole(ctx, nil, authCtx, &biz.Role{
		Code: "expired_reader", Name: "Expired Reader", Status: biz.RoleStatusActive,
	})
	require.NoError(t, err)
	_, err = h.svc.OrgIAM.PutRoleGrants(ctx, nil, authCtx, role.ID, []biz.Grant{
		{Operation: biz.PermOrgDepartmentManage, Effect: authorization.Allow, Scope: authorization.Scope{All: true}},
	}, role.Revision)
	require.NoError(t, err)
	_, err = h.svc.OrgIAM.CreateAssignment(ctx, nil, authCtx, &biz.Assignment{
		UserID: member.ID, RoleID: role.ID, Boundary: authorization.Scope{All: true},
		StartsAt: time.Now().Add(-2 * time.Hour), ExpiresAt: ptrTime(time.Now().Add(-time.Hour)),
		Origin: biz.OriginExplicit,
	})
	require.NoError(t, err)
	denied := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/authorization:explain?"+
		"user_id="+strconv.FormatInt(member.ID, 10)+"&operation=organization.department.manage", nil, "", false)
	require.Equal(t, http.StatusOK, denied.Code, denied.Body.String())
	require.Equal(t, false, decode[map[string]any](t, denied)["allowed"])
}

func ptrTime(v time.Time) *time.Time { return &v }

func TestOrgAuditDownloadRequiresCurrentPolicyRevision(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "policy-org")
	fixtureStepUp(h)
	job := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/audits:export",
		map[string]any{"reason": "policy review"}, "", true))
	path := "/api/v1/orgs/" + orgID + "/audits/exports/" + job["id"].(string) + "/download"
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, path, nil, "", false).Code)
	_, err := h.svc.Policy.BumpPolicyRevision(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, h.do(http.MethodGet, path, nil, "", false).Code)
}

func TestOrgExplainReportsDenySource(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := createTestOrg(t, h, "explain-deny")
	fixtureStepUp(h)
	ctx := context.Background()
	authCtx := authorization.Organization(parseID(t, orgID))
	member := fixtureUserWithEmail(t, h, "deny_member", "deny_member@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "deny_member", "role": "admin", "reason": "deny test",
	}, "", true).Code)
	// A deny grant written directly at the repository level is still visible to
	// the same evaluation path used by the real explain endpoint.
	role, err := h.svc.OrgIAM.CreateRole(ctx, nil, authCtx, &biz.Role{
		Code: "deny_role", Name: "Deny Role", Status: biz.RoleStatusActive,
	})
	require.NoError(t, err)
	_, err = h.svc.OrgIAM.PutRoleGrants(ctx, nil, authCtx, role.ID, []biz.Grant{
		{Operation: biz.PermOrgDepartmentManage, Effect: authorization.Deny, Scope: authorization.Scope{All: true}},
	}, role.Revision)
	require.NoError(t, err)
	_, err = h.svc.OrgIAM.CreateAssignment(ctx, nil, authCtx, &biz.Assignment{
		UserID: member.ID, RoleID: role.ID, Boundary: authorization.Scope{All: true},
		StartsAt: time.Now().Add(-time.Minute), Origin: biz.OriginExplicit,
	})
	require.NoError(t, err)
	reply := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/iam/authorization:explain?"+
		"user_id="+strconv.FormatInt(member.ID, 10)+"&operation=organization.department.manage", nil, "", false)
	require.Equal(t, http.StatusOK, reply.Code, reply.Body.String())
	body := decode[map[string]any](t, reply)
	require.Equal(t, false, body["allowed"], "an explicit deny must override the built-in allow")
	sources := body["sources"].([]any)
	require.NotEmpty(t, sources)
}

func TestSinglePreviewMatchesRealAssignment(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	role := iamFixtureRole(t, h, "preview_role", biz.Grant{
		Operation: "identity.user.list", Effect: authorization.Allow,
		Scope: authorization.Scope{All: true},
	})
	memberRoleID := strconv.FormatInt(role.ID, 10)
	target := fixtureUserWithEmail(t, h, "preview_target", "preview_target@example.com")
	targetID := strconv.FormatInt(target.ID, 10)
	policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(t, err)

	preview := h.do(http.MethodPost, "/api/v1/admin/iam/assignments:preview", map[string]any{
		"user_id": targetID, "role_id": memberRoleID, "boundary": map[string]any{"all": true},
	}, "", true)
	require.Equal(t, http.StatusOK, preview.Code, preview.Body.String())
	previewBody := decode[map[string]any](t, preview)
	require.Equal(t, true, previewBody["eligible"])
	previewOps := map[string]bool{}
	for _, raw := range previewBody["permissions"].([]any) {
		previewOps[raw.(map[string]any)["operation"].(string)] = true
	}

	created := h.do(http.MethodPost, "/api/v1/admin/iam/assignments", map[string]any{
		"user_id": targetID, "role_id": memberRoleID, "boundary": map[string]any{"all": true},
		"reason": "preview consistency", "expected_policy_revision": strconv.FormatUint(policy, 10),
	}, "", true)
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	grants, currentPolicy, err := h.svc.EffectivePermissions(context.Background(), target.ID, nil)
	require.NoError(t, err)
	require.Greater(t, currentPolicy, policy)
	for _, g := range grants {
		if previewOps[g.Operation] == false && g.RoleCode == "preview_role" {
			require.Fail(t, "preview omitted a permission granted by the real assignment", g.Operation)
		}
	}
}

func TestArchivedOrganizationReleasesQuota(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	current := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/organization", nil, "", false))
	require.Equal(t, http.StatusOK, h.do(http.MethodPatch, "/api/v1/admin/settings/organization", map[string]any{
		"quota_enabled": true, "max_owned_per_user": 1, "count_archived": false,
		"update_mask":       "quota_enabled,max_owned_per_user,count_archived",
		"expected_revision": current["revision"], "reason": "archive release",
	}, "", true).Code)
	fixtureUserWithEmail(t, h, "archive_user", "archive@example.com")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	require.Equal(t, http.StatusOK, h.login("archive_user", "InvitePass-123").Code)
	orgID := createTestOrg(t, h, "archive-a")
	blocked := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "archive-b", "name": "B"}, "", true)
	require.Equal(t, http.StatusConflict, blocked.Code)
	fixtureStepUp(h)
	archived := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+":archive", map[string]any{
		"expected_revision": "1", "reason": "release quota",
	}, "", true)
	require.Equal(t, http.StatusOK, archived.Code, archived.Body.String())
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/orgs",
		map[string]any{"code": "archive-b", "name": "B"}, "", true).Code)
}

func disabledRevision(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[map[string]any](t, rec)["revision"].(string)
}

func TestProviderViewIsReadOnlyAndToggleEnabled(t *testing.T) {
	h := newHarness(t)
	// The harness uses an explicit provider registry; add github to emulate a
	// deployment with configured credentials.
	h.svc.OAuth["github"] = mockOAuthProvider{}
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	view := h.do(http.MethodGet, "/api/v1/admin/settings/providers", nil, "", false)
	require.Equal(t, http.StatusOK, view.Code)
	body := view.Body.String()
	require.Contains(t, body, "credential_configured\":true")
	require.NotContains(t, body, "client_secret\":\"")
	fixtureStepUp(h)
	auth := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/admin/settings/auth", nil, "", false))
	policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(t, err)
	// Only "mock" is enabled: github must not appear in the login entry points.
	disabled := h.do(http.MethodPatch, "/api/v1/admin/settings/auth", map[string]any{
		"providers": []string{"mock"}, "update_mask": "providers",
		"expected_revision": auth["revision"], "reason": "disable github",
	}, "", true)
	require.Equal(t, http.StatusOK, disabled.Code, disabled.Body.String())
	beforeContext := h.do(http.MethodGet, "/api/v1/auth/context", nil, "", false).Body.String()
	require.NotContains(t, beforeContext, "github")
	updated := h.do(http.MethodPatch, "/api/v1/admin/settings/auth", map[string]any{
		"providers": []string{"mock", "github"}, "update_mask": "providers",
		"expected_revision": disabledRevision(t, disabled), "reason": "enable github",
	}, "", true)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	after, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(t, err)
	require.Greater(t, after, policy, "provider enable must advance the policy revision")
	afterContext := h.do(http.MethodGet, "/api/v1/auth/context", nil, "", false).Body.String()
	require.Contains(t, afterContext, "github", "enabling a provider must change the login entry points")
}
