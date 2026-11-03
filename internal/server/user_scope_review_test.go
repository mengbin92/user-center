package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
)

func TestCreateUserCannotAssignPrivilegedRolesOrSetPasswordWithoutCredentialAuthority(t *testing.T) {
	h := newHarness(t)
	actor := iamFixtureUser(t, h, "user_creator")
	creator := iamFixtureRole(t, h, "user_create_only", biz.Grant{Operation: "identity.user.create", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, actor.ID, creator.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "password_denied", "initial_password": "InitialPass-123", "reason": "review"}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")
	admin, err := h.svc.IAM.GetRoleByCode(context.Background(), nil, "admin")
	require.NoError(t, err)
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "privileged_denied", "email": "denied@example.com", "role_ids": []string{strconv.FormatInt(admin.ID, 10)}, "reason": "review"}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	_, err = h.svc.Users.GetByUsername(context.Background(), nil, "privileged_denied")
	require.ErrorIs(t, err, biz.ErrUserNotFound)
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "ordinary_member", "email": "member@example.com", "reason": "review"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)
	roles := created["roles"].([]any)
	require.Len(t, roles, 1)
	require.Equal(t, "member", roles[0].(map[string]any)["code"])
	credentialManager := iamFixtureRole(t, h, "credential_creator", biz.Grant{Operation: "identity.user.credential.update", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, actor.ID, credentialManager.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "stepup_denied", "initial_password": "InitialPass-123", "reason": "review"}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "STEP_UP_REQUIRED")
	fixtureStepUp(h)
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{"username": "password_member", "initial_password": "InitialPass-123", "reason": "review"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.login("password_member", "InitialPass-123")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, true, decode[map[string]any](t, rec)["password_change_required"])
}

func TestUserListAndOverviewApplyAllowAndDenyBeforeCountingAndPagination(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := iamFixtureUser(t, h, "scope_observer")
	first := iamFixtureUser(t, h, "scope_first")
	second := iamFixtureUser(t, h, "scope_second")
	hidden := iamFixtureUser(t, h, "scope_hidden")
	second.Status = biz.UserStatusDisabled
	_, err := h.svc.Users.Update(ctx, nil, second, second.Revision)
	require.NoError(t, err)
	reader := iamFixtureRole(t, h, "scoped_list", biz.Grant{Operation: "identity.user.list", Effect: authorization.Allow, Scope: authorization.Scope{All: true}}, biz.Grant{Operation: "identity.user.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	denier := iamFixtureRole(t, h, "list_deny", biz.Grant{Operation: "identity.user.list", Effect: authorization.Deny, Scope: authorization.Scope{UserIDs: []int64{hidden.ID}}}, biz.Grant{Operation: "identity.user.read", Effect: authorization.Deny, Scope: authorization.Scope{UserIDs: []int64{hidden.ID}}})
	iamFixtureAssign(t, h, actor.ID, reader.ID, authorization.Scope{UserIDs: []int64{first.ID, second.ID, hidden.ID}})
	iamFixtureAssign(t, h, actor.ID, denier.ID, authorization.Scope{All: true})
	now := time.Now().UTC()
	for i, u := range []*biz.User{first, second, hidden, actor} {
		id := "scope-session-" + strconv.Itoa(i)
		require.NoError(t, h.svc.Sessions.Create(ctx, nil, &biz.Session{ID: id, UserID: u.ID, ApplicationCode: biz.ApplicationCode, TokenHash: biz.HashToken(id), IssuedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), IdentityVersion: u.IdentityVersion, Revision: 1}))
	}
	for i, e := range []biz.SecurityEvent{
		{UserID: first.ID, Kind: "login", Result: "success", OccurredAt: now},
		{UserID: first.ID, Kind: "login", Result: "failure", OccurredAt: now},
		{UserID: second.ID, Kind: "login", Result: "denied", OccurredAt: now},
		{UserID: hidden.ID, Kind: "login", Result: "success", OccurredAt: now},
		{UserID: hidden.ID, Kind: "login", Result: "failure", OccurredAt: now},
		{UserID: first.ID, Kind: "login", Result: "success", OccurredAt: now.Add(-25 * time.Hour)},
		{UserID: first.ID, Kind: "password_change", Result: "success", OccurredAt: now},
	} {
		e.ID = "scope-event-" + strconv.Itoa(i)
		require.NoError(t, h.svc.Events.Append(ctx, nil, &e))
	}
	require.NoError(t, h.svc.MFA.Save(ctx, nil, &biz.MFAState{UserID: first.ID, Secret: "JBSWY3DPEHPK3PXP"}))
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec := h.do(http.MethodGet, "/api/v1/admin/users?page_size=1", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	page := decode[map[string]any](t, rec)
	require.Equal(t, "2", page["meta"].(map[string]any)["total_size"])
	items := page["items"].([]any)
	require.Len(t, items, 1)
	seen := []string{items[0].(map[string]any)["id"].(string)}
	next := page["meta"].(map[string]any)["next_page_token"].(string)
	require.NotEmpty(t, next)
	rec = h.do(http.MethodGet, "/api/v1/admin/users?page_size=1&page_token="+url.QueryEscape(next), nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	page = decode[map[string]any](t, rec)
	require.Equal(t, "2", page["meta"].(map[string]any)["total_size"])
	items = page["items"].([]any)
	require.Len(t, items, 1)
	seen = append(seen, items[0].(map[string]any)["id"].(string))
	require.ElementsMatch(t, []string{strconv.FormatInt(first.ID, 10), strconv.FormatInt(second.ID, 10)}, seen)
	require.Empty(t, page["meta"].(map[string]any)["next_page_token"])
	rec = h.do(http.MethodGet, "/api/v1/admin/users/"+strconv.FormatInt(hidden.ID, 10), nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/admin/overview", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	stats := decode[map[string]any](t, rec)
	for field, expected := range map[string]string{"total_users": "2", "enabled_users": "1", "disabled_users": "1", "mfa_users": "1", "active_sessions": "2", "logins_24h": "1", "failed_logins_24h": "2"} {
		require.Equal(t, expected, stats[field], field+": "+rec.Body.String())
	}
}

func TestUserExportRejectsChangedPolicySessionRolesAndDifferentSession(t *testing.T) {
	for _, change := range []string{"policy", "session_roles", "new_session"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			actor := iamFixtureUser(t, h, "export_actor")
			role := iamFixtureRole(t, h, "exporter", biz.Grant{Operation: "identity.user.export", Effect: authorization.Allow, Scope: authorization.Scope{All: true}}, biz.Grant{Operation: "audit.read", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
			iamFixtureAssign(t, h, actor.ID, role.ID, authorization.Scope{All: true})
			require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
			rec := h.management(http.MethodPost, "/api/v1/admin/audits:export", map[string]any{"fields": []string{"event_id"}, "reason": "review"}, "", true)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			rec = h.management(http.MethodPost, "/api/v1/admin/users:export", map[string]any{"fields": []string{"id", "username"}, "reason": "review"}, "", true)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			job := decode[map[string]any](t, rec)
			path := "/api/v1/admin/exports/" + job["id"].(string)
			rec = h.do(http.MethodGet, path+"/download", nil, "", false)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			switch change {
			case "policy":
				_, err := h.svc.Policy.BumpPolicyRevision(ctx, nil)
				require.NoError(t, err)
			case "session_roles":
				rec = h.do(http.MethodGet, "/api/v1/me/session-roles", nil, "", false)
				revision := decode[map[string]any](t, rec)["revision"]
				rec = h.do(http.MethodPut, "/api/v1/me/session-roles", map[string]any{"role_ids": []string{strconv.FormatInt(role.ID, 10)}, "expected_revision": revision}, "", true)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			case "new_session":
				require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
			}
			rec = h.do(http.MethodGet, path, nil, "", false)
			if change == "new_session" {
				require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			} else {
				require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			}
			rec = h.do(http.MethodGet, path+"/download", nil, "", false)
			require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "export_actor")
		})
	}
}

func TestAuditExportDownloadRequiresAuditExportPermission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := iamFixtureUser(t, h, "audit_exporter")
	role := iamFixtureRole(t, h, "audit_export_role", biz.Grant{Operation: "audit.export", Effect: authorization.Allow, Scope: authorization.Scope{All: true}})
	iamFixtureAssign(t, h, actor.ID, role.ID, authorization.Scope{All: true})
	require.Equal(t, http.StatusOK, h.login(actor.Username, "FixturePass-123").Code)
	rec := h.management(http.MethodPost, "/api/v1/admin/audits:export", map[string]any{"fields": []string{"event_id"}, "reason": "review"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	job := decode[map[string]any](t, rec)
	path := "/api/v1/admin/exports/" + job["id"].(string)
	rec = h.do(http.MethodGet, path+"/download", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	permission, err := h.svc.IAM.GetPermissionByCode(ctx, nil, "audit.export")
	require.NoError(t, err)
	permission.Status = biz.PermissionStatusDisabled
	_, err = h.svc.IAM.UpdatePermission(ctx, nil, permission, permission.Revision)
	require.NoError(t, err)
	rec = h.do(http.MethodGet, path, nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, path+"/download", nil, "", false)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}
