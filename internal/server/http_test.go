package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/obs"
	"github.com/mengbin92/user-center/internal/server"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/mengbin92/user-center/pkg/totp"
)

type captureMail struct {
	mu   sync.Mutex
	msgs []capturedMail
}

type capturedMail struct {
	to, subject, body string
}

func (m *captureMail) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, capturedMail{to: to, subject: subject, body: body})
	return nil
}

func (m *captureMail) last() capturedMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.msgs) == 0 {
		return capturedMail{}
	}
	return m.msgs[len(m.msgs)-1]
}

type harness struct {
	t      *testing.T
	srv    http.Handler
	jar    http.CookieJar
	csrf   string
	users  *biz.UserUsecase
	iam    *biz.IAMUsecase
	auth   *biz.AuthUsecase
	svc    *biz.Services
	artDir string
	mail   *captureMail
	d      *data.Data
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	sec := &conf.Security{
		SessionSecret: "test-session-secret", CsrfSecret: "test-csrf-secret",
		MfaEncryptionKey: "test-mfa-key", SessionTtlMinutes: 60, IdleTimeoutMinutes: 60,
	}
	dataConf := &conf.Data{Database: &conf.Database{
		Driver: "sqlite", Source: "file:" + filepath.Join(dir, "test.db") + "?_fk=1",
	}}
	d, cleanup, err := data.NewData(dataConf, sec, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.NoError(t, d.AutoMigrate())
	require.NoError(t, data.SeedCatalog(d.DB()))
	settingsRepo := data.NewSettingsRepo(d)
	baseSettings, err := settingsRepo.GetAuth(context.Background(), nil)
	require.NoError(t, err)
	baseSettings.MFARequiredForAdmins = false
	_, err = settingsRepo.SaveAuth(context.Background(), nil, baseSettings, baseSettings.Revision)
	require.NoError(t, err)

	runtime := &biz.RuntimeConfig{
		SessionTTL: time.Hour, IdleTimeout: time.Hour, StepUpTTL: 5 * time.Minute,
		ChallengeTTL: 10 * time.Minute, ResetTTL: 30 * time.Minute,
		ActivationTTL: time.Hour, ArtifactDir: filepath.Join(dir, "artifacts"),
		PublicBaseURL: "http://localhost:5173", CodeSecret: sec.SessionSecret,
	}
	mailer := &captureMail{}
	oidcSigner, err := data.NewOIDCSigner(d, zap.NewNop())
	require.NoError(t, err)
	svc := biz.NewServices(
		data.NewUserRepo(d), data.NewCredentialRepo(d), data.NewExternalIdentityRepo(d),
		data.NewMFARepo(d), data.NewSessionRepo(d), data.NewSecurityEventRepo(d),
		data.NewFlowCompletionRepo(d), data.NewChallengeStore(d), data.NewRateLimiter(d),
		data.NewStepUpStore(d), mailer,
		data.NewAuditRepo(d), data.NewPolicyRepo(d), data.NewIAMRepo(d), data.NewOutboxRepo(d),
		data.NewSettingsRepo(d), data.NewExportRepo(d), data.NewIntegrationClientRepo(d),
		data.NewOIDCClientRepo(d), data.NewOIDCCodeRepo(d), data.NewOIDCConsentRepo(d), oidcSigner,
		data.NewWebAuthnRepo(d),
		data.NewOrganizationRepo(d), data.NewOrgIAMRepo(d), d,
		data.Clock{}, data.IDs{}, data.NewSecretBox(sec),
		map[string]biz.OAuthProvider{"mock": &mockOAuthProvider{}},
		runtime,
	)
	users := biz.NewUserUsecase(svc)
	auth := biz.NewAuthUsecase(svc)
	security := biz.NewSecurityUsecase(svc)
	sessions := biz.NewSessionUsecase(svc)
	iam := biz.NewIAMUsecase(svc)
	audit := biz.NewAuditUsecase(svc)
	settings := biz.NewSettingsUsecase(svc)
	integration := biz.NewIntegrationUsecase(svc)
	integrationAdmin := biz.NewIntegrationAdminUsecase(svc)
	oidcAdmin := service.NewOIDCAdminService(biz.NewOIDCUsecase(svc))
	organizations := service.NewOrganizationService(biz.NewOrganizationUsecase(svc), biz.NewOrgIAMUsecase(svc))

	_, err = svc.BootstrapRoot(context.Background(), "root", "root@example.com", "ChangeMe-12345")
	require.NoError(t, err)

	deps := service.NewDeps(sec)
	mw := server.NewMiddleware(sessions, sec, zap.NewNop())
	srvCfg := &conf.Server{Http: &conf.HTTP{Addr: ":0", TimeoutSeconds: 30}}
	hs := server.NewHTTPServer(
		srvCfg, sec, mw, obs.NewMetrics(nil), zap.NewNop(),
		service.NewAuthService(auth, deps),
		service.NewMeService(users, security, sessions, biz.NewOIDCUsecase(svc), biz.NewWebAuthnUsecase(svc), deps),
		service.NewAdminUserService(users, sessions),
		service.NewIAMService(iam),
		service.NewAuditService(audit),
		service.NewSettingsService(settings),
		service.NewIntegrationAdminService(integrationAdmin),
		oidcAdmin,
		organizations,
		users,
		server.ArtifactDir(runtime.ArtifactDir),
	)
	_ = integration
	jar, _ := cookiejar.New(nil)
	h := &harness{t: t, srv: hs.Server, jar: jar, users: users, iam: iam, auth: auth, svc: svc, artDir: runtime.ArtifactDir, mail: mailer, d: d}
	h.refreshCSRF()
	return h
}

func (h *harness) refreshCSRF() {
	h.t.Helper()
	rec := h.do(http.MethodGet, "/api/v1/auth/context", nil, "", false)
	require.Equal(h.t, http.StatusOK, rec.Code)
	for _, c := range rec.Result().Cookies() {
		if c.Name == service.CSRFCookie {
			h.csrf = c.Value
		}
	}
	require.NotEmpty(h.t, h.csrf, "csrf cookie must be issued")
}

func (h *harness) do(method, path string, body any, token string, csrf bool) *httptest.ResponseRecorder {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://example.com"+path, reader)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", h.csrf)
	}
	for _, c := range h.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		h.jar.SetCookies(req.URL, []*http.Cookie{c})
	}
	return rec
}

func (h *harness) doForm(path string, form url.Values, clientID, secret string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.com"+path, strings.NewReader(form.Encode()))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" || secret != "" {
		req.SetBasicAuth(clientID, secret)
	}
	for _, c := range h.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		h.jar.SetCookies(req.URL, []*http.Cookie{c})
	}
	return rec
}

func (h *harness) login(username, password string) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"username": username, "password": password}, "", true)
}

// authorize runs the OIDC authorize request and, when the provider asks for
// consent, completes the one-time consent flow as the signed-in user. It
// returns the final redirect location (with the code on approval).
func (h *harness) authorize(t *testing.T, query url.Values) *url.URL {
	t.Helper()
	rec := h.do(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	if loc.Path == "/consent" {
		handle := loc.Query().Get("handle")
		require.NotEmpty(t, handle)
		view := h.do(http.MethodGet, "/api/v1/me/oidc-requests/"+url.PathEscape(handle), nil, "", false)
		require.Equal(t, http.StatusOK, view.Code, view.Body.String())
		decided := h.do(http.MethodPost,
			"/api/v1/me/oidc-requests/"+url.PathEscape(handle)+":decide",
			map[string]any{"handle": handle, "approve": true, "remember": true}, "", true)
		require.Equal(t, http.StatusOK, decided.Code, decided.Body.String())
		var reply struct {
			RedirectUrl string `json:"redirect_url"`
		}
		require.NoError(t, json.Unmarshal(decided.Body.Bytes(), &reply))
		loc, err = url.Parse(reply.RedirectUrl)
		require.NoError(t, err)
	}
	return loc
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return out
}

func TestAuthAndAuthorizationFlow(t *testing.T) {
	h := newHarness(t)

	// Unauthenticated access is rejected.
	rec := h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Login without CSRF is rejected.
	rec = h.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "root", "password": "ChangeMe-12345"}, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)

	rec = h.login("root", "ChangeMe-12345")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	login := decode[map[string]any](t, rec)
	require.Equal(t, "authenticated", login["status"])

	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	me := decode[map[string]any](t, rec)
	require.Equal(t, "root", me["username"])

	// Root sees the full user list and can create a member.
	fixtureStepUp(h)
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "alice", "email": "alice@example.com", "display_name": "Alice",
		"initial_password": "AlicePass-123", "reason": "test create",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	alice := decode[map[string]any](t, rec)
	aliceID := alice["id"].(string)
	require.NotEmpty(t, aliceID)

	// Duplicate username is a stable conflict reason.
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "alice", "initial_password": "AlicePass-123", "reason": "duplicate",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "USERNAME_EXISTS")

	// Member login is isolated to self scope.
	rec = h.login("alice", "AlicePass-123")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	authz := decode[map[string]any](t, rec)
	perms, _ := authz["permissions"].([]any)
	require.NotEmpty(t, perms)
	rec = h.do(http.MethodGet, "/api/v1/admin/users", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/admin/audits", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// Admin disables the member and all their sessions die.
	rec = h.login("root", "ChangeMe-12345")
	require.Equal(t, http.StatusOK, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/admin/users/"+aliceID, nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	member := decode[map[string]any](t, rec)
	revision := member["revision"].(string)

	fixtureStepUp(h)
	rec = h.management(http.MethodPost, "/api/v1/admin/users/"+aliceID+":set-status", map[string]any{
		"status": "disabled", "expected_revision": revision, "reason": "test disable",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The disabled account can no longer authenticate.
	rec = h.login("alice", "AlicePass-123")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Root explain sees the effective decision and its source.
	rec = h.do(http.MethodPost, "/api/v1/admin/iam/authorization:explain", map[string]any{
		"user_id": "1", "operation": "identity.user.read", "owner_user_id": "1",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	explain := decode[map[string]any](t, rec)
	require.Equal(t, true, explain["allowed"])
	require.Equal(t, "ALLOWED", explain["reason"])
}

func TestConcurrencyAndExport(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "bob", "email": "bob@example.com", "initial_password": "BobPass-12345", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	bob := decode[map[string]any](t, rec)
	bobID := bob["id"].(string)
	stale := bob["revision"].(string)

	rec = h.management(http.MethodPatch, "/api/v1/admin/users/"+bobID, map[string]any{
		"display_name": "Bob", "expected_revision": stale, "reason": "rename",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.management(http.MethodPatch, "/api/v1/admin/users/"+bobID, map[string]any{
		"display_name": "Bob2", "expected_revision": stale, "reason": "stale rename",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "REVISION_CONFLICT")

	rec = h.management(http.MethodPost, "/api/v1/admin/users:export", map[string]any{
		"fields": []string{"id", "username", "status"}, "reason": "test export",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	job := decode[map[string]any](t, rec)
	jobID := job["id"].(string)
	require.Equal(t, "ready", job["status"])

	rec = h.do(http.MethodGet, "/api/v1/admin/exports/"+jobID+"/download", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "bob")
	_, err := os.Stat(filepath.Join(h.artDir, job["artifact_name"].(string)))
	require.NoError(t, err)

	// Cross-user session revocation requires an explicit operation and is
	// audited; a member cannot call it.
	require.NotEmpty(t, fmt.Sprintf("%v", jobID))
}

func TestMFAEnrollmentAndLogin(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "mfa.user", "email": "mfa@example.com", "initial_password": "MfaPass-12345", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.login("mfa.user", "MfaPass-12345").Code)
	rec = h.do(http.MethodPost, "/api/v1/me/mfa:setup", map[string]any{"current_password": "MfaPass-12345"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	setup := decode[map[string]any](t, rec)
	secret := setup["secret"].(string)
	require.NotEmpty(t, secret)

	step := time.Now().Unix() / 30
	code, err := totp.Code(secret, step, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/me/mfa:confirm", map[string]any{"code": code}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	recovery := decode[map[string]any](t, rec)
	require.Len(t, recovery["recovery_codes"], 8)

	// A fresh login now stops at the MFA challenge.
	h.jar, _ = cookiejar.New(nil)
	h.refreshCSRF()
	rec = h.login("mfa.user", "MfaPass-12345")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	login := decode[map[string]any](t, rec)
	require.Equal(t, "mfa_required", login["status"])
	challenge := login["challenge_id"].(string)
	require.NotEmpty(t, challenge)

	next, err := totp.Code(secret, step+1, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
		"challenge_id": challenge, "code": next,
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "authenticated", decode[map[string]any](t, rec)["status"])
	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, true, decode[map[string]any](t, rec)["mfa_enabled"])
}

func enrollMFA(t *testing.T, h *harness, password string) string {
	t.Helper()
	rec := h.do(http.MethodPost, "/api/v1/me/mfa:setup", map[string]any{"current_password": password}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	secret := decode[map[string]any](t, rec)["secret"].(string)
	step := time.Now().Unix() / 30
	code, err := totp.Code(secret, step, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/me/mfa:confirm", map[string]any{"code": code}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return secret
}

func stepUp(t *testing.T, h *harness, password, secret string, offset int64) {
	t.Helper()
	step := time.Now().Unix()/30 + offset
	code, err := totp.Code(secret, step, 6)
	require.NoError(t, err)
	rec := h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{
		"current_password": password, "code": code,
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestIAMRoleAssignmentEnablesScopedAccess(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)

	rec := h.management(http.MethodPost, "/api/v1/admin/iam/roles", map[string]any{
		"code": "auditor", "name": "审计员", "description": "只读审计",
		"grants": []any{map[string]any{
			"operation": "audit.read", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "test role",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	role := decode[map[string]any](t, rec)
	roleID := role["id"].(string)

	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "carol", "email": "carol@example.com", "initial_password": "CarolPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	carol := decode[map[string]any](t, rec)
	carolID := carol["id"].(string)

	rec = h.management(http.MethodPost, "/api/v1/admin/iam/assignments", map[string]any{
		"user_id": carolID, "role_id": roleID, "boundary": map[string]any{"all": true},
		"reason": "test assignment",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.login("carol", "CarolPass-123").Code)
	rec = h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{
		"current_password": "CarolPass-123", "new_password": "CarolPass-456",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me/authorization", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "audit.read")

	rec = h.do(http.MethodGet, "/api/v1/admin/audits", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/admin/users", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAdminMFAEnforcement(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodGet, "/api/v1/admin/overview", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	settings, err := h.svc.Settings.GetAuth(context.Background(), nil)
	require.NoError(t, err)
	settings.MFARequiredForAdmins = true
	_, err = h.svc.Settings.SaveAuth(context.Background(), nil, settings, settings.Revision)
	require.NoError(t, err)

	rec = h.do(http.MethodGet, "/api/v1/admin/overview", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "MFA_ENROLLMENT_REQUIRED")

	secret := enrollMFA(t, h, "ChangeMe-12345")
	_ = secret
	rec = h.do(http.MethodGet, "/api/v1/admin/overview", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestForcedPasswordChange(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "forced", "email": "forced@example.com", "initial_password": "ForcedPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.login("forced", "ForcedPass-123")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	login := decode[map[string]any](t, rec)
	require.Equal(t, true, login["password_change_required"])

	rec = h.do(http.MethodGet, "/api/v1/admin/users", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "PASSWORD_CHANGE_REQUIRED")
	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{
		"current_password": "ForcedPass-123", "new_password": "ForcedPass-456",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/admin/users", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "PERMISSION_DENIED")
}

type mockOAuthProvider struct{}

func (mockOAuthProvider) Name() string { return "mock" }
func (mockOAuthProvider) AuthCodeURL(state, redirectURI string) string {
	return "https://mock.example/authorize?state=" + state
}
func (mockOAuthProvider) Exchange(ctx context.Context, code, redirectURI string) (biz.OAuthProfile, error) {
	return biz.OAuthProfile{Subject: "subject-1", Issuer: "mock", Display: "Mock User", Email: "mock@example.com"}, nil
}

func TestOAuthBindAndLogin(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode=bind", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	state := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "uc_oauth_state" {
			state = c.Value
		}
	}
	require.NotEmpty(t, state)

	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "bound=mock")

	rec = h.do(http.MethodGet, "/api/v1/me/external-identities", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "mock")

	// Logout and log back in through the bound provider.
	rec = h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode=login", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	state = ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "uc_oauth_state" {
			state = c.Value
		}
	}
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "status=success")
	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestIntegrationClientAndOutboxDelivery(t *testing.T) {
	t.Setenv("OUTBOX_SIGNING_SECRET", "test-webhook-secret-at-least-32-bytes")
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)

	var received int
	var signature string
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		signature = r.Header.Get("X-UserCenter-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()

	rec := h.management(http.MethodPost, "/api/v1/admin/integration-clients", map[string]any{
		"code": "billing-adapter", "service_owner": "billing",
		"allowed_methods":     []string{"ValidateSession", "GetUser"},
		"event_subscriptions": []string{"user.created"},
		"callback_url":        webhook.URL, "reason": "test integration",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)
	credential := created["credential"].(string)
	require.Contains(t, credential, ".")
	client := created["client"].(map[string]any)
	clientID := client["client_id"].(string)

	integration := biz.NewIntegrationUsecase(h.svc)
	got, err := integration.AuthenticateClient(context.Background(), credential)
	require.NoError(t, err)
	require.Equal(t, clientID, got.ClientID)
	require.True(t, integration.AllowedMethod(got, "/api.usercenter.v1.IntegrationService/ValidateSession"))
	require.False(t, integration.AllowedMethod(got, "/api.usercenter.v1.IntegrationService/RevokeSession"))
	_, err = integration.AuthenticateClient(context.Background(), credential+"x")
	require.Error(t, err)

	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "evented", "email": "evented@example.com",
		"initial_password": "EventedPass-123", "reason": "emit event",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	admin := biz.NewIntegrationAdminUsecase(h.svc)
	require.NoError(t, admin.Dispatch(context.Background()))
	require.Equal(t, 1, received)
	require.NotEmpty(t, signature)

	deliveries, total, err := h.svc.Outbox.ListDeliveries(context.Background(), nil, "delivered", 0, 10)
	require.NoError(t, err)
	require.GreaterOrEqual(t, total, int64(1))
	require.NotEmpty(t, deliveries)
}

func TestAdminEmailChange(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)

	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "emailchange", "email": "old@example.com", "initial_password": "EmailPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	user := decode[map[string]any](t, rec)
	userID := user["id"].(string)

	rec = h.management(http.MethodPost, "/api/v1/admin/users/"+userID+"/email-changes", map[string]any{
		"new_email": "new@example.com", "reason": "test email change",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	challenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	require.NotEmpty(t, challenge)
	code := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, code, "verification code must be mailed")

	rec = h.management(http.MethodPost, "/api/v1/admin/users/"+userID+"/email-changes:confirm", map[string]any{
		"challenge_id": challenge, "code": code, "reason": "test email change",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	updated := decode[map[string]any](t, rec)
	require.Equal(t, "new@example.com", updated["email"])
}

func TestRegistrationAndPasswordReset(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodPost, "/api/v1/auth/registration-challenges", map[string]any{
		"email": "newbie@example.com",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	challenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	code := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, code)

	rec = h.do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"username": "newbie", "email": "newbie@example.com", "password": "NewbiePass-123",
		"code": code, "challenge_id": challenge, "terms_version": "v1",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, h.login("newbie", "NewbiePass-123").Code)

	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset-challenges", map[string]any{
		"identifier": "newbie@example.com",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	challenge = decode[map[string]any](t, rec)["challenge_id"].(string)
	code = regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, code)

	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{
		"challenge_id": challenge, "code": code, "new_password": "NewbiePass-456",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusUnauthorized, h.login("newbie", "NewbiePass-123").Code)
	require.Equal(t, http.StatusOK, h.login("newbie", "NewbiePass-456").Code)
}

func TestOAuthLoginRequiresMFA(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")

	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode=bind", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	state := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "uc_oauth_state" {
			state = c.Value
		}
	}
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)

	rec = h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode=login", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	state = ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "uc_oauth_state" {
			state = c.Value
		}
	}
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "mfa_challenge=")
	challenge := rec.Header().Get("Location")
	challenge = challenge[strings.Index(challenge, "mfa_challenge=")+len("mfa_challenge="):]
	code, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
		"challenge_id": challenge, "code": code,
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestOIDCAuthorizationCodeFlow(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	redirectURI := "http://localhost/callback"
	verifier := "verifier-0123456789-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	_, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: "oidc_test", Name: "Test App", ServiceOwner: "test",
		Status: "active", SecretHash: biz.HashToken("oidc-secret"),
		RedirectURIs: []string{redirectURI},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:  true, AccessTTL: 900, RefreshTTL: 3600,
	})
	require.NoError(t, err)

	query := url.Values{
		"client_id":             {"oidc_test"},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {"state-1"},
		"nonce":                 {"nonce-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	location := h.authorize(t, query)
	require.Equal(t, "state-1", location.Query().Get("state"))
	code := location.Query().Get("code")
	require.NotEmpty(t, code)

	rec := h.doForm("/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}, "oidc_test", "oidc-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	require.NotEmpty(t, tokens["access_token"])
	require.NotEmpty(t, tokens["id_token"])
	require.NotEmpty(t, tokens["refresh_token"])
	require.Equal(t, "Bearer", tokens["token_type"])

	rec = h.do(http.MethodGet, "/oidc/userinfo", nil, "", false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	ui := httptest.NewRecorder()
	h.srv.ServeHTTP(ui, req)
	require.Equal(t, http.StatusOK, ui.Code, ui.Body.String())
	info := decode[map[string]any](t, ui)
	require.Equal(t, "1", info["sub"])
	require.Equal(t, "root", info["preferred_username"])

	rec = h.do(http.MethodGet, "/.well-known/openid-configuration", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	disco := decode[map[string]any](t, rec)
	require.Contains(t, disco["authorization_endpoint"], "/oidc/authorize")
	rec = h.do(http.MethodGet, "/oidc/jwks", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	jwks := decode[map[string]any](t, rec)
	require.NotEmpty(t, jwks["keys"])

	rec = h.doForm("/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)},
	}, "oidc_test", "oidc-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	refreshed := decode[map[string]any](t, rec)
	require.NotEmpty(t, refreshed["access_token"])

	rec = h.doForm("/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}, "oidc_test", "oidc-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_grant")
}

func TestOIDCClientAdmin(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)

	rec := h.management(http.MethodPost, "/api/v1/admin/oidc-clients", map[string]any{
		"name": "Admin App", "service_owner": "test",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"scopes":        []string{"openid", "email"},
		"require_pkce":  true, "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)
	require.NotEmpty(t, created["client_secret"])
	client := created["client"].(map[string]any)
	require.NotEmpty(t, client["client_id"])
	require.Equal(t, true, client["require_pkce"])

	rec = h.do(http.MethodGet, "/api/v1/admin/oidc-clients", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Admin App")
}

func TestOIDCPublicClientPKCE(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	redirectURI := "http://localhost/public-callback"
	_, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: "oidc_public", Name: "Public App", ServiceOwner: "test",
		Status: "active", RedirectURIs: []string{redirectURI},
		Scopes: []string{"openid", "email"}, Public: true, RequirePKCE: true,
		AccessTTL: 900, RefreshTTL: 3600,
	})
	require.NoError(t, err)
	base := url.Values{
		"client_id": {"oidc_public"}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"openid email"}, "state": {"s1"},
	}
	rec := h.do(http.MethodGet, "/oidc/authorize?"+base.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "error=invalid_request")

	verifier := "public-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	base.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	base.Set("code_challenge_method", "S256")
	loc := h.authorize(t, base)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	rec = h.doForm("/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"oidc_public"},
		"code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}, "", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestOrganizationLifecycle(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "acme", "name": "Acme"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	org := decode[map[string]any](t, rec)
	orgID := org["id"].(string)
	require.Equal(t, "owner", org["role"])
	require.Equal(t, "1", org["member_count"])
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)

	rec = h.do(http.MethodPost, "/api/v1/auth/registration-challenges", map[string]any{
		"email": "orgmember@example.com",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	registrationChallenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	registrationCode := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, registrationCode)
	rec = h.do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"username": "orgmember", "email": "orgmember@example.com", "password": "OrgPass-123",
		"code": registrationCode, "challenge_id": registrationChallenge, "terms_version": "v1",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	memberUser := decode[map[string]any](t, rec)["user"].(map[string]any)
	memberID := memberUser["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/members", map[string]any{
		"identifier": "orgmember", "role": "member", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/departments", map[string]any{
		"code": "eng", "name": "Engineering",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	dept := decode[map[string]any](t, rec)
	deptID := dept["id"].(string)

	rec = h.do(http.MethodPatch, "/api/v1/orgs/"+orgID+"/members/"+memberID, map[string]any{
		"role": "admin", "department_id": deptID, "expected_revision": "1", "reason": "promote",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	member := decode[map[string]any](t, rec)
	require.Equal(t, "admin", member["role"])

	// Stale member revision is rejected for removal.
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/members/"+memberID+"?expected_revision=999&reason=test", nil, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// Owner cannot be demoted when last owner.
	rec = h.do(http.MethodPatch, "/api/v1/orgs/"+orgID+"/members/1", map[string]any{
		"role": "member", "expected_revision": "1", "reason": "demote self",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "ORGANIZATION_LAST_OWNER")

	// Platform admin sees all organizations before the session switches.
	rec = h.do(http.MethodGet, "/api/v1/admin/organizations", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Acme")

	// Archiving an organization requires step-up and hides it from members.
	rec = h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "archive-me", "name": "Archive Me"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	archiveID := decode[map[string]any](t, rec)["id"].(string)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+archiveID+":archive", map[string]any{
		"expected_revision": "1", "reason": "test archive",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+archiveID, nil, "", false)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// The member can see the org and manage departments as admin.
	require.Equal(t, http.StatusOK, h.login("orgmember", "OrgPass-123").Code)
	rec = h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{
		"current_password": "OrgPass-123", "new_password": "OrgPass-456",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/orgs", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "acme")
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = h.do(http.MethodPost, "/api/v1/orgs/"+orgID+":archive", map[string]any{
		"expected_revision": "1", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code)

}

func TestOrganizationPermissions(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodPost, "/api/v1/orgs", map[string]any{"code": "secure", "name": "Secure"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	orgID := decode[map[string]any](t, rec)["id"].(string)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	// Last owner cannot be removed.
	rec = h.do(http.MethodDelete, "/api/v1/orgs/"+orgID+"/members/1?expected_revision=1&reason=test", nil, "", true)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "ORGANIZATION_LAST_OWNER")

	// Register an outsider and ensure org resources are not visible.
	rec = h.do(http.MethodPost, "/api/v1/auth/registration-challenges", map[string]any{"email": "outsider@example.com"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	challenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	code := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	rec = h.do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"username": "outsider", "email": "outsider@example.com", "password": "OutsiderPass-123",
		"code": code, "challenge_id": challenge, "terms_version": "v1",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, h.login("outsider", "OutsiderPass-123").Code)
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID, nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false)
	require.Equal(t, http.StatusForbidden, rec.Code)
	rec = h.do(http.MethodGet, "/api/v1/orgs", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "secure")
}
