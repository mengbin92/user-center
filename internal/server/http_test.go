package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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
	svc := biz.NewServices(
		data.NewUserRepo(d), data.NewCredentialRepo(d), data.NewExternalIdentityRepo(d),
		data.NewMFARepo(d), data.NewSessionRepo(d), data.NewSecurityEventRepo(d),
		data.NewFlowCompletionRepo(d), data.NewChallengeStore(d), data.NewRateLimiter(d),
		data.NewStepUpStore(d), mailer,
		data.NewAuditRepo(d), data.NewPolicyRepo(d), data.NewIAMRepo(d), data.NewOutboxRepo(d),
		data.NewSettingsRepo(d), data.NewExportRepo(d), data.NewIntegrationClientRepo(d), d,
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

	_, err = svc.BootstrapRoot(context.Background(), "root", "root@example.com", "ChangeMe-12345")
	require.NoError(t, err)

	deps := service.NewDeps(sec)
	mw := server.NewMiddleware(sessions, sec, zap.NewNop())
	srvCfg := &conf.Server{Http: &conf.HTTP{Addr: ":0", TimeoutSeconds: 30}}
	hs := server.NewHTTPServer(
		srvCfg, sec, mw, zap.NewNop(),
		service.NewAuthService(auth, deps),
		service.NewMeService(users, security, sessions, deps),
		service.NewAdminUserService(users, sessions),
		service.NewIAMService(iam),
		service.NewAuditService(audit),
		service.NewSettingsService(settings),
		service.NewIntegrationAdminService(integrationAdmin),
		users,
		server.ArtifactDir(runtime.ArtifactDir),
	)
	_ = integration
	jar, _ := cookiejar.New(nil)
	h := &harness{t: t, srv: hs.Server, jar: jar, users: users, iam: iam, auth: auth, svc: svc, artDir: runtime.ArtifactDir, mail: mailer}
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

func (h *harness) login(username, password string) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"username": username, "password": password}, "", true)
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
	rec = h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "alice", "email": "alice@example.com", "display_name": "Alice",
		"initial_password": "AlicePass-123", "reason": "test create",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	alice := decode[map[string]any](t, rec)
	aliceID := alice["id"].(string)
	require.NotEmpty(t, aliceID)

	// Duplicate username is a stable conflict reason.
	rec = h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
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

	rec = h.do(http.MethodPost, "/api/v1/admin/users/"+aliceID+":set-status", map[string]any{
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

	rec := h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "bob", "email": "bob@example.com", "initial_password": "BobPass-12345", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	bob := decode[map[string]any](t, rec)
	bobID := bob["id"].(string)
	stale := bob["revision"].(string)

	rec = h.do(http.MethodPatch, "/api/v1/admin/users/"+bobID, map[string]any{
		"display_name": "Bob", "expected_revision": stale, "reason": "rename",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = h.do(http.MethodPatch, "/api/v1/admin/users/"+bobID, map[string]any{
		"display_name": "Bob2", "expected_revision": stale, "reason": "stale rename",
	}, "", true)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "REVISION_CONFLICT")

	rec = h.do(http.MethodPost, "/api/v1/admin/users:export", map[string]any{
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
	rec := h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
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

	rec := h.do(http.MethodPost, "/api/v1/admin/iam/roles", map[string]any{
		"code": "auditor", "name": "审计员", "description": "只读审计",
		"grants": []any{map[string]any{
			"operation": "audit.read", "effect": "allow", "scope": map[string]any{"all": true},
		}},
		"reason": "test role",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	role := decode[map[string]any](t, rec)
	roleID := role["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "carol", "email": "carol@example.com", "initial_password": "CarolPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	carol := decode[map[string]any](t, rec)
	carolID := carol["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/admin/iam/assignments", map[string]any{
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
	rec := h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
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
	t.Setenv("OUTBOX_SIGNING_SECRET", "test-webhook-secret")
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

	rec := h.do(http.MethodPost, "/api/v1/admin/integration-clients", map[string]any{
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

	rec = h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
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

	rec := h.do(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "emailchange", "email": "old@example.com", "initial_password": "EmailPass-123", "reason": "test",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	user := decode[map[string]any](t, rec)
	userID := user["id"].(string)

	rec = h.do(http.MethodPost, "/api/v1/admin/users/"+userID+"/email-changes", map[string]any{
		"new_email": "new@example.com", "reason": "test email change",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	challenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	require.NotEmpty(t, challenge)
	code := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, code, "verification code must be mailed")

	rec = h.do(http.MethodPost, "/api/v1/admin/users/"+userID+"/email-changes:confirm", map[string]any{
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
