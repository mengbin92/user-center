package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/mengbin92/user-center/pkg/totp"
	"github.com/stretchr/testify/require"
)

type retainingChallenges struct{ biz.ChallengeStore }

func (s retainingChallenges) Delete(context.Context, string, string) error {
	return errors.New("delete unavailable")
}

type failingMFA struct{ biz.MFARepo }

func (s failingMFA) Get(context.Context, biz.Tx, int64) (*biz.MFAState, error) {
	return nil, errors.New("mfa unavailable")
}

type failingCredentials struct{ biz.CredentialRepo }

func (s failingCredentials) Get(context.Context, biz.Tx, int64) (*biz.Credential, error) {
	return nil, errors.New("credential unavailable")
}

type failingSessionRevoke struct{ biz.SessionRepo }

func (s failingSessionRevoke) Revoke(context.Context, biz.Tx, string, *time.Time) error {
	return errors.New("revoke unavailable")
}

func resetChallenge(t *testing.T, h *harness, identifier string) (string, string) {
	t.Helper()
	rec := h.do(http.MethodPost, "/api/v1/auth/password-reset-challenges", map[string]any{"identifier": identifier}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	id := decode[map[string]any](t, rec)["challenge_id"].(string)
	link := passwordResetMailParams(t, h)
	require.Equal(t, id, link.Get("challenge"))
	code := link.Get("code")
	require.Regexp(t, `^[0-9]{6}$`, code)
	return id, code
}

func passwordResetMailParams(t *testing.T, h *harness) url.Values {
	t.Helper()
	rawLink := regexp.MustCompile(`https?://[^\s]+`).FindString(h.mail.last().body)
	link, err := url.Parse(rawLink)
	require.NoError(t, err)
	require.Equal(t, "/reset-password", link.Path)
	require.Empty(t, link.RawQuery)
	params, err := url.ParseQuery(link.Fragment)
	require.NoError(t, err)
	return params
}

func assertRememberCookie(t *testing.T, rec *httptest.ResponseRecorder, remember bool) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name != service.SessionCookie {
			continue
		}
		require.True(t, c.HttpOnly)
		if remember {
			require.True(t, c.Expires.After(time.Now()))
		} else {
			require.True(t, c.Expires.IsZero())
		}
		return
	}
	t.Fatal("missing session cookie")
}

func TestRememberControlsOnlyCookiePersistence(t *testing.T) {
	h := newHarness(t)
	for _, remember := range []bool{false, true} {
		rec := h.do(http.MethodPost, "/api/v1/auth/login", map[string]any{
			"username": "root", "password": "ChangeMe-12345", "remember": remember,
		}, "", true)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assertRememberCookie(t, rec, remember)
		require.NotEmpty(t, decode[map[string]any](t, rec)["session_expires_at"])
	}
}

func TestPasswordResetAfterChangedCredentialAndReplayDenied(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{"current_password": "ChangeMe-12345", "new_password": "ChangedPass-12345"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	id, code := resetChallenge(t, h, "root@example.com")
	h.svc.Challenges = retainingChallenges{h.svc.Challenges}
	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"challenge_id": id, "code": code, "new_password": "ResetPass-12345"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"challenge_id": id, "code": code, "new_password": "ReplayedPass-12345"}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "CHALLENGE_INVALID")
	require.Equal(t, http.StatusUnauthorized, h.login("root", "ChangedPass-12345").Code)
	require.Equal(t, http.StatusUnauthorized, h.login("root", "ReplayedPass-12345").Code)
	require.Equal(t, http.StatusOK, h.login("root", "ResetPass-12345").Code)
}

func TestPasswordResetDeniesStaleIdentityGeneration(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	id, code := resetChallenge(t, h, "root@example.com")
	rec := h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{
		"current_password": "ChangeMe-12345", "new_password": "ChangedPass-12345",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{
		"challenge_id": id, "code": code, "new_password": "StalePass-12345",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "CHALLENGE_INVALID")
	require.Equal(t, http.StatusOK, h.login("root", "ChangedPass-12345").Code)
}

func TestUnverifiedEmailRequiresGovernedPasswordReset(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	u := fixtureUserWithEmail(t, h, "verify.reset", "verify-reset@example.com")
	u.EmailVerified = false
	_, err := h.svc.Users.Update(context.Background(), nil, u, u.Revision)
	require.NoError(t, err)

	rec := h.do(http.MethodPost, "/api/v1/auth/password-reset-challenges", map[string]any{"identifier": u.Username}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotEmpty(t, decode[map[string]any](t, rec)["challenge_id"])
	require.Empty(t, h.mail.last().to)

	path := "/api/v1/admin/users/" + strconv.FormatInt(u.ID, 10) + "/password-reset-requests"
	rec = h.management(http.MethodPost, path, map[string]any{"reason": "account recovery"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, u.Email, h.mail.last().to)
	link := passwordResetMailParams(t, h)
	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{
		"challenge_id": link.Get("challenge"), "code": link.Get("code"), "new_password": "AdminReset-12345",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, h.login(u.Username, "AdminReset-12345").Code)
}

func TestChallengeAttemptLimitDeniesCorrectCodeAfterTenFailures(t *testing.T) {
	h := newHarness(t)
	id, code := resetChallenge(t, h, "root@example.com")
	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}
	for range 10 {
		rec := h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"challenge_id": id, "code": wrong, "new_password": "NewPassword-12345"}, "", true)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	rec := h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"challenge_id": id, "code": code, "new_password": "NewPassword-12345"}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
}

func TestLoginAccountLimitCountsWrongPasswordsAcrossAddresses(t *testing.T) {
	h := newHarness(t)
	h.svc.MaxLoginAttempts = 2
	waitForFreshRateLimitWindow(t, 5*time.Minute)
	require.Equal(t, http.StatusUnauthorized, h.login("root", "wrong-password").Code)
	// Username and email share the same authoritative account limit.
	require.Equal(t, http.StatusUnauthorized, h.login("root@example.com", "wrong-password").Code)
	rec := h.login("root", "ChangeMe-12345")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
}

func TestOAuthMFAReadFailureCannotCreateSession(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	oauth := func(mode string) string {
		rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode="+mode, nil, "", false)
		require.Equal(t, http.StatusFound, rec.Code)
		for _, c := range rec.Result().Cookies() {
			if c.Name == "uc_oauth_state" {
				return c.Value
			}
		}
		t.Fatal("missing OAuth state")
		return ""
	}
	state := oauth("bind")
	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "bound=mock")
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	state = oauth("login")
	h.svc.MFA = failingMFA{h.svc.MFA}
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "oauth_error=")
	require.NotContains(t, rec.Header().Get("Location"), "status=success")
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
}

func TestOldMFAChallengeDeniedAfterPasswordReset(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	rec := h.login("root", "ChangeMe-12345")
	challenge := decode[map[string]any](t, rec)["challenge_id"].(string)
	id, code := resetChallenge(t, h, "root@example.com")
	rec = h.do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"challenge_id": id, "code": code, "new_password": "NewPassword-12345"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	factor, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challenge_id": challenge, "code": factor}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
}

func TestLogoutRevokeFailureIsReported(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	h.svc.Sessions = failingSessionRevoke{h.svc.Sessions}
	rec := h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DEPENDENCY_UNAVAILABLE")
}

func TestCredentialReadFailureDeniesProtectedHTTP(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	h.svc.Credentials = failingCredentials{h.svc.Credentials}
	rec := h.do(http.MethodGet, "/api/v1/admin/users", nil, "", false)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "DEPENDENCY_UNAVAILABLE")
}

func TestOversizedPasswordReturnsPolicyViolation(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{"current_password": "ChangeMe-12345", "new_password": strings.Repeat("a", 73)}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	// PASSWORD_POLICY_VIOLATION rather than VALIDATION_FAILED: the web form keys
	// off this reason to show the rule next to the password field.
	require.Contains(t, rec.Body.String(), "PASSWORD_POLICY_VIOLATION")
}

func TestConcurrentTOTPReplayOnlyCreatesOneSession(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	h.jar, _ = cookiejar.New(nil)
	h.refreshCSRF()
	challenges := make([]string, 2)
	for i := range challenges {
		challenges[i] = decode[map[string]any](t, h.login("root", "ChangeMe-12345"))["challenge_id"].(string)
	}
	held := make(chan struct{}, 1)
	release := make(chan struct{})
	h.svc.Users = &lockGate{UserRepo: h.svc.Users, held: held, release: release}
	code, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	type outcome struct {
		code int
		body string
	}
	results := make(chan outcome, 2)
	complete := func(id string) {
		rec := h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challenge_id": id, "code": code}, "", true)
		results <- outcome{code: rec.Code, body: rec.Body.String()}
	}
	go complete(challenges[0])
	<-held
	go complete(challenges[1])
	first := <-results
	close(release)
	second := <-results
	// Keep the bodies in the failure message: a 503 here means a dependency
	// error (for SQLite, a write lock) rather than the expected replay
	// rejection, and the body is the only place that distinguishes them.
	require.ElementsMatch(t, []int{http.StatusOK, http.StatusBadRequest},
		[]int{first.code, second.code}, "first=%+v second=%+v", first, second)
}

type unavailableSessionCreate struct{ biz.SessionRepo }

func (unavailableSessionCreate) Create(context.Context, biz.Tx, *biz.Session) error {
	return errors.New("session persistence unavailable")
}

func TestMFALoginRollsBackRecoveryCodeIfSessionCreationFails(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	setup := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/me/mfa:setup",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	code, err := totp.Code(setup["secret"].(string), time.Now().Unix()/30, 6)
	require.NoError(t, err)
	confirmed := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/me/mfa:confirm",
		map[string]any{"code": code}, "", true))
	recoveryCode := confirmed["recovery_codes"].([]any)[0].(string)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)

	challenge := decode[map[string]any](t, h.login("root", "ChangeMe-12345"))["challenge_id"]
	body := map[string]any{"challenge_id": challenge, "code": recoveryCode}
	repo := h.svc.Sessions
	h.svc.Sessions = unavailableSessionCreate{repo}
	rec := h.do(http.MethodPost, "/api/v1/auth/mfa/complete", body, "", true)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	h.svc.Sessions = repo
	rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

type passwordlessCredentials struct{ biz.CredentialRepo }

func (s passwordlessCredentials) Get(ctx context.Context, tx biz.Tx, id int64) (*biz.Credential, error) {
	c, err := s.CredentialRepo.Get(ctx, tx, id)
	if err == nil {
		c.PasswordHash = ""
	}
	return c, err
}

type failingIdentityCount struct{ biz.ExternalIdentityRepo }

func (s failingIdentityCount) CountByUser(context.Context, biz.Tx, int64) (int64, error) {
	return 0, errors.New("identity count unavailable")
}

func TestExternalIdentityRemovalKeepsLastLoginMethodAndFailsClosed(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	ctx := context.Background()
	user, err := h.svc.Users.GetByUsername(ctx, nil, "root")
	require.NoError(t, err)
	sessions, err := h.svc.Sessions.ListByUser(ctx, nil, user.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.NoError(t, h.svc.StepUp.Put(ctx, biz.StepUpKey(sessions[0]), time.Now().Add(time.Minute)))
	first, err := h.svc.Identities.Create(ctx, nil, &biz.ExternalIdentity{UserID: user.ID, Provider: "a", Issuer: "a", ProviderSubject: "first"})
	require.NoError(t, err)
	second, err := h.svc.Identities.Create(ctx, nil, &biz.ExternalIdentity{UserID: user.ID, Provider: "b", Issuer: "b", ProviderSubject: "second"})
	require.NoError(t, err)
	h.svc.Credentials = passwordlessCredentials{h.svc.Credentials}
	rec := h.do(http.MethodDelete, "/api/v1/me/external-identities/"+fmt.Sprint(first.ID), nil, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodDelete, "/api/v1/me/external-identities/"+fmt.Sprint(second.ID), nil, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "LAST_LOGIN_METHOD")
	require.NoError(t, func() error { _, err := h.svc.Identities.GetByID(ctx, nil, second.ID); return err }())
	h.svc.Identities = failingIdentityCount{h.svc.Identities}
	rec = h.do(http.MethodDelete, "/api/v1/me/external-identities/"+fmt.Sprint(second.ID), nil, "", true)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
}

func TestCredentialChangesInvalidateOtherSessionsAndOldStepUp(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	ctx := context.Background()
	user, err := h.svc.Users.GetByUsername(ctx, nil, "root")
	require.NoError(t, err)
	oldSessions, err := h.svc.Sessions.ListByUser(ctx, nil, user.ID)
	require.NoError(t, err)
	require.Len(t, oldSessions, 1)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	old, err := h.svc.Sessions.Get(ctx, nil, oldSessions[0].ID)
	require.NoError(t, err)
	require.NotNil(t, old.RevokedAt, "enrolling MFA revokes sessions which never verified a factor")
	stepUp(t, h, "ChangeMe-12345", secret, 1)
	rec := h.do(http.MethodGet, "/api/v1/me/security", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, decode[map[string]any](t, rec)["step_up_expires_at"])
	rec = h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{"current_password": "ChangeMe-12345", "new_password": "ChangedPass-12345"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.do(http.MethodGet, "/api/v1/me/security", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Empty(t, decode[map[string]any](t, rec)["step_up_expires_at"], "old proof cannot survive the credential generation change")
	// Reintroducing a delayed proof for the old generation must stay unusable.
	sessions, err := h.svc.Sessions.ListByUser(ctx, nil, user.ID)
	require.NoError(t, err)
	for _, s := range sessions {
		if s.RevokedAt == nil {
			s.IdentityVersion--
			require.NoError(t, h.svc.StepUp.Put(ctx, biz.StepUpKey(s), time.Now().Add(time.Minute)))
		}
	}
	rec = h.do(http.MethodGet, "/api/v1/me/security", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, decode[map[string]any](t, rec)["step_up_expires_at"])
}

func TestOfflineRootMFARecoveryRevokesBrowserSession(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	enrollMFA(t, h, "ChangeMe-12345")
	require.NoError(t, h.svc.ResetRootMFA(context.Background(), "root"))
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
	rec := h.login("root", "ChangeMe-12345")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "authenticated", decode[map[string]any](t, rec)["status"])
	rec = h.do(http.MethodGet, "/api/v1/me/security", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code)
	require.False(t, decode[struct {
		MFAEnabled bool `json:"mfa_enabled"`
	}](t, rec).MFAEnabled)
	audits, _, err := h.svc.Audit.List(context.Background(), nil, biz.AuditFilter{Action: "account.rescue.mfa_reset", Limit: 100})
	require.NoError(t, err)
	require.Len(t, audits, 1)
}

func TestOversizedHTTPRequestIsRejectedForKnownAndChunkedLength(t *testing.T) {
	h := newHarness(t)
	raw := `{"username":"` + strings.Repeat("a", 1<<20) + `","password":"test"}`
	for _, length := range []int64{int64(len(raw)), -1} {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/auth/login", strings.NewReader(raw))
		req.ContentLength = length
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.srv.ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "REQUEST_TOO_LARGE")
	}
}
