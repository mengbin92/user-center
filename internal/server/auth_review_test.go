package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/totp"
	"github.com/stretchr/testify/require"
)

type retainingChallenges struct{ biz.ChallengeStore }

func (s retainingChallenges) Delete(context.Context, string) error {
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
	code := regexp.MustCompile(`[0-9]{6}`).FindString(h.mail.last().body)
	require.NotEmpty(t, code)
	return id, code
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

type concurrentMFARead struct {
	biz.MFARepo
	ready sync.WaitGroup
}

func (s *concurrentMFARead) Get(ctx context.Context, tx biz.Tx, id int64) (*biz.MFAState, error) {
	state, err := s.MFARepo.Get(ctx, tx, id)
	s.ready.Done()
	s.ready.Wait()
	return state, err
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
	state := &concurrentMFARead{MFARepo: h.svc.MFA}
	state.ready.Add(2)
	h.svc.MFA = state
	code, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	results := make(chan int, 2)
	for _, challenge := range challenges {
		go func(id string) {
			results <- h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challenge_id": id, "code": code}, "", true).Code
		}(challenge)
	}
	statuses := []int{<-results, <-results}
	require.ElementsMatch(t, []int{http.StatusOK, http.StatusBadRequest}, statuses)
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
