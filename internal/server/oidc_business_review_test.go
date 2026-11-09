package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func oidcReviewClient(t *testing.T, h *harness, scopes []string) *biz.OIDCClient {
	t.Helper()
	c, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: "review_client", Name: "Review", ServiceOwner: "review",
		SecretHash: biz.HashToken("review-secret"), RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes: scopes, RequirePKCE: true, AccessTTL: 900, RefreshTTL: 3600,
	})
	require.NoError(t, err)
	return c
}

func oidcReviewAuthorization(t *testing.T, h *harness, scope string) (string, string) {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"review_client"}, "redirect_uri": {"https://app.example.com/callback"},
		"response_type": {"code"}, "scope": {scope}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	loc := h.authorize(t, q)
	return loc.Query().Get("code"), verifier
}

func oidcReviewExchange(h *harness, code, verifier string) *httptest.ResponseRecorder {
	return h.doForm("/oidc/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://app.example.com/callback"}, "code_verifier": {verifier}}, "review_client", "review-secret")
}

func oidcReviewUserInfo(h *harness, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

func TestOIDCReviewRejectsScopesOutsideClientRegistration(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, _ := oidcReviewAuthorization(t, h, "openid email offline_access")
	require.Empty(t, code, "an openid-only client must not obtain email or refresh access")
}

func TestOIDCReviewInvalidatesCredentialsAfterIdentityChange(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "email", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid email offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	code, verifier = oidcReviewAuthorization(t, h, "openid")
	_, err := h.svc.Users.BumpIdentityVersion(context.Background(), nil, 1)
	require.NoError(t, err)
	rec = oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = oidcReviewUserInfo(h, tokens["access_token"].(string))
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

type oidcFailingSigner struct{ biz.OIDCSigner }

func (oidcFailingSigner) Sign(map[string]any) (string, error) {
	return "", errors.New("signing temporarily unavailable")
}

func TestOIDCReviewTokenFailureDoesNotConsumeGrant(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	signer := h.svc.OIDCSigner
	h.svc.OIDCSigner = oidcFailingSigner{signer}
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	h.svc.OIDCSigner = signer
	rec = oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, "failed issuance must roll back one-time grant consumption: "+rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	h.svc.OIDCSigner = oidcFailingSigner{signer}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}
	rec = h.doForm("/oidc/token", form, "review_client", "review-secret")
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	h.svc.OIDCSigner = signer
	rec = h.doForm("/oidc/token", form, "review_client", "review-secret")
	require.Equal(t, http.StatusOK, rec.Code, "failed refresh issuance must roll back old-token consumption: "+rec.Body.String())
}

func TestOIDCReviewRefreshDoesNotExtendOriginalLifetime(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code)
	tokens := decode[map[string]any](t, rec)
	now := time.Now()
	h.svc.Clock = futureClock{now: now.Add(30 * time.Minute)}
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rotated := decode[map[string]any](t, rec)
	h.svc.Clock = futureClock{now: now.Add(61 * time.Minute)}
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {rotated["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, "refresh rotation must not keep a grant alive forever: "+rec.Body.String())
}

func TestOIDCReviewRejectsStaleClientScopeAndRedirects(t *testing.T) {
	h := newHarness(t)
	c := oidcReviewClient(t, h, []string{"openid", "email", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid email offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	code, verifier = oidcReviewAuthorization(t, h, "openid")
	c.Scopes = []string{"openid"}
	c.RedirectURIs = []string{"https://app.example.com/new-callback"}
	_, err := h.svc.OIDCClients.UpdateOIDCClient(context.Background(), nil, c, c.Revision)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, oidcReviewUserInfo(h, tokens["access_token"].(string)).Code)
	require.Equal(t, http.StatusBadRequest, oidcReviewExchange(h, code, verifier).Code)
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestOIDCReviewRejectsDisabledClientAndWrongAudience(t *testing.T) {
	h := newHarness(t)
	c := oidcReviewClient(t, h, []string{"openid"})
	user, err := h.svc.Users.Get(context.Background(), nil, 1)
	require.NoError(t, err)
	claims := map[string]any{"iss": "http://localhost:5173", "sub": "1", "aud": "another-client", "client_id": c.ClientID,
		"token_type": "access", "identity_version": strconv.FormatUint(user.IdentityVersion, 10), "scope": "openid",
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
	token, err := h.svc.OIDCSigner.Sign(claims)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, oidcReviewUserInfo(h, token).Code)
	claims["aud"] = c.ClientID
	token, err = h.svc.OIDCSigner.Sign(claims)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, oidcReviewUserInfo(h, token).Code)
	require.NoError(t, h.svc.OIDCClients.DisableOIDCClient(context.Background(), nil, c.ID, c.Revision))
	require.Equal(t, http.StatusUnauthorized, oidcReviewUserInfo(h, token).Code)
}

func TestOIDCReviewRefreshReuseRevokesTheReplacement(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	refresh := func(raw string) *httptest.ResponseRecorder {
		return h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}, "review_client", "review-secret")
	}
	rec = refresh(tokens["refresh_token"].(string))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rotated := decode[map[string]any](t, rec)
	require.Equal(t, http.StatusBadRequest, refresh(tokens["refresh_token"].(string)).Code)
	rec = refresh(rotated["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, rec.Code, "reuse of any ancestor must revoke its replacement: "+rec.Body.String())
}

func TestOIDCReviewRefreshScopesCanOnlyNarrow(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "email", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "scope": {"openid email"}}
	rec = h.doForm("/oidc/token", form, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	form.Set("scope", "openid")
	rec = h.doForm("/oidc/token", form, "review_client", "review-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	narrowed := decode[map[string]any](t, rec)
	require.Equal(t, "openid", narrowed["scope"])
	require.NotContains(t, narrowed, "refresh_token")
}

func TestOIDCReviewManagementRequiresVersionsAndReason(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(t, err)
	body := map[string]any{"name": "Original", "service_owner": "review", "redirect_uris": []string{"https://app.example.com/callback"},
		"scopes": []string{"openid"}, "require_pkce": true, "reason": "review"}
	rec := h.do(http.MethodPost, "/api/v1/admin/oidc-clients", body, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	body["expected_policy_revision"] = strconv.FormatUint(policy, 10)
	body["reason"] = " "
	rec = h.do(http.MethodPost, "/api/v1/admin/oidc-clients", body, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	body["reason"] = "review"
	body["expected_policy_revision"] = strconv.FormatUint(policy+1, 10)
	rec = h.do(http.MethodPost, "/api/v1/admin/oidc-clients", body, "", true)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	body["expected_policy_revision"] = strconv.FormatUint(policy, 10)
	rec = h.do(http.MethodPost, "/api/v1/admin/oidc-clients", body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	created := decode[map[string]any](t, rec)["client"].(map[string]any)
	path := "/api/v1/admin/oidc-clients/" + created["id"].(string)
	body["expected_revision"] = created["revision"]
	body["name"] = "Renamed"
	delete(body, "service_owner")
	rec = h.do(http.MethodPatch, path, body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	updated := decode[map[string]any](t, rec)
	require.Equal(t, "Renamed", updated["name"])
	mutation := map[string]any{"reason": "review", "expected_policy_revision": strconv.FormatUint(policy, 10)}
	for _, suffix := range []string{":rotate-secret", ":disable"} {
		rec = h.do(http.MethodPost, path+suffix, mutation, "", true)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		mutation["expected_revision"] = created["revision"]
		rec = h.do(http.MethodPost, path+suffix, mutation, "", true)
		require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
		delete(mutation, "expected_revision")
	}
	mutation["expected_revision"] = updated["revision"]
	rec = h.do(http.MethodPost, path+":disable", mutation, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestOIDCReviewEnforcesCurrentAccountSecurityPolicy(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)
	code, verifier = oidcReviewAuthorization(t, h, "openid")
	settings, err := h.svc.Settings.GetAuth(context.Background(), nil)
	require.NoError(t, err)
	settings.MFARequiredForAdmins = true
	_, err = h.svc.Settings.SaveAuth(context.Background(), nil, settings, settings.Revision)
	require.NoError(t, err)
	rec = oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusUnauthorized, oidcReviewUserInfo(h, tokens["access_token"].(string)).Code)
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	sum := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	q := url.Values{"client_id": {"review_client"}, "redirect_uri": {"https://app.example.com/callback"},
		"response_type": {"code"}, "scope": {"openid"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	rec = h.do(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/account/security", location.Path)
	require.Equal(t, "1", location.Query().Get("mfa_enrollment_required"))
	require.Contains(t, location.Query().Get("next"), "/oidc/authorize?")
	q.Set("prompt", "none")
	rec = h.do(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil, "", false)
	location, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "interaction_required", location.Query().Get("error"))
	require.Empty(t, location.Query().Get("code"))
}

// The credential restriction has to travel with the credential, not with one
// protocol. Before this was fixed, enabling expiry blocked the browser (the
// middleware gate) while an existing refresh token kept exchanging for fresh
// access tokens, and the internal gRPC API still reported a usable session.
func TestOIDCReviewRejectsExpiredPasswordOnEverySurface(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokens := decode[map[string]any](t, rec)

	// One day of validity, and a password set 48 hours ago.
	h.setAuthSettings(func(s *biz.AuthSettings) { s.PasswordExpiryDays = 1 })
	require.NoError(t, h.d.DB().Exec(
		"UPDATE user_credentials SET password_changed_at = ?", time.Now().UTC().Add(-48*time.Hour)).Error)

	// Refresh and UserInfo run through authenticationRestrictions.
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "invalid_grant")
	require.Equal(t, http.StatusUnauthorized, oidcReviewUserInfo(h, tokens["access_token"].(string)).Code)

	// A brand-new authorization parks the user on the change-password screen
	// instead of issuing another code.
	verifier = strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"review_client"}, "redirect_uri": {"https://app.example.com/callback"},
		"response_type": {"code"}, "scope": {"openid"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	rec = h.do(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/account/security", location.Path)
	require.Equal(t, "1", location.Query().Get("password_change_required"))

	// The internal API refuses the session outright: an integration cannot be
	// trusted to enforce a flag it was merely told about.
	login, err := h.auth.LoginForApplication(context.Background(), biz.LoginInput{
		Username: "root", Password: "ChangeMe-12345", IP: "10.1.2.3", UserAgent: "integration",
	}, "review-app")
	require.NoError(t, err, "login itself still succeeds; the restriction is applied per use")
	require.True(t, login.PasswordChangeRequired)
	integration := biz.NewIntegrationUsecase(h.svc)
	_, _, err = integration.ValidateSession(context.Background(), login.RawToken, "review-app")
	require.ErrorIs(t, err, biz.ErrPasswordChange)
	_, _, _, err = integration.SessionAuthorization(context.Background(), login.RawToken, "review-app")
	require.ErrorIs(t, err, biz.ErrPasswordChange)
}

func TestOIDCReviewValidatesPromptMaxAgeAndPKCE(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"review_client"}, "redirect_uri": {"https://app.example.com/callback"},
		"response_type": {"code"}, "scope": {"openid"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	for _, test := range []struct{ field, value, code string }{
		{"prompt", "login", "login_required"},
		{"prompt", "none login", "invalid_request"}, {"prompt", "select_account", "account_selection_required"},
		{"prompt", "unknown", "invalid_request"}, {"max_age", "0", "login_required"},
		{"max_age", "-1", "invalid_request"}, {"max_age", "x", "invalid_request"},
		{"code_challenge", "short", "invalid_request"},
	} {
		t.Run(test.field+"="+test.value, func(t *testing.T) {
			query := q.Encode()
			values, err := url.ParseQuery(query)
			require.NoError(t, err)
			values.Set(test.field, test.value)
			rec := h.do(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil, "", false)
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
			location, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			require.Empty(t, location.Query().Get("code"))
			require.Equal(t, test.code, location.Query().Get("error"))
		})
	}
	for _, invalidVerifier := range []string{"short", strings.Repeat("v", 129), strings.Repeat("!", 64)} {
		sum := sha256.Sum256([]byte(invalidVerifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		location := h.authorize(t, q)
		rec := oidcReviewExchange(h, location.Query().Get("code"), invalidVerifier)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

type oidcUnavailableCodes struct{ biz.OIDCCodeRepo }

func (oidcUnavailableCodes) ConsumeOIDCCode(context.Context, biz.Tx, string, string, string, time.Time) (*biz.OIDCCode, error) {
	return nil, errors.New("temporary database failure")
}

func (oidcUnavailableCodes) ConsumeOIDCRefreshToken(context.Context, biz.Tx, string, string, time.Time) (*biz.OIDCRefreshToken, error) {
	return nil, errors.New("temporary database failure")
}

func TestOIDCReviewDependencyFailureDoesNotInvalidateClientGrant(t *testing.T) {
	h := newHarness(t)
	oidcReviewClient(t, h, []string{"openid", "offline_access"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	code, verifier := oidcReviewAuthorization(t, h, "openid offline_access")
	codes := h.svc.OIDCCodes
	h.svc.OIDCCodes = oidcUnavailableCodes{codes}
	rec := oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "server_error")
	require.NotContains(t, rec.Body.String(), "invalid_grant")
	h.svc.OIDCCodes = codes
	rec = oidcReviewExchange(h, code, verifier)
	require.Equal(t, http.StatusOK, rec.Code)
	tokens := decode[map[string]any](t, rec)
	h.svc.OIDCCodes = oidcUnavailableCodes{codes}
	rec = h.doForm("/oidc/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)}}, "review_client", "review-secret")
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "server_error")
	require.NotContains(t, rec.Body.String(), "invalid_grant")
}

func TestOIDCReviewClientMutationsRollbackWithAudit(t *testing.T) {
	h := newHarness(t)
	c := oidcReviewClient(t, h, []string{"openid"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
	require.NoError(t, err)
	h.svc.Audit = rejectedAudit{h.svc.Audit}
	body := map[string]any{"name": "Changed", "redirect_uris": c.RedirectURIs, "scopes": c.Scopes,
		"require_pkce": true, "reason": "review", "expected_revision": strconv.FormatUint(c.Revision, 10),
		"expected_policy_revision": strconv.FormatUint(policy, 10)}
	path := "/api/v1/admin/oidc-clients/" + strconv.FormatInt(c.ID, 10)
	for _, request := range []struct{ method, path string }{
		{http.MethodPatch, path}, {http.MethodPost, path + ":rotate-secret"}, {http.MethodPost, path + ":disable"},
	} {
		requestBody := body
		if request.method == http.MethodPost {
			requestBody = map[string]any{"reason": "review", "expected_revision": body["expected_revision"], "expected_policy_revision": body["expected_policy_revision"]}
		}
		rec := h.do(request.method, request.path, requestBody, "", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		current, err := h.svc.OIDCClients.GetOIDCClient(context.Background(), nil, c.ID)
		require.NoError(t, err)
		require.Equal(t, c.Revision, current.Revision)
		require.Equal(t, c.SecretHash, current.SecretHash)
		require.Equal(t, c.Status, current.Status)
		require.Equal(t, c.Name, current.Name)
	}
}
