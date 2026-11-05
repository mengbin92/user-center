package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/service"
)

const consentRedirect = "https://app.example.com/callback"
const consentVerifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

func consentQuery(scope, prompt string) url.Values {
	sum := sha256.Sum256([]byte(consentVerifier))
	q := url.Values{
		"client_id": {"consent_client"}, "redirect_uri": {consentRedirect},
		"response_type": {"code"}, "scope": {scope}, "state": {"state-42"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	return q
}

func consentClient(t *testing.T, h *harness, scopes []string) {
	t.Helper()
	_, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: "consent_client", Name: "Consent App", ServiceOwner: "example",
		Status: "active", RedirectURIs: []string{consentRedirect},
		PostLogoutRedirectURIs: []string{"https://app.example.com/logged-out"},
		Scopes:                 scopes, Public: true, RequirePKCE: true, AccessTTL: 900, RefreshTTL: 3600,
	})
	require.NoError(t, err)
}

// consentFromLocation extracts the one-time handle from the consent redirect.
func consentFromLocation(t *testing.T, loc *url.URL) string {
	t.Helper()
	require.Equal(t, "/consent", loc.Path)
	require.Empty(t, loc.Query().Get("client_id"), "authorize parameters must not be in the consent URL")
	require.Empty(t, loc.Query().Get("state"))
	require.Empty(t, loc.Query().Get("redirect_uri"))
	handle := loc.Query().Get("handle")
	require.NotEmpty(t, handle)
	return handle
}

func decideConsent(t *testing.T, h *harness, handle string, approve, remember bool) *url.URL {
	t.Helper()
	view := h.do(http.MethodGet, "/api/v1/me/oidc-requests/"+url.PathEscape(handle), nil, "", false)
	require.Equal(t, http.StatusOK, view.Code, view.Body.String())
	rec := h.do(http.MethodPost, "/api/v1/me/oidc-requests/"+url.PathEscape(handle)+":decide",
		map[string]any{"handle": handle, "approve": approve, "remember": remember}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var reply struct {
		RedirectUrl string `json:"redirect_url"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reply))
	loc, err := url.Parse(reply.RedirectUrl)
	require.NoError(t, err)
	return loc
}

func TestOIDCConsentLifecycle(t *testing.T) {
	h := newHarness(t)
	consentClient(t, h, []string{"openid", "profile", "email"})
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)

	// First authorize parks the request; the consent URL carries no client data.
	rec := h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid profile", "").Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	handle := consentFromLocation(t, loc)
	view := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me/oidc-requests/"+handle, nil, "", false))
	require.Equal(t, "Consent App", view["client_name"])
	require.Equal(t, "app.example.com", view["redirect_host"])

	// Approving with remember issues exactly one code and keeps the state.
	granted := decideConsent(t, h, handle, true, true)
	require.NotEmpty(t, granted.Query().Get("code"))
	require.Equal(t, "state-42", granted.Query().Get("state"))

	// Replay of the same handle is rejected and never yields a second code.
	replay := h.do(http.MethodPost, "/api/v1/me/oidc-requests/"+handle+":decide",
		map[string]any{"handle": handle, "approve": true, "remember": true}, "", true)
	require.Equal(t, http.StatusNotFound, replay.Code)

	// A repeated, non-widened request reuses the consent without a new page.
	loc = h.authorize(t, consentQuery("openid profile", ""))
	require.NotEmpty(t, loc.Query().Get("code"))
	require.NotEqual(t, "/consent", loc.Path)

	// Widening the scope re-prompts.
	rec = h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid profile email", "").Encode(), nil, "", false)
	loc, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/consent", loc.Path)

	// prompt=none without a matching consent returns interaction_required.
	rec = h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid profile email", "none").Encode(), nil, "", false)
	loc, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "interaction_required", loc.Query().Get("error"))
	require.Empty(t, loc.Query().Get("code"))

	// prompt=consent forces a fresh decision even for a covered scope.
	rec = h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid", "consent").Encode(), nil, "", false)
	loc, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	denied := decideConsent(t, h, consentFromLocation(t, loc), false, false)
	require.Equal(t, "access_denied", denied.Query().Get("error"))
	require.Equal(t, "state-42", denied.Query().Get("state"))
	require.Empty(t, denied.Query().Get("code"))

	// The user can list and revoke; revoking forces a new consent.
	list := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me/oidc-consents", nil, "", false))
	require.NotEmpty(t, list["items"])
	revoke := h.do(http.MethodDelete, "/api/v1/me/oidc-consents/consent_client", nil, "", true)
	require.Equal(t, http.StatusOK, revoke.Code, revoke.Body.String())
	rec = h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid", "").Encode(), nil, "", false)
	loc, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/consent", loc.Path)
}

func TestOIDCConsentHandleRequiresTheOriginatingSession(t *testing.T) {
	h := newHarness(t)
	consentClient(t, h, []string{"openid"})
	fixtureUserWithEmail(t, h, "intruder", "intruder@example.com")
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rec := h.do(http.MethodGet, "/oidc/authorize?"+consentQuery("openid", "").Encode(), nil, "", false)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	handle := consentFromLocation(t, loc)
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	// Once the starting session is gone, the parked request is unreachable.
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me/oidc-requests/"+handle, nil, "", false).Code)
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodPost,
		"/api/v1/me/oidc-requests/"+handle+":decide", map[string]any{"handle": handle, "approve": true}, "", true).Code)

	// A different signed-in user cannot see or consume another user's handle;
	// the response is the same as for an unknown handle.
	require.Equal(t, http.StatusOK, h.login("intruder", "InvitePass-123").Code)
	require.Equal(t, http.StatusNotFound, h.do(http.MethodGet, "/api/v1/me/oidc-requests/"+handle, nil, "", false).Code)
	require.Equal(t, http.StatusNotFound, h.do(http.MethodPost,
		"/api/v1/me/oidc-requests/"+handle+":decide", map[string]any{"handle": handle, "approve": true}, "", true).Code)
}

func TestOIDCEndSession(t *testing.T) {
	h := newHarness(t)
	consentClient(t, h, []string{"openid", "profile"})
	_, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: "other_client", Name: "Other App", ServiceOwner: "example",
		Status: "active", RedirectURIs: []string{"https://other.example.com/callback"},
		PostLogoutRedirectURIs: []string{"https://other.example.com/out"},
		Scopes:                 []string{"openid"}, Public: true, RequirePKCE: true, AccessTTL: 900, RefreshTTL: 3600,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	disco := decode[map[string]any](t, h.do(http.MethodGet, "/.well-known/openid-configuration", nil, "", false))
	require.Contains(t, disco["end_session_endpoint"], "/oidc/logout")

	// An unregistered post_logout_redirect_uri is never followed, but it must
	// not leave the server-side session alive behind a cleared browser cookie.
	bad := h.do(http.MethodGet, "/oidc/logout?"+url.Values{
		"client_id": {"consent_client"}, "post_logout_redirect_uri": {"https://attacker.example.com/"},
	}.Encode(), nil, "", false)
	require.Equal(t, http.StatusBadRequest, bad.Code)
	require.Contains(t, bad.Body.String(), "已退出")
	cleared := false
	for _, cookie := range bad.Result().Cookies() {
		if cookie.Name == service.SessionCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "a rejected logout must still clear the session cookie")
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)

	// A valid ID token hint identifies the client and permits the registered
	// post-logout target.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	loc := h.authorize(t, consentQuery("openid", ""))
	tokenRec := h.doForm("/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {consentRedirect}, "code_verifier": {consentVerifier},
		"client_id": {"consent_client"},
	}, "", "")
	require.Equal(t, http.StatusOK, tokenRec.Code, tokenRec.Body.String())
	validHint := decode[map[string]any](t, tokenRec)["id_token"].(string)
	withHint := h.do(http.MethodGet, "/oidc/logout?"+url.Values{
		"id_token_hint": {validHint}, "post_logout_redirect_uri": {"https://app.example.com/logged-out"},
	}.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, withHint.Code, withHint.Body.String())
	require.Equal(t, "https://app.example.com/logged-out", withHint.Header().Get("Location"))
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)

	// A hint for another client must not authorize a redirect registered for a
	// different client, even when that target exists in the other client's
	// whitelist.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	cross := h.do(http.MethodGet, "/oidc/logout?"+url.Values{
		"id_token_hint": {validHint}, "client_id": {"other_client"},
		"post_logout_redirect_uri": {"https://other.example.com/out"},
	}.Encode(), nil, "", false)
	require.Equal(t, http.StatusBadRequest, cross.Code)
	require.Contains(t, cross.Body.String(), "does not match")
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)

	// client_id alone is accepted, but the target is still whitelisted.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	q := url.Values{"client_id": {"consent_client"},
		"post_logout_redirect_uri": {"https://app.example.com/logged-out"}, "state": {"s-9"}}
	good := h.do(http.MethodGet, "/oidc/logout?"+q.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, good.Code)
	target, err := url.Parse(good.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "s-9", target.Query().Get("state"))

	// The session is revoked: /me is now unauthenticated, and a repeat is safe.
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
	require.Equal(t, http.StatusFound, h.do(http.MethodGet, "/oidc/logout?"+q.Encode(), nil, "", false).Code)

	// Invalid and expired hints behave identically to a missing hint: no error
	// page, no session or account disclosure, and the whitelist still applies.
	expired, err := h.svc.OIDCSigner.Sign(map[string]any{
		"iss": biz.NewOIDCUsecase(h.svc).Issuer(), "sub": "1", "aud": "consent_client",
		"exp": 1, "iat": 1,
	})
	require.NoError(t, err)
	for _, hint := range []string{"garbage", expired} {
		rec := h.do(http.MethodGet, "/oidc/logout?"+url.Values{
			"id_token_hint": {hint}, "client_id": {"consent_client"},
			"post_logout_redirect_uri": {"https://app.example.com/logged-out"},
		}.Encode(), nil, "", false)
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	}
	// An unregistered target is still rejected for invalid hints.
	require.Equal(t, http.StatusBadRequest, h.do(http.MethodGet, "/oidc/logout?"+url.Values{
		"id_token_hint": {expired}, "client_id": {"consent_client"},
		"post_logout_redirect_uri": {"https://example.com/other"},
	}.Encode(), nil, "", false).Code)
}
