package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestOIDCTransportRejectsOversizedAndAmbiguousTokenRequests(t *testing.T) {
	h := newHarness(t)
	for _, tt := range []struct {
		name, path, body, authorization, contentType string
		status                                       int
	}{
		{"oversized", "/oidc/token", "padding=" + strings.Repeat("x", 1<<20), "", "application/x-www-form-urlencoded", 413},
		{"duplicate", "/oidc/token", "grant_type=authorization_code&grant_type=refresh_token", "", "application/x-www-form-urlencoded", 400},
		{"query", "/oidc/token?grant_type=refresh_token", "client_id=test", "", "application/x-www-form-urlencoded", 400},
		{"two_auth_methods", "/oidc/token", "client_id=test&client_secret=secret", "Basic dGVzdDpzZWNyZXQ=", "application/x-www-form-urlencoded", 400},
		{"json", "/oidc/token", `{}`, "", "application/json", 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.com"+tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			h.srv.ServeHTTP(rec, req)
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
		})
	}
}

func TestOIDCTransportLimitsUnknownLengthAndDecodesBasicAuth(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/oidc/token", strings.NewReader("padding="+strings.Repeat("x", 1<<20)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())

	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	clientID, secret := "client+percent", "secret+%: space"
	redirect := "https://app.example.com/callback"
	_, err := h.svc.OIDCClients.CreateOIDCClient(context.Background(), nil, &biz.OIDCClient{
		ClientID: clientID, Name: "Transport", ServiceOwner: "app", RequirePKCE: false,
		SecretHash: biz.HashToken(secret), RedirectURIs: []string{redirect}, Scopes: []string{"openid"},
	})
	require.NoError(t, err)
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}}
	rec = h.do(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	code := location.Query().Get("code")
	require.NotEmpty(t, code)
	form := url.Values{"client_id": {clientID}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	req = httptest.NewRequest(http.MethodPost, "http://example.com/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	rec = httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	tokens := decode[map[string]any](t, rec)
	req = httptest.NewRequest(http.MethodGet, "http://example.com/oidc/userinfo", nil)
	req.Header.Set("Authorization", "bearer "+tokens["access_token"].(string))
	rec = httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	req.Header.Set("Authorization", "Bearer "+tokens["id_token"].(string))
	rec = httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
}

func TestOIDCTransportMethodsAndChallenges(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/authorize", "/oidc/userinfo"} {
		rec := h.do(http.MethodDelete, path, nil, "", false)
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
		require.NotEmpty(t, rec.Header().Get("Allow"), path)
	}
	rec := h.do(http.MethodGet, "/oidc/userinfo", nil, "", false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
	rec = h.do(http.MethodGet, "/oidc/authorize", nil, "", false)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}
