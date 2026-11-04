package server_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/stretchr/testify/require"
)

func TestOAuthLoginPreservesOIDCAuthorizationContinuation(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "passwordless", true: "mfa"}[mfa], func(t *testing.T) {
			h := newHarness(t)
			require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
			_, err := h.svc.Identities.Create(context.Background(), nil, &biz.ExternalIdentity{UserID: 1, Provider: "mock", Issuer: "mock", ProviderSubject: "subject-1"})
			require.NoError(t, err)
			if mfa {
				enrollMFA(t, h, "ChangeMe-12345")
			}
			require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
			next := "/oidc/authorize?client_id=example&state=original-state"
			rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?next="+url.QueryEscape(next), nil, "", false)
			require.Equal(t, http.StatusFound, rec.Code)
			provider, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			state := provider.Query().Get("state")
			require.NotEmpty(t, state)
			rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok&next=//attacker.example", nil, "", false)
			require.Equal(t, http.StatusFound, rec.Code)
			if !mfa {
				require.Equal(t, next, rec.Header().Get("Location"))
				return
			}
			location, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "/login", location.Path)
			require.NotEmpty(t, location.Query().Get("mfa_challenge"))
			require.Equal(t, next, location.Query().Get("next"))
		})
	}
}

func TestOAuthContinuationRejectsExternalAndNonAuthorizationTargets(t *testing.T) {
	h := newHarness(t)
	for _, next := range []string{"https://attacker.example/oidc/authorize", "//attacker.example/oidc/authorize", "/\\attacker.example/oidc/authorize", "/admin/users", "/oidc/authorize/../../admin"} {
		rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?next="+url.QueryEscape(next), nil, "", false)
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, "/login?oauth_error=oauth_failed", rec.Header().Get("Location"))
	}
}
