package data

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func oauthTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	})
	return httptest.NewServer(mux)
}

func TestGitHubProviderExchange(t *testing.T) {
	server := oauthTestServer(t)
	defer server.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"id":12345,"login":"octocat","name":"Octo Cat","email":""}`))
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"email":"other@example.com","primary":false,"verified":true},{"email":"octo@example.com","primary":true,"verified":true}]`))
	})
	info := httptest.NewServer(mux)
	defer info.Close()

	p := &githubProvider{
		conf: &oauth2.Config{
			ClientID: "id", ClientSecret: "secret",
			Endpoint:    oauth2.Endpoint{TokenURL: server.URL + "/token"},
			RedirectURL: "http://localhost/callback",
		},
		log: zap.NewNop(), userInfoURL: info.URL + "/user", emailsURL: info.URL + "/emails",
	}
	profile, err := p.Exchange(context.Background(), "code", "http://localhost/callback")
	require.NoError(t, err)
	require.Equal(t, "12345", profile.Subject)
	require.Equal(t, "github", profile.Issuer)
	require.Equal(t, "Octo Cat", profile.Display)
	require.Equal(t, "octo@example.com", profile.Email)
}

func TestGoogleProviderExchange(t *testing.T) {
	server := oauthTestServer(t)
	defer server.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sub":"google-sub","name":"Google User","email":"google@example.com"}`))
	})
	info := httptest.NewServer(mux)
	defer info.Close()

	p := &googleProvider{
		conf: &oauth2.Config{
			ClientID: "id", ClientSecret: "secret",
			Endpoint:    oauth2.Endpoint{TokenURL: server.URL + "/token"},
			RedirectURL: "http://localhost/callback",
		},
		log: zap.NewNop(), userInfoURL: info.URL + "/userinfo",
	}
	profile, err := p.Exchange(context.Background(), "code", "http://localhost/callback")
	require.NoError(t, err)
	require.Equal(t, "google-sub", profile.Subject)
	require.Equal(t, "google", profile.Issuer)
	require.Equal(t, "Google User", profile.Display)
	require.Equal(t, "google@example.com", profile.Email)
}
