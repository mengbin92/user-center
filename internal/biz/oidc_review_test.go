package biz

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOIDCReviewClientInputMatchesStoredContract(t *testing.T) {
	uc := NewOIDCUsecase(&Services{OIDCAccessTTL: 20 * time.Minute, OIDCRefreshTTL: 2 * time.Hour})
	input := OIDCClientInput{Name: " Review ", ServiceOwner: " owner ", RedirectURIs: []string{"https://app.example.com/callback"}, Scopes: []string{"openid"}}
	_, err := uc.validateClient(&input)
	require.NoError(t, err)
	require.Equal(t, "Review", input.Name)
	require.Equal(t, "owner", input.ServiceOwner)
	require.Equal(t, 1200, input.AccessTTL)
	require.Equal(t, 7200, input.RefreshTTL)
	input.AccessTTL = -1
	_, err = uc.validateClient(&input)
	require.Error(t, err)
	for _, uri := range []string{"https://app.example.com/callback#", "https://app.example.com/callback#fragment", "https://user:pass@app.example.com/callback", "http://app.example.com/callback"} {
		require.False(t, validRedirectURI(uri), uri)
	}
	for _, uri := range []string{"https://app.example.com/callback", "http://localhost/callback", "http://127.0.0.1/callback", "http://[::1]/callback"} {
		require.True(t, validRedirectURI(uri), uri)
	}
}
