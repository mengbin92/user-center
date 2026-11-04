package data

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOIDCSignerRejectsWeakRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, err = parseRSAKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	require.Error(t, err)
}

func TestOIDCSignerRequiresPersistentProductionKey(t *testing.T) {
	t.Setenv("OIDC_SIGNING_KEY_PEM", "")
	t.Setenv("OIDC_SIGNING_KEY_PATH", "")
	for _, d := range []*Data{
		{conf: &conf.Data{Database: &conf.Database{Driver: "mysql"}}},
		{conf: &conf.Data{Database: &conf.Database{Driver: "sqlite"}}, secure: &conf.Security{CookieSecure: true}},
	} {
		_, err := NewOIDCSigner(d, zap.NewNop())
		require.ErrorContains(t, err, "must be configured in production")
	}
	d := &Data{conf: &conf.Data{Database: &conf.Database{Driver: "sqlite"}}}
	first, err := NewOIDCSigner(d, zap.NewNop())
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	t.Setenv("OIDC_SIGNING_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	second, err := NewOIDCSigner(d, zap.NewNop())
	require.NoError(t, err)
	third, err := NewOIDCSigner(d, zap.NewNop())
	require.NoError(t, err)
	require.Equal(t, second.KeyID(), third.KeyID())
	require.NotEqual(t, first.KeyID(), second.KeyID())
}

func TestOIDCSignerRejectsIncompleteToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := &oidcSigner{key: key, keyID: "test-key"}
	for _, missing := range []string{"exp", "iat", "sub"} {
		t.Run(missing, func(t *testing.T) {
			claims := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "sub": "1"}
			delete(claims, missing)
			raw, err := signer.Sign(claims)
			require.NoError(t, err)
			_, err = signer.Verify(raw)
			require.Error(t, err)
		})
	}
}
