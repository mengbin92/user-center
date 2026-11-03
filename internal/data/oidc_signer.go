package data

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
)

type oidcSigner struct {
	key   *rsa.PrivateKey
	keyID string
}

// NewOIDCSigner loads the RSA key from OIDC_SIGNING_KEY_PEM or
// OIDC_SIGNING_KEY_PATH. A development instance without a key generates an
// ephemeral key so tokens become invalid on restart; production must mount a
// stable key.
func NewOIDCSigner(log *zap.Logger) (biz.OIDCSigner, error) {
	pemData := os.Getenv("OIDC_SIGNING_KEY_PEM")
	if path := os.Getenv("OIDC_SIGNING_KEY_PATH"); pemData == "" && path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read OIDC signing key: %w", err)
		}
		pemData = string(raw)
	}
	var key *rsa.PrivateKey
	if strings.TrimSpace(pemData) != "" {
		parsed, err := parseRSAKey([]byte(pemData))
		if err != nil {
			return nil, err
		}
		key = parsed
	} else {
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		key = generated
		if log != nil {
			log.Warn("OIDC signing key not configured; generated an ephemeral key (tokens will not survive restart)")
		}
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &oidcSigner{key: key, keyID: hex.EncodeToString(sum[:8])}, nil
}

func parseRSAKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("OIDC signing key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("OIDC signing key must be RSA")
	}
	return key, nil
}

func (s *oidcSigner) KeyID() string { return s.keyID }

func (s *oidcSigner) Sign(claims map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = s.keyID
	return token.SignedString(s.key)
}

func (s *oidcSigner) PublicJWK() map[string]any {
	pub := &s.key.PublicKey
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.keyID,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (s *oidcSigner) Verify(raw string) (map[string]any, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected OIDC signing method")
		}
		return &s.key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		return nil, bespokeInvalidToken(err)
	}
	return map[string]any(claims), nil
}

func bespokeInvalidToken(err error) error {
	if err != nil {
		return err
	}
	return errors.New("invalid OIDC token")
}
