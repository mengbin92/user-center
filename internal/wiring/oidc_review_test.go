package wiring

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func oidcDevelopmentConfig() *conf.Bootstrap {
	return &conf.Bootstrap{
		Data:   &conf.Data{Database: &conf.Database{Driver: "sqlite"}},
		Server: &conf.Server{Http: &conf.HTTP{PublicBaseUrl: "http://localhost:5173"}},
	}
}

func TestOIDCRuntimeRejectsInvalidIssuerAndLifetime(t *testing.T) {
	for _, tt := range []struct {
		name, env, value string
		production       bool
	}{
		{"remote_http", "OIDC_ISSUER", "http://issuer.example.com", false},
		{"userinfo", "OIDC_ISSUER", "https://user:password@issuer.example.com", false},
		{"query", "OIDC_ISSUER", "https://issuer.example.com?query=1", false},
		{"fragment", "OIDC_ISSUER", "https://issuer.example.com#fragment", false},
		{"relative", "OIDC_ISSUER", "/issuer", false},
		{"production_http", "OIDC_ISSUER", "http://localhost:8080", true},
		{"access_parse", "OIDC_ACCESS_TTL_SECONDS", "incorrect", false},
		{"access_range", "OIDC_ACCESS_TTL_SECONDS", "86401", false},
		{"refresh_overflow", "OIDC_REFRESH_TTL_SECONDS", "999999999999", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OIDC_ISSUER", "")
			t.Setenv("OIDC_ACCESS_TTL_SECONDS", "")
			t.Setenv("OIDC_REFRESH_TTL_SECONDS", "")
			t.Setenv(tt.env, tt.value)
			b := oidcDevelopmentConfig()
			if tt.production {
				b.Data.Database.Driver = "mysql"
			}
			cfg, err := NewRuntimeConfig(b)
			require.Error(t, err)
			require.Nil(t, cfg)
		})
	}
	t.Setenv("OIDC_ISSUER", "https://issuer.example.com/identity")
	t.Setenv("OIDC_ACCESS_TTL_SECONDS", "600")
	t.Setenv("OIDC_REFRESH_TTL_SECONDS", "3600")
	cfg, err := NewRuntimeConfig(oidcDevelopmentConfig())
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com/identity", cfg.OIDCIssuer)
	require.Equal(t, 600*time.Second, cfg.OIDCAccessTTL)
}

func TestOfflineRescueDoesNotDependOnOIDCConfiguration(t *testing.T) {
	t.Setenv("OIDC_SIGNING_KEY_PEM", "invalid key")
	t.Setenv("OIDC_ISSUER", "invalid issuer")
	b := oidcDevelopmentConfig()
	b.Data.Database.Source = "file:" + filepath.Join(t.TempDir(), "rescue.db")
	d, cleanup, err := data.NewData(b.Data, &conf.Security{}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.NoError(t, d.AutoMigrate())
	require.NoError(t, data.SeedCatalog(d.DB()))
	svc := BuildServices(d, b)
	require.NotNil(t, svc)
	_, err = svc.BootstrapRoot(context.Background(), "root", "root@example.com", "Test-password-1234")
	require.NoError(t, err)
}
