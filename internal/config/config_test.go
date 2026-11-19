package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/conf"
)

func TestApplyEnvMaterializesMissingConfig(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":8181")
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("COOKIE_SECURE", "TRUE")
	t.Setenv("TENANT_SCHEMA_ISOLATION", "yes")
	var bootstrap conf.Bootstrap
	require.NoError(t, applyEnv(&bootstrap))
	require.Equal(t, ":8181", bootstrap.GetServer().GetHttp().GetAddr())
	require.Equal(t, "sqlite", bootstrap.GetData().GetDatabase().GetDriver())
	require.True(t, bootstrap.GetData().GetTenancy().GetSchemaIsolation())
	require.True(t, bootstrap.GetSecurity().GetCookieSecure())
}

func TestApplyEnvRejectsMalformedSafetySettings(t *testing.T) {
	for name, value := range map[string]string{
		"COOKIE_SECURE": "ture", "TENANT_SCHEMA_ISOLATION": "enabled",
		"RATE_LIMIT_WRITE_PER_MINUTE": "2147483648", "REDIS_DB": "-1",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			require.ErrorContains(t, applyEnv(&conf.Bootstrap{}), name)
		})
	}
}
