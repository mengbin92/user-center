package data

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestProductionStartupRejectsMissingWeakAndSampleSecrets(t *testing.T) {
	valid := func() *conf.Security {
		return &conf.Security{CookieSecure: true, SessionSecret: strings.Repeat("s", 40), CsrfSecret: strings.Repeat("c", 40), MfaEncryptionKey: strings.Repeat("m", 40)}
	}
	cases := []struct {
		name      string
		configure func(*conf.Security)
	}{
		{"session", func(s *conf.Security) { s.SessionSecret = "" }},
		{"csrf", func(s *conf.Security) { s.CsrfSecret = "short" }},
		{"mfa", func(s *conf.Security) { s.MfaEncryptionKey = "sample-mfa-key-change-me-32-bytes!!" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sec := valid()
			tt.configure(sec)
			cfg := &conf.Data{Database: &conf.Database{Driver: "sqlite", Source: "file:" + filepath.Join(t.TempDir(), "prod.db")}}
			d, cleanup, err := NewData(cfg, sec, zap.NewNop())
			require.Error(t, err)
			require.Nil(t, d)
			require.Nil(t, cleanup)
		})
	}
	require.Error(t, validateProductionSecrets(nil))
	require.NoError(t, validateProductionSecrets(valid()))
}

func TestConfiguredRedisFailureDoesNotFallBackToMemory(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	cfg := &conf.Data{Database: &conf.Database{Driver: "sqlite", Source: "file:" + filepath.Join(t.TempDir(), "redis.db")}, Redis: &conf.Redis{Addr: addr}}
	sec := &conf.Security{SessionSecret: "test", CsrfSecret: "test", MfaEncryptionKey: "test"}
	d, cleanup, err := NewData(cfg, sec, zap.NewNop())
	require.ErrorContains(t, err, "configured redis is unavailable")
	require.Nil(t, d)
	require.Nil(t, cleanup)
}

func TestUnknownDatabaseDriverRejected(t *testing.T) {
	d, cleanup, err := NewData(&conf.Data{Database: &conf.Database{Driver: "myslq"}}, nil, zap.NewNop())
	require.ErrorContains(t, err, "unsupported database driver")
	require.Nil(t, d)
	require.Nil(t, cleanup)
}
