package data

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/conf"
)

// TestLiveSMTP is opt-in and only reads credentials from the process
// environment; it never writes secrets to the repository or logs.
// Run with:
//
//	SMTP_LIVE_TEST=1 SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... \
//	SMTP_PASS=... SMTP_FROM=... SMTP_TO=... go test ./internal/data -run TestLiveSMTP -v
func TestLiveSMTP(t *testing.T) {
	if os.Getenv("SMTP_LIVE_TEST") != "1" {
		t.Skip("set SMTP_LIVE_TEST=1 to send a real message")
	}
	host := os.Getenv("SMTP_HOST")
	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	require.NoError(t, err)
	user, pass := os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS")
	from, to := os.Getenv("SMTP_FROM"), os.Getenv("SMTP_TO")
	require.NotEmpty(t, host)
	require.NotEmpty(t, user)
	require.NotEmpty(t, pass)
	require.NotEmpty(t, from)
	if to == "" {
		to = from
	}

	d := testData(t)
	secret, err := NewSecretBox(d.secure).Encrypt(pass)
	require.NoError(t, err)
	repo := NewSettingsRepo(d)
	settings, _, err := repo.GetEmail(context.Background(), nil)
	require.NoError(t, err)
	settings.Driver = "smtp"
	settings.From = from
	settings.SMTPHost = host
	settings.SMTPPort = port
	settings.SMTPUsername = user
	_, err = repo.SaveEmail(context.Background(), nil, settings, secret, 0)
	require.NoError(t, err)

	mailer := NewMailSender(d, zap.NewNop(), &conf.Mail{Driver: "console"})
	err = mailer.Send(context.Background(), to, "用户中心 SMTP 验收", "这是一封来自 user-center 的真实 SMTP 验收邮件，用于验证 STARTTLS 与认证配置。")
	require.NoError(t, err)
	t.Log("SMTP server accepted the message")
}
