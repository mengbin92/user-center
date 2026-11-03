package data

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSavedConsoleMailOverridesFileSMTPWithoutLoggingCodes(t *testing.T) {
	d := testData(t)
	settings := NewSettingsRepo(d)
	_, err := settings.SaveEmail(context.Background(), nil, &biz.EmailSettings{Driver: "console", From: "test@example.com", SMTPPort: 587}, "", 1)
	require.NoError(t, err)
	core, logs := observer.New(zap.InfoLevel)
	sender := NewMailSender(d, zap.New(core), &conf.Mail{Driver: "smtp", Smtp: &conf.SMTP{Host: "127.0.0.1", Port: 1}})
	require.NoError(t, sender.Send(context.Background(), "user@example.com", "验证码", "secret 135791"))
	require.Len(t, logs.All(), 1)
	require.NotContains(t, fmt.Sprint(logs.All()[0].ContextMap()), "135791")
	require.NotContains(t, fmt.Sprint(logs.All()[0].ContextMap()), "body")
}

func TestMailDependencyFailuresCannotBecomeConsoleSuccess(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		d := testData(t)
		require.NoError(t, d.DB().Migrator().DropTable(&emailSettingsPO{}))
		sender := NewMailSender(d, zap.NewNop(), &conf.Mail{Driver: "console"})
		require.ErrorIs(t, sender.Send(context.Background(), "user@example.com", "subject", "code"), biz.ErrDependency)
	})
	t.Run("encrypted secret", func(t *testing.T) {
		d := testData(t)
		_, err := NewSettingsRepo(d).SaveEmail(context.Background(), nil, &biz.EmailSettings{Driver: "smtp", From: "test@example.com", SMTPHost: "127.0.0.1", SMTPPort: 1}, "invalid-ciphertext", 1)
		require.NoError(t, err)
		sender := NewMailSender(d, zap.NewNop(), nil)
		require.ErrorIs(t, sender.Send(context.Background(), "user@example.com", "subject", "code"), biz.ErrDependency)
	})
}

func TestSMTPHonorsRequestDeadlineWhileWaitingForGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.Error(t, sendSMTP(ctx, listener.Addr().String(), "localhost", nil, "from@example.com", "to@example.com", []byte("message")))
	require.Less(t, time.Since(started), time.Second)
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("SMTP connection not accepted")
	}
}
