package data

import (
	"context"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/conf"
)

type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	msgs []string
	done chan struct{}
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeSMTP{addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-f.done })
	return f
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 localhost ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_ = tp.PrintfLine("250-localhost")
			_ = tp.PrintfLine("250 8BITMIME")
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"), strings.HasPrefix(upper, "RSET"):
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(upper, "DATA"):
			_ = tp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				l, err := tp.ReadLine()
				if err != nil {
					return
				}
				if l == "." {
					break
				}
				b.WriteString(l)
				b.WriteString("\r\n")
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, b.String())
			f.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case strings.HasPrefix(upper, "QUIT"):
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 OK")
		}
	}
}

func (f *fakeSMTP) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func TestMailSenderUsesRuntimeSMTPSettings(t *testing.T) {
	d := testData(t)
	smtp := startFakeSMTP(t)
	host, portRaw, err := net.SplitHostPort(smtp.addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portRaw)
	require.NoError(t, err)

	repo := NewSettingsRepo(d)
	settings, secret, err := repo.GetEmail(context.Background(), nil)
	require.NoError(t, err)
	settings.Driver = "smtp"
	settings.From = "noreply@example.com"
	settings.SMTPHost = host
	settings.SMTPPort = port
	settings.SMTPUsername = ""
	_, err = repo.SaveEmail(context.Background(), nil, settings, secret, 0)
	require.NoError(t, err)

	mailer := NewMailSender(d, zap.NewNop(), &conf.Mail{Driver: "console"})
	err = mailer.Send(context.Background(), "user@example.com", "验证码", "你的验证码是 123456")
	require.NoError(t, err)

	msgs := smtp.messages()
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "To: user@example.com")
	require.Contains(t, msgs[0], "Subject:")
	require.Contains(t, msgs[0], "123456")
}
