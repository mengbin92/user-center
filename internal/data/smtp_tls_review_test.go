package data

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"net/textproto"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSMTPRejectsRemoteCleartextSubmission(t *testing.T) {
	smtp := startFakeSMTP(t)
	err := sendSMTP(context.Background(), smtp.addr, "smtp.example.com", nil, "from@example.com", "to@example.com", []byte("verification code"))
	require.Error(t, err, "remote SMTP must not send verification codes when STARTTLS is missing")
	require.Empty(t, smtp.messages())
}

func TestSMTPRejectsUntrustedSTARTTLSCertificate(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		protocol := textproto.NewConn(conn)
		_ = protocol.PrintfLine("220 localhost ESMTP")
		if _, err = protocol.ReadLine(); err != nil {
			return
		}
		_ = protocol.PrintfLine("250-localhost")
		_ = protocol.PrintfLine("250 STARTTLS")
		if _, err = protocol.ReadLine(); err != nil {
			return
		}
		_ = protocol.PrintfLine("220 Ready to start TLS")
		_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	require.Error(t, sendSMTP(context.Background(), listener.Addr().String(), "smtp.example.com", nil, "from@example.com", "to@example.com", []byte("verification code")))
	<-done
}
