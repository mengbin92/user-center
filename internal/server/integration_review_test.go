package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/server"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func sessionCookie(t *testing.T, h *harness) string {
	t.Helper()
	u, err := url.Parse("http://example.com")
	require.NoError(t, err)
	for _, c := range h.jar.Cookies(u) {
		if c.Name == service.SessionCookie {
			return c.Value
		}
	}
	t.Fatal("missing session cookie")
	return ""
}

func integrationRPC(t *testing.T, h *harness) usercv1.IntegrationServiceClient {
	t.Helper()
	srv := server.NewGRPCServer(&conf.Server{Grpc: &conf.GRPC{Addr: "127.0.0.1:0"}}, zap.NewNop(), service.NewIntegrationService(biz.NewIntegrationUsecase(h.svc)))
	endpoint, err := srv.Endpoint()
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- srv.Start(context.Background()) }()
	conn, err := grpc.NewClient(endpoint.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); _ = srv.Stop(context.Background()); <-done })
	return usercv1.NewIntegrationServiceClient(conn)
}

func machineCredential(t *testing.T, h *harness, owner string, methods ...string) string {
	t.Helper()
	clientID := h.svc.IDs.NewID()
	_, err := h.svc.IntegrationClients.Create(context.Background(), nil, &biz.IntegrationClient{ClientID: clientID, Code: clientID, ServiceOwner: owner, CredentialHash: biz.HashToken("machine-secret"), Status: "active", AllowedMethods: methods})
	require.NoError(t, err)
	return clientID + ".machine-secret"
}

func TestIntegrationCallerAudienceOwnerAndRevocationBoundaries(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	rootToken := sessionCookie(t, h)
	rootSession, err := h.svc.Sessions.GetByTokenHash(context.Background(), nil, biz.HashToken(rootToken))
	require.NoError(t, err)
	other := iamFixtureUser(t, h, "rpc_other")
	require.Equal(t, http.StatusOK, h.login(other.Username, "FixturePass-123").Code)
	otherSession, err := h.svc.Sessions.GetByTokenHash(context.Background(), nil, biz.HashToken(sessionCookie(t, h)))
	require.NoError(t, err)
	rpc := integrationRPC(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = rpc.GetUser(ctx, &usercv1.IntegrationGetUserRequest{UserId: "1"})
	require.Error(t, err, "unauthenticated machine calls must fail")
	readToken := machineCredential(t, h, "billing", "GetUser")
	readCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+readToken)
	_, err = rpc.RevokeSession(readCtx, &usercv1.IntegrationRevokeSessionRequest{SessionId: rootSession.ID, SessionToken: rootToken, Reason: "review"})
	require.Error(t, err, "method allowlist must apply before the handler")
	cred := machineCredential(t, h, "billing", "ValidateSession", "GetSessionAuthorization", "GetResourceAuthorization", "RevokeSession")
	caller := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cred)
	facts, err := rpc.ValidateSession(caller, &usercv1.ValidateSessionRequest{SessionToken: rootToken, ApplicationCode: "micro-one-api"})
	require.NoError(t, err)
	require.False(t, facts.Valid, "application audience must equal the issued session audience")
	facts, err = rpc.ValidateSession(caller, &usercv1.ValidateSessionRequest{SessionToken: rootToken, ApplicationCode: biz.ApplicationCode})
	require.NoError(t, err)
	require.True(t, facts.Valid)
	projection, err := rpc.GetSessionAuthorization(caller, &usercv1.SessionAuthorizationRequest{SessionToken: rootToken, ApplicationCode: biz.ApplicationCode})
	require.NoError(t, err)
	require.Empty(t, projection.Permissions, "billing must not receive user-center policy grants")
	_, err = rpc.GetResourceAuthorization(caller, &usercv1.ResourceAuthorizationRequest{SessionToken: rootToken, Operation: "identity.user.read", ExecutionPoint: "identity.user.read", Object: &usercv1.AuthorizationObjectFacts{OwnerUserId: "1", ResourceId: "1"}})
	require.Error(t, err, "the machine cannot assert facts for a different resource owner")
	_, err = rpc.RevokeSession(caller, &usercv1.IntegrationRevokeSessionRequest{SessionId: otherSession.ID, SessionToken: rootToken, Reason: "review"})
	require.Error(t, err, "a BFF cannot revoke another user's session")
	unchanged, err := h.svc.Sessions.Get(context.Background(), nil, otherSession.ID)
	require.NoError(t, err)
	require.Nil(t, unchanged.RevokedAt)
	_, err = rpc.RevokeSession(caller, &usercv1.IntegrationRevokeSessionRequest{SessionId: rootSession.ID, Reason: "review"})
	require.Error(t, err, "a machine credential alone cannot revoke user sessions")
	_, err = rpc.RevokeSession(caller, &usercv1.IntegrationRevokeSessionRequest{SessionId: rootSession.ID, SessionToken: rootToken, Reason: "review"})
	require.NoError(t, err)
	revoked, err := h.svc.Sessions.Get(context.Background(), nil, rootSession.ID)
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)
}

func TestIntegrationClientRejectsUnknownMethodUnderValidPrefix(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/integration-clients", map[string]any{"code": "unknown_method", "service_owner": "billing", "allowed_methods": []string{"/api.usercenter.v1.IntegrationService/FutureAdminMethod"}, "reason": "review"}, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestOutboxRetainsBacklogBeyondNewestPage(t *testing.T) {
	t.Setenv("OUTBOX_SIGNING_SECRET", "review-signing-secret-at-least-32-bytes")
	h := newHarness(t)
	var received []string
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Get("X-UserCenter-Event"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	client, err := h.svc.IntegrationClients.Create(context.Background(), nil, &biz.IntegrationClient{ClientID: "backlog", Code: "backlog", ServiceOwner: "billing", Status: "active", AllowedMethods: []string{"GetUser"}, EventSubscriptions: []string{"review.backlog"}, CallbackURL: webhook.URL})
	require.NoError(t, err)
	for i := 0; i < 205; i++ {
		require.NoError(t, h.svc.Outbox.Append(context.Background(), nil, &biz.Event{EventID: "backlog-" + strconv.Itoa(i), EventType: "review.backlog", AggregateType: "user", AggregateID: 1, AggregateRevision: 1, SchemaVersion: 1, Payload: "{}", OccurredAt: client.CreatedAt.Add(time.Duration(i+1) * time.Millisecond)}))
	}
	worker := biz.NewIntegrationAdminUsecase(h.svc)
	for i := 0; i < 5; i++ {
		require.NoError(t, worker.Dispatch(context.Background()))
	}
	require.Len(t, received, 205)
	_, total, err := h.svc.Outbox.ListDeliveries(context.Background(), nil, "delivered", 0, 100)
	require.NoError(t, err)
	require.EqualValues(t, 205, total)
}
