package biz

import (
	"context"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Internal gRPC login (V2.4 R7). Everything below the service layer is shared
// with the HTTP login path: credential lookup, failure counters, rate limits,
// MFA challenges and session creation. Only the audience differs.

type IntegrationAuthResult struct {
	Status           string
	ChallengeID      string
	ChallengeExpires time.Time
	SessionToken     string
	SessionID        string
	UserID           int64
	SessionExpires   time.Time
}

func (uc *IntegrationUsecase) integrationAppID(ctx context.Context, requested string) (string, *IntegrationClient, error) {
	client, err := integrationClientFromContext(ctx)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(requested) != "" && requested != client.Code {
		return "", nil, ErrPermissionDenied
	}
	if strings.TrimSpace(client.Code) == "" {
		return "", nil, ErrPermissionDenied
	}
	return client.Code, client, nil
}

func (uc *IntegrationUsecase) Authenticate(ctx context.Context, appID, username, password, ip, ua, requestID string) (*IntegrationAuthResult, error) {
	audience, client, err := uc.integrationAppID(ctx, appID)
	if err != nil {
		return nil, err
	}
	auth := &AuthUsecase{Services: uc.Services}
	result, err := auth.LoginForApplication(ctx, LoginInput{
		Username: username, Password: password, IP: ip, UserAgent: ua,
	}, audience)
	if err != nil {
		return nil, err
	}
	out := &IntegrationAuthResult{Status: result.Status, UserID: result.User.ID}
	if result.Status == "mfa_required" {
		out.ChallengeID = result.ChallengeID
		out.ChallengeExpires = result.ChallengeExpires
		return out, nil
	}
	out.SessionToken = result.RawToken
	out.SessionID = result.Session.ID
	out.SessionExpires = result.Session.ExpiresAt
	uc.auditIntegrationLogin(ctx, client, result.User.ID, result.Session.ID, requestID, false)
	return out, nil
}

func (uc *IntegrationUsecase) CompleteMFA(ctx context.Context, challengeID, code, ip, ua, requestID string) (*IntegrationAuthResult, error) {
	_, client, err := uc.integrationAppID(ctx, "")
	if err != nil {
		return nil, err
	}
	auth := &AuthUsecase{Services: uc.Services}
	result, err := auth.CompleteMFAForApplication(ctx, challengeID, code, ip, ua, client.Code)
	if err != nil {
		return nil, err
	}
	out := &IntegrationAuthResult{
		Status: "authenticated", UserID: result.User.ID,
		SessionToken: result.RawToken, SessionID: result.Session.ID,
		SessionExpires: result.Session.ExpiresAt,
	}
	uc.auditIntegrationLogin(ctx, client, result.User.ID, result.Session.ID, requestID, true)
	return out, nil
}

func (uc *IntegrationUsecase) auditIntegrationLogin(ctx context.Context, client *IntegrationClient, userID int64, sessionID, requestID string, mfa bool) {
	action := "auth.integration_login"
	if mfa {
		action = "auth.integration_login_mfa"
	}
	actor := ActorContext{
		User:      &User{ID: userID},
		Actor:     authorization.Actor{UserID: userID, ServiceID: client.ClientID},
		RequestID: requestID,
	}
	_ = uc.audit(ctx, nil, actor, action, sessionID, "{}", "{}", "{}", "integration gRPC authentication", "success")
}
