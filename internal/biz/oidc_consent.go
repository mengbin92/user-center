package biz

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// OIDC consent (V2.4 R1).
//
// The authorize endpoint never issues a code for an unapproved scope set: it
// parks the validated request behind a one-time handle and sends the browser to
// the consent page. The handle is opaque and bound to the authenticated user,
// so the client_id, redirect_uri and state are never exposed to tampering.

// OIDCConsentPrompt is what the consent page displays.
type OIDCConsentPrompt struct {
	Client       *OIDCClient
	Scopes       []string
	Granted      []string
	RedirectHost string
	RequestedAt  time.Time
	ExpiresAt    time.Time
}

func (uc *OIDCUsecase) consentRequired(ctx context.Context, client *OIDCClient, userID int64, scopes []string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	consent, err := uc.OIDCConsents.GetConsent(ctx, nil, client.ClientID, userID)
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return true, nil
		}
		return false, err
	}
	for _, scope := range scopes {
		if !slices.Contains(consent.Scopes, scope) {
			return true, nil
		}
	}
	return false, nil
}

func (uc *OIDCUsecase) parkConsentRequest(ctx context.Context, actor ActorContext, client *OIDCClient, req OIDCAuthorizeRequest, redirect, scope, challenge, method string, authTime time.Time) (string, error) {
	raw, err := newToken(32)
	if err != nil {
		return "", ErrDependency
	}
	parked := &OIDCConsentRequest{
		HandleHash: HashToken(raw), ClientID: client.ClientID, UserID: actor.User.ID,
		RedirectURI: redirect, Scope: scope, State: req.State, Nonce: req.Nonce,
		CodeChallenge: challenge, CodeChallengeMethod: method,
		AuthTime: authTime.UTC(), IdentityVersion: actor.User.IdentityVersion,
		CreatedAt: uc.Clock.Now().UTC(), ExpiresAt: uc.Clock.Now().Add(10 * time.Minute).UTC(),
	}
	if err := uc.OIDCConsents.CreateConsentRequest(ctx, nil, parked); err != nil {
		return "", ErrDependency
	}
	return "/consent?handle=" + url.QueryEscape(raw), nil
}

// ConsentPrompt resolves the display view for a parked request. The handle is
// not consumed here so a reload of the page still works.
func (uc *OIDCUsecase) ConsentPrompt(ctx context.Context, actor ActorContext, handle string) (*OIDCConsentPrompt, error) {
	if strings.TrimSpace(handle) == "" {
		return nil, ErrResourceNotFound
	}
	parked, err := uc.OIDCConsents.GetConsentRequest(ctx, nil, HashToken(handle), actor.User.ID, uc.Clock.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return nil, ErrResourceNotFound
		}
		return nil, ErrDependency
	}
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, parked.ClientID)
	if err != nil || client.Status != "active" {
		return nil, ErrResourceNotFound
	}
	if !slices.Contains(client.RedirectURIs, parked.RedirectURI) {
		return nil, ErrResourceNotFound
	}
	host := ""
	if u, err := url.Parse(parked.RedirectURI); err == nil {
		host = u.Host
	}
	granted := []string{}
	if consent, err := uc.OIDCConsents.GetConsent(ctx, nil, parked.ClientID, actor.User.ID); err == nil {
		granted = consent.Scopes
	} else if !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	return &OIDCConsentPrompt{
		Client: client, Scopes: strings.Fields(parked.Scope), Granted: granted,
		RedirectHost: host, RequestedAt: parked.CreatedAt, ExpiresAt: parked.ExpiresAt,
	}, nil
}

// DecideConsent consumes the one-time handle and either issues the authorization
// code or returns access_denied. The decision is final: a second attempt is a
// 404, never a second code.
func (uc *OIDCUsecase) DecideConsent(ctx context.Context, actor ActorContext, handle string, approve, remember bool) (string, error) {
	if strings.TrimSpace(handle) == "" {
		return "", ErrResourceNotFound
	}
	now := uc.Clock.Now().UTC()
	var redirect string
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		parked, err := uc.OIDCConsents.ConsumeConsentRequest(ctx, tx, HashToken(handle), actor.User.ID, now)
		if err != nil {
			if errors.Is(err, ErrResourceNotFound) {
				return ErrResourceNotFound
			}
			return ErrDependency
		}
		client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, tx, parked.ClientID)
		if err != nil || client.Status != "active" {
			return ErrResourceNotFound
		}
		if !slices.Contains(client.RedirectURIs, parked.RedirectURI) {
			return ErrResourceNotFound
		}
		if !approve {
			if err := uc.audit(ctx, tx, actor, "oidc.consent.deny", client.ClientID, "{}", "{}", "{}", "user denied consent", "success"); err != nil {
				return err
			}
			redirect = appendQuery(parked.RedirectURI, map[string]string{
				"error": "access_denied", "error_description": "the user denied the request", "state": parked.State,
			})
			return nil
		}
		if remember {
			scopes := strings.Fields(parked.Scope)
			if existing, err := uc.OIDCConsents.GetConsent(ctx, tx, client.ClientID, actor.User.ID); err == nil {
				for _, scope := range existing.Scopes {
					if !slices.Contains(scopes, scope) {
						scopes = append(scopes, scope)
					}
				}
			} else if !errors.Is(err, ErrResourceNotFound) {
				return ErrDependency
			}
			if err := uc.OIDCConsents.UpsertConsent(ctx, tx, &OIDCConsent{
				ClientID: client.ClientID, UserID: actor.User.ID, Scopes: scopes, GrantedAt: now,
			}); err != nil {
				return ErrDependency
			}
		}
		rawCode, err := newToken(32)
		if err != nil {
			return ErrDependency
		}
		code := &OIDCCode{
			CodeHash: HashToken(rawCode), ClientID: client.ClientID, UserID: parked.UserID,
			IdentityVersion: parked.IdentityVersion, RedirectURI: parked.RedirectURI,
			Scope: parked.Scope, Nonce: parked.Nonce,
			CodeChallenge: parked.CodeChallenge, CodeChallengeMethod: parked.CodeChallengeMethod,
			AuthTime: parked.AuthTime, ExpiresAt: now.Add(5 * time.Minute).UTC(),
		}
		if err := uc.OIDCCodes.CreateOIDCCode(ctx, tx, code); err != nil {
			return ErrDependency
		}
		if err := uc.audit(ctx, tx, actor, "oidc.consent.grant", client.ClientID, "{}",
			string(mustJSON(map[string]any{"scopes": strings.Fields(parked.Scope), "remember": remember})), "{}", "user approved consent", "success"); err != nil {
			return err
		}
		redirect = appendQuery(parked.RedirectURI, map[string]string{"code": rawCode, "state": parked.State})
		return nil
	})
	if err != nil {
		return "", err
	}
	return redirect, nil
}

// Consents lists the clients this user has approved.
func (uc *OIDCUsecase) Consents(ctx context.Context, actor ActorContext) ([]*OIDCConsent, error) {
	consents, err := uc.OIDCConsents.ListConsentsByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	return consents, nil
}

// ClientNames resolves display names for a consent list without exposing other
// clients' configuration.
func (uc *OIDCUsecase) ClientName(ctx context.Context, clientID string) string {
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, clientID)
	if err != nil {
		return ""
	}
	return client.Name
}

func (uc *OIDCUsecase) RevokeConsent(ctx context.Context, actor ActorContext, clientID string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return Validation("client_id 不能为空")
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.OIDCConsents.DeleteConsent(ctx, tx, clientID, actor.User.ID); err != nil {
			return err // ErrResourceNotFound: no row, therefore no audit
		}
		return uc.audit(ctx, tx, actor, "oidc.consent.revoke", clientID, "{}", "{}", "{}", "user revoked consent", "success")
	})
}

// RP-initiated logout (V2.4 R2).

type OIDCLogoutRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
}

// Logout ends the local session and resolves the validated post-logout target.
// An invalid or expired hint is treated exactly like a missing hint: it never
// reveals whether the session or the user still exists.
//
// The local session is always revoked before the redirect is validated. A
// bad or unregistered post_logout_redirect_uri must not turn into "logged out
// in the browser but still valid on the server"; it only suppresses the
// redirect and yields an error page the transport renders after clearing the
// cookie.
func (uc *OIDCUsecase) Logout(ctx context.Context, actor ActorContext, req OIDCLogoutRequest) (string, error) {
	hintClientID := ""
	if strings.TrimSpace(req.IDTokenHint) != "" {
		if claims, err := uc.OIDCSigner.Verify(req.IDTokenHint); err == nil && claims["iss"] == uc.issuer {
			if aud, ok := claims["aud"].(string); ok && aud != "" && claims["sub"] != nil {
				hintClientID = aud
			}
		}
	}
	explicitClientID := strings.TrimSpace(req.ClientID)
	// RP-Initiated Logout 1.0: when both are supplied, client_id must match the
	// hint's aud. A mismatch is rejected below, but the local session is still
	// ended (fail-safe: a request must never leave a session alive by accident).
	mismatch := explicitClientID != "" && hintClientID != "" && explicitClientID != hintClientID
	clientID := explicitClientID
	if clientID == "" {
		clientID = hintClientID
	}
	if actor.Session != nil {
		now := uc.Clock.Now().UTC()
		if err := uc.Sessions.Revoke(ctx, nil, actor.Session.ID, &now); err != nil {
			return "", ErrDependency
		}
		_ = uc.StepUp.Delete(ctx, StepUpKey(actor.Session))
		_ = uc.audit(ctx, nil, actor, "auth.logout", actor.Session.ID, "{}", "{}", "{}", "RP-initiated logout", "success")
	}
	if mismatch {
		return "", oidcErr("invalid_request", "client_id does not match id_token_hint", 400)
	}
	target := strings.TrimSpace(req.PostLogoutRedirectURI)
	redirect := ""
	if target != "" {
		client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, clientID)
		if err != nil || client.Status != "active" || !slices.Contains(client.PostLogoutRedirectURIs, target) {
			return "", oidcErr("invalid_request", "post_logout_redirect_uri is not registered", 400)
		}
		redirect = appendQuery(target, map[string]string{"state": req.State})
	}
	return redirect, nil
}
