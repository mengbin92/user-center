package biz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// OIDCError is translated to an OAuth2 JSON error by the HTTP transport. When
// RedirectURI is set the error is returned to the validated client redirect.
type OIDCError struct {
	Code        string
	Description string
	Status      int
	RedirectURI string
	State       string
}

func (e *OIDCError) Error() string { return e.Code + ": " + e.Description }

func oidcErr(code, description string, status int) *OIDCError {
	return &OIDCError{Code: code, Description: description, Status: status}
}

type OIDCClientCredential struct {
	Client *OIDCClient
	Secret string
}

type OIDCClientInput struct {
	Name         string
	ServiceOwner string
	RedirectURIs []string
	Scopes       []string
	Public       bool
	RequirePKCE  bool
	AccessTTL    int
	RefreshTTL   int
}

type OIDCConfig struct {
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type OIDCAuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

type OIDCTokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
}

type OIDCUsecase struct {
	*Services
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewOIDCUsecase(s *Services) *OIDCUsecase {
	issuer := s.OIDCIssuer
	if issuer == "" {
		issuer = strings.TrimRight(s.PublicBaseURL, "/")
	}
	access := s.OIDCAccessTTL
	if access <= 0 {
		access = 15 * time.Minute
	}
	refresh := s.OIDCRefreshTTL
	if refresh <= 0 {
		refresh = 24 * time.Hour
	}
	return &OIDCUsecase{Services: s, issuer: strings.TrimRight(issuer, "/"), accessTTL: access, refreshTTL: refresh}
}

func (uc *OIDCUsecase) Issuer() string { return uc.issuer }

func (uc *OIDCUsecase) Discovery() map[string]any {
	base := uc.issuer
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oidc/authorize",
		"token_endpoint":                        base + "/oidc/token",
		"userinfo_endpoint":                     base + "/oidc/userinfo",
		"jwks_uri":                              base + "/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"claims_supported":                      []string{"sub", "name", "preferred_username", "email", "email_verified", "auth_time"},
	}
}

func (uc *OIDCUsecase) JWKS() map[string]any {
	return map[string]any{"keys": []any{uc.OIDCSigner.PublicJWK()}}
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))
}

func normalizeScopes(scopes []string) ([]string, error) {
	allowed := map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true}
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		for _, s := range strings.Fields(raw) {
			if !allowed[s] {
				return nil, Validation("不支持的 OIDC scope: " + s)
			}
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	if !slices.Contains(out, "openid") {
		return nil, Validation("OIDC scope 必须包含 openid")
	}
	return out, nil
}

func validateOIDCClient(in OIDCClientInput) ([]string, []string, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.ServiceOwner = strings.TrimSpace(in.ServiceOwner)
	if in.Name == "" || in.ServiceOwner == "" {
		return nil, nil, Validation("名称和 service_owner 不能为空")
	}
	if len(in.RedirectURIs) == 0 {
		return nil, nil, Validation("至少需要一个 redirect_uri")
	}
	for _, u := range in.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, nil, Validation("redirect_uri 必须是 HTTPS（localhost 可用 HTTP）且不能含 fragment")
		}
	}
	scopes, err := normalizeScopes(in.Scopes)
	if err != nil {
		return nil, nil, err
	}
	if in.AccessTTL <= 0 {
		in.AccessTTL = 900
	}
	if in.RefreshTTL <= 0 {
		in.RefreshTTL = 86400
	}
	if in.AccessTTL < 60 || in.AccessTTL > 86400 || in.RefreshTTL < 300 || in.RefreshTTL > 2592000 {
		return nil, nil, Validation("token 有效期超出允许范围")
	}
	if in.Public {
		in.RequirePKCE = true
	}
	return nil, scopes, nil
}

func (uc *OIDCUsecase) Clients(ctx context.Context, actor ActorContext) ([]*OIDCClient, error) {
	if _, err := uc.Authorize(ctx, actor, "oidc.client.read", 0, true); err != nil {
		return nil, err
	}
	return uc.OIDCClients.ListOIDCClients(ctx, nil)
}

func (uc *OIDCUsecase) CreateClient(ctx context.Context, actor ActorContext, in OIDCClientInput, reason string) (*OIDCClientCredential, error) {
	if _, err := uc.Authorize(ctx, actor, "oidc.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	_, scopes, err := validateOIDCClient(in)
	if err != nil {
		return nil, err
	}
	if in.Public {
		in.RequirePKCE = true
	}
	if in.AccessTTL <= 0 {
		in.AccessTTL = 900
	}
	if in.RefreshTTL <= 0 {
		in.RefreshTTL = 86400
	}
	rawID, err := newToken(16)
	if err != nil {
		return nil, ErrDependency
	}
	client := &OIDCClient{
		ClientID: "oidc_" + rawID, Name: in.Name, ServiceOwner: in.ServiceOwner,
		Status: "active", RedirectURIs: in.RedirectURIs, Scopes: scopes,
		Public: in.Public, RequirePKCE: in.RequirePKCE, AccessTTL: in.AccessTTL, RefreshTTL: in.RefreshTTL,
	}
	secret := ""
	if !in.Public {
		secret, err = newToken(32)
		if err != nil {
			return nil, ErrDependency
		}
		client.SecretHash = HashToken(secret)
	}
	var created *OIDCClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.OIDCClients.CreateOIDCClient(ctx, tx, client)
		if err != nil {
			return err
		}
		created = row
		return uc.audit(ctx, tx, actor, "oidc.client.create", row.ClientID, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return &OIDCClientCredential{Client: created, Secret: secret}, nil
}

func (uc *OIDCUsecase) UpdateClient(ctx context.Context, actor ActorContext, id int64, in OIDCClientInput, expected uint64, reason string) (*OIDCClient, error) {
	if _, err := uc.Authorize(ctx, actor, "oidc.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	existing, err := uc.OIDCClients.GetOIDCClient(ctx, nil, id)
	if err != nil {
		return nil, ErrOIDCClientNotFound
	}
	in.Name, in.ServiceOwner = existing.Name, existing.ServiceOwner
	_, scopes, err := validateOIDCClient(in)
	if err != nil {
		return nil, err
	}
	if in.Public != existing.Public {
		return nil, Validation("public 属性不可修改，请新建客户端")
	}
	if in.AccessTTL <= 0 {
		in.AccessTTL = 900
	}
	if in.RefreshTTL <= 0 {
		in.RefreshTTL = 86400
	}
	existing.Name, existing.RedirectURIs, existing.Scopes = in.Name, in.RedirectURIs, scopes
	existing.Public, existing.RequirePKCE = in.Public, in.RequirePKCE
	if existing.Public {
		existing.RequirePKCE = true
	}
	existing.AccessTTL, existing.RefreshTTL = in.AccessTTL, in.RefreshTTL
	var updated *OIDCClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.OIDCClients.UpdateOIDCClient(ctx, tx, existing, expected)
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "oidc.client.update", row.ClientID, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *OIDCUsecase) RotateSecret(ctx context.Context, actor ActorContext, id int64, reason string) (*OIDCClientCredential, error) {
	if _, err := uc.Authorize(ctx, actor, "oidc.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	existing, err := uc.OIDCClients.GetOIDCClient(ctx, nil, id)
	if err != nil || existing.Public {
		return nil, ErrOIDCClientNotFound
	}
	secret, err := newToken(32)
	if err != nil {
		return nil, ErrDependency
	}
	var updated *OIDCClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.OIDCClients.RotateOIDCClientSecret(ctx, tx, id, HashToken(secret))
		if err != nil {
			return err
		}
		updated = row
		return uc.audit(ctx, tx, actor, "oidc.client.rotate", row.ClientID, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return &OIDCClientCredential{Client: updated, Secret: secret}, nil
}

func (uc *OIDCUsecase) DisableClient(ctx context.Context, actor ActorContext, id int64, reason string) (*OIDCClient, error) {
	if _, err := uc.Authorize(ctx, actor, "oidc.client.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	existing, err := uc.OIDCClients.GetOIDCClient(ctx, nil, id)
	if err != nil {
		return nil, ErrOIDCClientNotFound
	}
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.OIDCClients.DisableOIDCClient(ctx, tx, id); err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "oidc.client.disable", existing.ClientID, "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	existing.Status = "disabled"
	existing.Revision++
	return existing, nil
}

func (uc *OIDCUsecase) AuthorizeRequest(ctx context.Context, actor ActorContext, req OIDCAuthorizeRequest) (string, error) {
	if actor.User == nil || actor.Session == nil {
		return "", oidcErr("access_denied", "user session is required", 401)
	}
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, req.ClientID)
	if err != nil || client.Status != "active" {
		return "", oidcErr("invalid_request", "unknown or disabled client", 400)
	}
	redirect := ""
	for _, u := range client.RedirectURIs {
		if u == req.RedirectURI {
			redirect = u
			break
		}
	}
	if redirect == "" {
		return "", oidcErr("invalid_request", "redirect_uri is not registered", 400)
	}
	state := req.State
	if req.ResponseType != "code" {
		return "", &OIDCError{Code: "unsupported_response_type", Description: "only code is supported", Status: 400, RedirectURI: redirect, State: state}
	}
	scopes, serr := normalizeScopes([]string{req.Scope})
	if serr != nil {
		return "", &OIDCError{Code: "invalid_scope", Description: serr.Error(), Status: 400, RedirectURI: redirect, State: state}
	}
	scope := strings.Join(scopes, " ")
	challenge := req.CodeChallenge
	method := req.CodeChallengeMethod
	if challenge != "" {
		if method == "" {
			method = "plain"
		}
		if method != "S256" {
			return "", &OIDCError{Code: "invalid_request", Description: "only S256 PKCE is supported", Status: 400, RedirectURI: redirect, State: state}
		}
	} else if client.Public || client.RequirePKCE {
		return "", &OIDCError{Code: "invalid_request", Description: "PKCE code_challenge is required", Status: 400, RedirectURI: redirect, State: state}
	}
	rawCode, err := newToken(32)
	if err != nil {
		return "", ErrDependency
	}
	authTime := actor.Session.IssuedAt
	if authTime.IsZero() {
		authTime = uc.Clock.Now()
	}
	code := &OIDCCode{
		CodeHash: HashToken(rawCode), ClientID: client.ClientID, UserID: actor.User.ID,
		RedirectURI: redirect, Scope: scope, Nonce: req.Nonce,
		CodeChallenge: challenge, CodeChallengeMethod: method,
		AuthTime: authTime.UTC(), ExpiresAt: uc.Clock.Now().Add(5 * time.Minute).UTC(),
	}
	if err := uc.OIDCCodes.CreateOIDCCode(ctx, nil, code); err != nil {
		return "", ErrDependency
	}
	return appendQuery(redirect, map[string]string{"code": rawCode, "state": state}), nil
}

func appendQuery(raw string, values map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range values {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (uc *OIDCUsecase) Token(ctx context.Context, req OIDCTokenRequest) (map[string]any, error) {
	client, err := uc.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" || req.RedirectURI == "" {
			return nil, oidcErr("invalid_request", "code and redirect_uri are required", 400)
		}
		code, err := uc.OIDCCodes.ConsumeOIDCCode(ctx, nil, HashToken(req.Code), client.ClientID, req.RedirectURI, now)
		if err != nil {
			return nil, oidcErr("invalid_grant", "authorization code is invalid, used or expired", 400)
		}
		if code.CodeChallenge != "" {
			if req.CodeVerifier == "" || !verifyPKCE(code.CodeChallenge, req.CodeVerifier) {
				return nil, oidcErr("invalid_grant", "PKCE verification failed", 400)
			}
		}
		return uc.issueTokens(ctx, client, code.UserID, code.Scope, code.Nonce, code.AuthTime)
	case "refresh_token":
		if req.RefreshToken == "" {
			return nil, oidcErr("invalid_request", "refresh_token is required", 400)
		}
		refresh, err := uc.OIDCCodes.ConsumeOIDCRefreshToken(ctx, nil, HashToken(req.RefreshToken), client.ClientID, now)
		if err != nil {
			return nil, oidcErr("invalid_grant", "refresh token is invalid, used or expired", 400)
		}
		return uc.issueTokens(ctx, client, refresh.UserID, refresh.Scope, "", refresh.AuthTime)
	default:
		return nil, oidcErr("unsupported_grant_type", "only authorization_code and refresh_token are supported", 400)
	}
}

func (uc *OIDCUsecase) authenticateClient(ctx context.Context, clientID, secret string) (*OIDCClient, error) {
	if clientID == "" {
		return nil, oidcErr("invalid_client", "client_id is required", 401)
	}
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, clientID)
	if err != nil || client.Status != "active" {
		return nil, oidcErr("invalid_client", "unknown or disabled client", 401)
	}
	if client.Public {
		return client, nil
	}
	if secret == "" || subtle.ConstantTimeCompare([]byte(HashToken(secret)), []byte(client.SecretHash)) != 1 {
		return nil, oidcErr("invalid_client", "client authentication failed", 401)
	}
	return client, nil
}

func verifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func (uc *OIDCUsecase) issueTokens(ctx context.Context, client *OIDCClient, userID int64, scope, nonce string, authTime time.Time) (map[string]any, error) {
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil || user.Status != UserStatusEnabled {
		return nil, oidcErr("invalid_grant", "user is unavailable", 400)
	}
	now := uc.Clock.Now().UTC()
	accessTTL := time.Duration(client.AccessTTL) * time.Second
	refreshTTL := time.Duration(client.RefreshTTL) * time.Second
	exp := now.Add(accessTTL)
	accessClaims := map[string]any{
		"iss": uc.issuer, "sub": itoa(user.ID), "aud": client.ClientID,
		"exp": exp.Unix(), "iat": now.Unix(), "jti": uc.IDs.NewID(),
		"scope": scope, "client_id": client.ClientID, "token_type": "access",
	}
	access, err := uc.OIDCSigner.Sign(accessClaims)
	if err != nil {
		return nil, ErrDependency
	}
	scopes := strings.Fields(scope)
	idClaims := map[string]any{
		"iss": uc.issuer, "sub": itoa(user.ID), "aud": client.ClientID,
		"exp": exp.Unix(), "iat": now.Unix(), "auth_time": authTime.Unix(),
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if slices.Contains(scopes, "profile") {
		idClaims["name"] = user.DisplayName
		idClaims["preferred_username"] = user.Username
	}
	if slices.Contains(scopes, "email") {
		idClaims["email"] = user.Email
		idClaims["email_verified"] = user.EmailVerified
	}
	idToken, err := uc.OIDCSigner.Sign(idClaims)
	if err != nil {
		return nil, ErrDependency
	}
	resp := map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(accessTTL.Seconds()), "id_token": idToken, "scope": scope,
	}
	if slices.Contains(scopes, "offline_access") {
		raw, err := newToken(32)
		if err != nil {
			return nil, ErrDependency
		}
		refresh := &OIDCRefreshToken{
			TokenHash: HashToken(raw), ClientID: client.ClientID, UserID: user.ID,
			Scope: scope, AuthTime: authTime.UTC(), ExpiresAt: now.Add(refreshTTL).UTC(),
		}
		if err := uc.OIDCCodes.CreateOIDCRefreshToken(ctx, nil, refresh); err != nil {
			return nil, ErrDependency
		}
		resp["refresh_token"] = raw
	}
	return resp, nil
}

func (uc *OIDCUsecase) UserInfo(ctx context.Context, raw string) (map[string]any, error) {
	claims, err := uc.OIDCSigner.Verify(raw)
	if err != nil {
		return nil, oidcErr("invalid_token", "access token is invalid or expired", 401)
	}
	if claims["iss"] != uc.issuer || claims["token_type"] != "access" {
		return nil, oidcErr("invalid_token", "access token is invalid", 401)
	}
	sub, _ := claims["sub"].(string)
	userID, err := ParseID(sub, "sub")
	if err != nil {
		return nil, oidcErr("invalid_token", "access token subject is invalid", 401)
	}
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil || user.Status != UserStatusEnabled {
		return nil, oidcErr("invalid_token", "user is unavailable", 401)
	}
	out := map[string]any{"sub": sub}
	scope, _ := claims["scope"].(string)
	if slices.Contains(strings.Fields(scope), "profile") {
		out["name"] = user.DisplayName
		out["preferred_username"] = user.Username
	}
	if slices.Contains(strings.Fields(scope), "email") {
		out["email"] = user.Email
		out["email_verified"] = user.EmailVerified
	}
	return out, nil
}

func (uc *OIDCUsecase) ErrorRedirect(err error) (redirect, state string, ok bool) {
	var oe *OIDCError
	if errors.As(err, &oe) && oe.RedirectURI != "" {
		target := appendQuery(oe.RedirectURI, map[string]string{
			"error": oe.Code, "error_description": oe.Description, "state": oe.State,
		})
		return target, oe.State, true
	}
	return "", "", false
}

var _ = fmt.Sprintf
var _ = jsonx.Marshal
