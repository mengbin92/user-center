package biz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
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
	Name                   string
	ServiceOwner           string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Public                 bool
	RequirePKCE            bool
	AccessTTL              int
	RefreshTTL             int
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
	MaxAge              string
}

type OIDCTokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
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
		"end_session_endpoint":                  base + "/oidc/logout",
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
	if err != nil || strings.Contains(raw, "#") || u.Host == "" || u.User != nil || len(raw) > 512 {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))
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

func (uc *OIDCUsecase) validateClient(in *OIDCClientInput) ([]string, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.ServiceOwner = strings.TrimSpace(in.ServiceOwner)
	if in.Name == "" || in.ServiceOwner == "" || utf8.RuneCountInString(in.Name) > 128 || utf8.RuneCountInString(in.ServiceOwner) > 64 {
		return nil, Validation("名称和 service_owner 不能为空，且不能超过 128/64 个字符")
	}
	if len(in.RedirectURIs) == 0 {
		return nil, Validation("至少需要一个 redirect_uri")
	}
	for _, u := range in.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, Validation("redirect_uri 必须是 HTTPS（localhost 可用 HTTP），不能含用户信息/fragment，最长 512 字节")
		}
	}
	if len(in.PostLogoutRedirectURIs) > 10 {
		return nil, Validation("登出回调地址最多 10 个")
	}
	for _, u := range in.PostLogoutRedirectURIs {
		if !validRedirectURI(u) {
			return nil, Validation("post_logout_redirect_uri 必须是 HTTPS（localhost 可用 HTTP），不能含用户信息/fragment")
		}
	}
	in.PostLogoutRedirectURIs = dedupeStrings(in.PostLogoutRedirectURIs)
	scopes, err := normalizeScopes(in.Scopes)
	if err != nil {
		return nil, err
	}
	if in.AccessTTL < 0 || in.RefreshTTL < 0 {
		return nil, Validation("token 有效期不能为负数")
	}
	if in.AccessTTL == 0 {
		in.AccessTTL = int(uc.accessTTL.Seconds())
	}
	if in.RefreshTTL == 0 {
		in.RefreshTTL = int(uc.refreshTTL.Seconds())
	}
	if in.AccessTTL < 60 || in.AccessTTL > 86400 || in.RefreshTTL < 300 || in.RefreshTTL > 2592000 {
		return nil, Validation("token 有效期超出允许范围")
	}
	if in.Public {
		in.RequirePKCE = true
	}
	return scopes, nil
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, value := range in {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func (uc *OIDCUsecase) managementGuard(ctx context.Context, tx Tx, actor ActorContext, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	if actor.ExpectedPolicyRevision == 0 {
		return Validation("expected_policy_revision 不能为空")
	}
	policy, err := uc.Policy.PolicyRevision(ctx, tx)
	if err != nil {
		return ErrDependency
	}
	if policy != actor.ExpectedPolicyRevision {
		return ConflictPolicy(policy)
	}
	current, err := uc.currentIAMActor(ctx, actor)
	if err != nil {
		return err
	}
	if err := uc.authenticationRestrictions(ctx, tx, current.User); err != nil {
		return err
	}
	if _, err := uc.Authorize(ctx, current, "oidc.client.update", 0, true); err != nil {
		return err
	}
	return uc.RequireStepUp(ctx, current)
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
	scopes, err := uc.validateClient(&in)
	if err != nil {
		return nil, err
	}
	rawID, err := newToken(16)
	if err != nil {
		return nil, ErrDependency
	}
	client := &OIDCClient{
		ClientID: "oidc_" + rawID, Name: in.Name, ServiceOwner: in.ServiceOwner,
		Status: "active", RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs, Scopes: scopes,
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
		if err := uc.managementGuard(ctx, tx, actor, reason); err != nil {
			return err
		}
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
		return nil, err
	}
	in.ServiceOwner = existing.ServiceOwner
	scopes, err := uc.validateClient(&in)
	if err != nil {
		return nil, err
	}
	if in.Public != existing.Public {
		return nil, Validation("public 属性不可修改，请新建客户端")
	}
	existing.Name, existing.RedirectURIs, existing.Scopes = in.Name, in.RedirectURIs, scopes
	existing.PostLogoutRedirectURIs = in.PostLogoutRedirectURIs
	existing.Public, existing.RequirePKCE = in.Public, in.RequirePKCE
	if existing.Public {
		existing.RequirePKCE = true
	}
	existing.AccessTTL, existing.RefreshTTL = in.AccessTTL, in.RefreshTTL
	var updated *OIDCClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementGuard(ctx, tx, actor, reason); err != nil {
			return err
		}
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
	if err != nil {
		return nil, err
	}
	if existing.Public {
		return nil, ErrOIDCClientNotFound
	}
	secret, err := newToken(32)
	if err != nil {
		return nil, ErrDependency
	}
	var updated *OIDCClient
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementGuard(ctx, tx, actor, reason); err != nil {
			return err
		}
		if actor.ExpectedTargetRevision == 0 {
			return Validation("expected_revision 不能为空")
		}
		row, err := uc.OIDCClients.RotateOIDCClientSecret(ctx, tx, id, HashToken(secret), actor.ExpectedTargetRevision)
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
		return nil, err
	}
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementGuard(ctx, tx, actor, reason); err != nil {
			return err
		}
		if actor.ExpectedTargetRevision == 0 {
			return Validation("expected_revision 不能为空")
		}
		if err := uc.OIDCClients.DisableOIDCClient(ctx, tx, id, actor.ExpectedTargetRevision); err != nil {
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
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, req.ClientID)
	if err != nil && !errors.Is(err, ErrOIDCClientNotFound) {
		return "", ErrDependency
	}
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
	reject := func(code, description string) (string, error) {
		return "", &OIDCError{Code: code, Description: description, Status: 400, RedirectURI: redirect, State: state}
	}
	if req.ResponseType != "code" {
		return reject("unsupported_response_type", "only code is supported")
	}
	scopes, serr := normalizeScopes([]string{req.Scope})
	if serr != nil {
		return reject("invalid_scope", "requested scope is not supported")
	}
	if !oidcScopesAllowed(scopes, client.Scopes) {
		return reject("invalid_scope", "requested scope is not registered for this client")
	}
	scope := strings.Join(scopes, " ")
	challenge := req.CodeChallenge
	method := req.CodeChallengeMethod
	if challenge != "" {
		if method == "" {
			method = "plain"
		}
		decoded, err := base64.RawURLEncoding.DecodeString(challenge)
		if method != "S256" || len(challenge) != 43 || err != nil || len(decoded) != sha256.Size {
			return reject("invalid_request", "a valid S256 PKCE code_challenge is required")
		}
	} else if client.Public || client.RequirePKCE {
		return reject("invalid_request", "PKCE code_challenge is required")
	} else if method != "" {
		return reject("invalid_request", "code_challenge_method requires code_challenge")
	}
	if utf8.RuneCountInString(req.Nonce) > 255 {
		return reject("invalid_request", "nonce is too long")
	}
	if utf8.RuneCountInString(req.State) > 512 {
		return reject("invalid_request", "state is too long")
	}
	prompts := strings.Fields(req.Prompt)
	if slices.Contains(prompts, "none") && len(prompts) != 1 {
		return reject("invalid_request", "prompt none cannot be combined with other values")
	}
	for _, prompt := range prompts {
		switch prompt {
		case "none", "consent":
		case "login":
			return reject("login_required", "fresh authentication is required")
		case "select_account":
			return reject("account_selection_required", "account selection is not available")
		default:
			return reject("invalid_request", "unsupported prompt")
		}
	}
	var maxAge int64
	if req.MaxAge != "" {
		var err error
		maxAge, err = strconv.ParseInt(req.MaxAge, 10, 64)
		if err != nil || maxAge < 0 {
			return reject("invalid_request", "max_age must be a non-negative integer")
		}
	}
	if actor.User == nil || actor.Session == nil {
		if slices.Contains(prompts, "none") {
			return reject("login_required", "user session is required")
		}
		return "", oidcErr("login_required", "user session is required", 401)
	}
	current, err := uc.currentIAMActor(ctx, actor)
	if err != nil {
		if errors.Is(err, ErrDependency) {
			return "", err
		}
		return reject("login_required", "user session is no longer valid")
	}
	actor = current
	if err := uc.authenticationRestrictions(ctx, nil, actor.User); err != nil {
		if !errors.Is(err, ErrPasswordChange) && !errors.Is(err, ErrMFAEnrollmentReq) {
			return "", err
		}
		if slices.Contains(prompts, "none") {
			return reject("interaction_required", "account security requirements must be completed")
		}
		if errors.Is(err, ErrPasswordChange) {
			return "/account/security?password_change_required=1", nil
		}
		if errors.Is(err, ErrMFAEnrollmentReq) {
			return "/account/security?mfa_enrollment_required=1", nil
		}
	}
	if req.MaxAge != "" && (maxAge == 0 || uc.Clock.Now().Unix()-actor.Session.IssuedAt.Unix() > maxAge) {
		return reject("login_required", "authentication is older than max_age")
	}
	authTime := actor.Session.IssuedAt
	if authTime.IsZero() {
		authTime = uc.Clock.Now()
	}
	// Consent (V2.4 R1): an unapproved or widened scope set is parked behind a
	// one-time handle instead of issuing a code. prompt=consent always
	// re-prompts; prompt=none fails with interaction_required instead of
	// silently granting.
	needConsent, cerr := uc.consentRequired(ctx, client, actor.User.ID, scopes, slices.Contains(prompts, "consent"))
	if cerr != nil {
		return "", ErrDependency
	}
	if needConsent {
		if slices.Contains(prompts, "none") {
			return reject("interaction_required", "user consent is required")
		}
		return uc.parkConsentRequest(ctx, actor, client, req, redirect, scope, challenge, method, authTime)
	}
	rawCode, err := newToken(32)
	if err != nil {
		return "", ErrDependency
	}
	code := &OIDCCode{
		CodeHash: HashToken(rawCode), ClientID: client.ClientID, UserID: actor.User.ID,
		IdentityVersion: actor.User.IdentityVersion,
		RedirectURI:     redirect, Scope: scope, Nonce: req.Nonce,
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
	var response map[string]any
	var committedError error
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		client, err := uc.authenticateClient(ctx, tx, req.ClientID, req.ClientSecret)
		if err != nil {
			return err
		}
		now := uc.Clock.Now().UTC()
		switch req.GrantType {
		case "authorization_code":
			if req.Code == "" || req.RedirectURI == "" {
				return oidcErr("invalid_request", "code and redirect_uri are required", 400)
			}
			code, err := uc.OIDCCodes.ConsumeOIDCCode(ctx, tx, HashToken(req.Code), client.ClientID, req.RedirectURI, now)
			if err != nil {
				if !errors.Is(err, ErrOIDCInvalidGrant) {
					return ErrDependency
				}
				return oidcErr("invalid_grant", "authorization code is invalid, used or expired", 400)
			}
			if !slices.Contains(client.RedirectURIs, code.RedirectURI) {
				return oidcErr("invalid_grant", "redirect_uri is no longer registered", 400)
			}
			if code.CodeChallenge != "" {
				if !verifyPKCE(code.CodeChallenge, req.CodeVerifier) {
					return oidcErr("invalid_grant", "PKCE verification failed", 400)
				}
			} else if req.CodeVerifier != "" || client.Public || client.RequirePKCE {
				return oidcErr("invalid_grant", "PKCE verification failed", 400)
			}
			response, err = uc.issueTokens(ctx, tx, client, code.UserID, code.IdentityVersion, code.Scope, code.Nonce, code.AuthTime, "", time.Time{})
			return err
		case "refresh_token":
			if req.RefreshToken == "" {
				return oidcErr("invalid_request", "refresh_token is required", 400)
			}
			refresh, err := uc.OIDCCodes.ConsumeOIDCRefreshToken(ctx, tx, HashToken(req.RefreshToken), client.ClientID, now)
			if err != nil {
				if refresh != nil && errors.Is(err, ErrOIDCInvalidGrant) {
					committedError = oidcErr("invalid_grant", "refresh token reuse detected", 400)
					return nil // Persist the repository's revocation of the entire token family.
				}
				if !errors.Is(err, ErrOIDCInvalidGrant) {
					return ErrDependency
				}
				return oidcErr("invalid_grant", "refresh token is invalid, used or expired", 400)
			}
			scope := refresh.Scope
			if req.Scope != "" {
				scopes, err := normalizeScopes([]string{req.Scope})
				if err != nil || !oidcScopesAllowed(scopes, strings.Fields(refresh.Scope)) {
					return oidcErr("invalid_scope", "refresh scope must be a subset of the original scope", 400)
				}
				scope = strings.Join(scopes, " ")
			}
			response, err = uc.issueTokens(ctx, tx, client, refresh.UserID, refresh.IdentityVersion, scope, "", refresh.AuthTime, refresh.FamilyID, refresh.ExpiresAt)
			return err
		default:
			return oidcErr("unsupported_grant_type", "only authorization_code and refresh_token are supported", 400)
		}
	})
	if err == nil && committedError != nil {
		err = committedError
	}
	return response, err
}

func (uc *OIDCUsecase) authenticateClient(ctx context.Context, tx Tx, clientID, secret string) (*OIDCClient, error) {
	if clientID == "" {
		return nil, oidcErr("invalid_client", "client_id is required", 401)
	}
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, tx, clientID)
	if err != nil && !errors.Is(err, ErrOIDCClientNotFound) {
		return nil, ErrDependency
	}
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
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func oidcScopesAllowed(scopes, registered []string) bool {
	for _, scope := range scopes {
		if !slices.Contains(registered, scope) {
			return false
		}
	}
	return true
}

func (uc *OIDCUsecase) authenticationRestrictions(ctx context.Context, tx Tx, user *User) error {
	credential, err := uc.Credentials.Get(ctx, tx, user.ID)
	if err == nil && credential.MustChangePassword {
		return ErrPasswordChange
	}
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return ErrDependency
	}
	roles, err := uc.Users.RolesForUser(ctx, tx, user.ID)
	if err != nil {
		return ErrDependency
	}
	user.Roles = roles
	return uc.requireAdminMFA(ctx, ActorContext{User: user})
}

func (uc *OIDCUsecase) issueTokens(ctx context.Context, tx Tx, client *OIDCClient, userID int64, identityVersion uint64, scope, nonce string, authTime time.Time, familyID string, refreshExpiry time.Time) (map[string]any, error) {
	user, err := uc.Users.Get(ctx, tx, userID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}
	if err != nil || user.Status != UserStatusEnabled || identityVersion == 0 || user.IdentityVersion != identityVersion {
		return nil, oidcErr("invalid_grant", "user is unavailable", 400)
	}
	if err := uc.authenticationRestrictions(ctx, tx, user); err != nil {
		if errors.Is(err, ErrPasswordChange) || errors.Is(err, ErrMFAEnrollmentReq) {
			return nil, oidcErr("invalid_grant", "account security requirements must be completed", 400)
		}
		return nil, err
	}
	if !oidcScopesAllowed(strings.Fields(scope), client.Scopes) {
		return nil, oidcErr("invalid_scope", "scope is no longer registered for this client", 400)
	}
	now := uc.Clock.Now().UTC()
	accessTTL := time.Duration(client.AccessTTL) * time.Second
	refreshTTL := time.Duration(client.RefreshTTL) * time.Second
	exp := now.Add(accessTTL)
	accessClaims := map[string]any{
		"iss": uc.issuer, "sub": itoa(user.ID), "aud": client.ClientID,
		"exp": exp.Unix(), "iat": now.Unix(), "jti": uc.IDs.NewID(),
		"scope": scope, "client_id": client.ClientID, "token_type": "access",
		"identity_version": uitoa(identityVersion),
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
		if familyID == "" {
			familyID = uc.IDs.NewID()
		}
		if refreshExpiry.IsZero() || now.Add(refreshTTL).Before(refreshExpiry) {
			refreshExpiry = now.Add(refreshTTL).UTC()
		}
		refresh := &OIDCRefreshToken{
			TokenHash: HashToken(raw), ClientID: client.ClientID, UserID: user.ID,
			IdentityVersion: identityVersion,
			FamilyID:        familyID,
			Scope:           scope, AuthTime: authTime.UTC(), ExpiresAt: refreshExpiry,
		}
		if err := uc.OIDCCodes.CreateOIDCRefreshToken(ctx, tx, refresh); err != nil {
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
	clientID, _ := claims["client_id"].(string)
	client, err := uc.OIDCClients.GetOIDCClientByClientID(ctx, nil, clientID)
	if err != nil && !errors.Is(err, ErrOIDCClientNotFound) {
		return nil, ErrDependency
	}
	if err != nil || client.Status != "active" || claims["aud"] != clientID {
		return nil, oidcErr("invalid_token", "access token client is unavailable", 401)
	}
	sub, _ := claims["sub"].(string)
	userID, err := ParseID(sub, "sub")
	if err != nil {
		return nil, oidcErr("invalid_token", "access token subject is invalid", 401)
	}
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}
	if err != nil || user.Status != UserStatusEnabled || claims["identity_version"] != uitoa(user.IdentityVersion) {
		return nil, oidcErr("invalid_token", "user is unavailable", 401)
	}
	if err := uc.authenticationRestrictions(ctx, nil, user); err != nil {
		if !errors.Is(err, ErrPasswordChange) && !errors.Is(err, ErrMFAEnrollmentReq) {
			return nil, err
		}
		return nil, oidcErr("invalid_token", "account security requirements are not satisfied", 401)
	}
	out := map[string]any{"sub": sub}
	scope, _ := claims["scope"].(string)
	if !oidcScopesAllowed(strings.Fields(scope), client.Scopes) {
		return nil, oidcErr("invalid_token", "access token scope is no longer available", 401)
	}
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
