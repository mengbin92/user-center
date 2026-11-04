package biz

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// OAuthProfile is the verified external identity returned by a provider.
type OAuthProfile struct {
	Subject string
	Issuer  string
	Display string
	Email   string
}

// OAuthProvider is the server-side protocol adapter. Browser clients never
// receive provider secrets or access tokens.
type OAuthProvider interface {
	Name() string
	AuthCodeURL(state, redirectURI string) string
	Exchange(ctx context.Context, code, redirectURI string) (OAuthProfile, error)
}

type oauthState struct {
	Provider        string `json:"provider"`
	Mode            string `json:"mode"`
	UserID          int64  `json:"user_id"`
	SessionID       string `json:"session_id"`
	IdentityVersion uint64 `json:"identity_version"`
	RedirectURI     string `json:"redirect_uri"`
	Next            string `json:"next,omitempty"`
}

type OAuthResult struct {
	Status           string
	ChallengeID      string
	ChallengeExpires time.Time
	Session          *Session
	RawToken         string
	User             *User
	Redirect         string
}

func (uc *AuthUsecase) OAuthProviders() []string {
	var out []string
	// An explicit enable list in auth settings wins: toggling a provider must
	// actually change the login entry points. An empty list keeps the legacy
	// behavior of exposing every configured provider.
	if settings, err := uc.Settings.GetAuth(context.Background(), nil); err == nil && len(settings.Providers) > 0 {
		for _, name := range settings.Providers {
			if p := uc.OAuth[name]; p != nil {
				out = append(out, name)
			}
		}
		return out
	}
	for name, p := range uc.OAuth {
		if p != nil {
			out = append(out, name)
		}
	}
	return out
}

func (uc *AuthUsecase) oauthProvider(name string) (OAuthProvider, error) {
	p, ok := uc.OAuth[name]
	if !ok || p == nil {
		return nil, ErrOAuthUnavailable
	}
	return p, nil
}

func (uc *AuthUsecase) oauthRedirectURI(provider string) string {
	return strings.TrimRight(uc.PublicBaseURL, "/") + "/api/v1/auth/providers/" + provider + "/callback"
}

// StartOAuth creates a single-use state and returns the provider redirect.
// Binding mode requires an authenticated session; the state carries the user
// so the callback cannot be replayed for another account.
func (uc *AuthUsecase) StartOAuth(ctx context.Context, provider, mode, next string, actor *ActorContext) (string, string, time.Time, error) {
	p, err := uc.oauthProvider(provider)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if mode == "" {
		mode = "login"
	}
	if mode != "login" && mode != "bind" && mode != "verify" {
		return "", "", time.Time{}, Validation("不支持的第三方登录模式")
	}
	state := oauthState{Provider: provider, Mode: mode, RedirectURI: uc.oauthRedirectURI(provider)}
	if mode == "login" && next != "" {
		u, err := url.ParseRequestURI(next)
		if err != nil || len(next) > 8192 || !strings.HasPrefix(next, "/") || u.IsAbs() || u.Host != "" || u.Path != "/oidc/authorize" {
			return "", "", time.Time{}, Validation("第三方登录回跳仅支持本机 OIDC 授权入口")
		}
		state.Next = next
	}
	if mode == "bind" || mode == "verify" {
		if actor == nil || actor.User == nil || actor.Session == nil {
			return "", "", time.Time{}, ErrUnauthenticated
		}
		state.UserID = actor.User.ID
		state.SessionID = actor.Session.ID
		state.IdentityVersion = actor.Session.IdentityVersion
		if mode == "verify" {
			identities, err := uc.Identities.ListByUser(ctx, nil, actor.User.ID)
			if err != nil {
				return "", "", time.Time{}, ErrDependency
			}
			bound := false
			for _, identity := range identities {
				if identity.Provider == provider {
					bound = true
					break
				}
			}
			if !bound {
				return "", "", time.Time{}, ErrOAuthNotBound
			}
		}
	}
	raw, _ := jsonx.Marshal(state)
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(10 * time.Minute)
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: "oauth_state", Payload: string(raw), ExpiresAt: expires,
	}); err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	return p.AuthCodeURL(id, state.RedirectURI), id, expires, nil
}

func (uc *AuthUsecase) CompleteOAuth(ctx context.Context, provider, state, code string, actor *ActorContext, ip, ua string) (*OAuthResult, error) {
	p, err := uc.oauthProvider(provider)
	if err != nil {
		return nil, err
	}
	c, err := uc.Challenges.Get(ctx, "oauth_state", state)
	if err != nil {
		return nil, ErrOAuthState
	}
	defer func() { _ = uc.Challenges.Delete(ctx, state) }()
	var st oauthState
	if err := jsonx.Unmarshal([]byte(c.Payload), &st); err != nil || st.Provider != provider || st.RedirectURI == "" {
		return nil, ErrOAuthState
	}
	if err := uc.Flows.Complete(ctx, nil, state, "oauth_state", st.UserID, "oauth"); err != nil {
		return nil, ErrOAuthState
	}
	profile, err := p.Exchange(ctx, code, st.RedirectURI)
	if err != nil {
		return nil, ErrOAuthUnavailable
	}
	if profile.Subject == "" {
		return nil, ErrOAuthUnavailable
	}
	if profile.Issuer == "" {
		profile.Issuer = provider
	}
	if st.Mode == "bind" || st.Mode == "verify" {
		if actor == nil || actor.User == nil || actor.Session == nil || actor.User.ID != st.UserID || actor.Session.ID != st.SessionID || actor.Session.IdentityVersion != st.IdentityVersion {
			return nil, ErrUnauthenticated
		}
	}
	if st.Mode == "verify" {
		identity, err := uc.Identities.FindBySubject(ctx, nil, provider, profile.Issuer, profile.Subject)
		if errors.Is(err, ErrResourceNotFound) || err == nil && identity.UserID != st.UserID {
			return nil, ErrOAuthNotBound
		}
		if err != nil {
			return nil, ErrDependency
		}
		until := uc.Clock.Now().Add(5 * time.Minute)
		if err := uc.StepUp.Put(ctx, primaryProofKey(actor.Session), until); err != nil {
			return nil, ErrDependency
		}
		uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "external_identity_verify", "success", ip, ua, actor.RequestID)
		return &OAuthResult{Redirect: "/account/security?verified=" + provider}, nil
	}
	if st.Mode == "bind" {
		err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
			if existing, ferr := uc.Identities.FindBySubject(ctx, tx, provider, profile.Issuer, profile.Subject); ferr == nil {
				if existing.UserID == st.UserID {
					return nil
				}
				return ErrOAuthBound
			}
			if _, cerr := uc.Identities.Create(ctx, tx, &ExternalIdentity{
				UserID: st.UserID, Provider: provider, ProviderSubject: profile.Subject,
				Issuer: profile.Issuer, Display: profile.Display,
			}); cerr != nil {
				return cerr
			}
			if err := uc.audit(ctx, tx, *actor, "identity.external.bind", itoa(st.UserID), "{}", "{}", "{}", "self-service external identity binding", "success"); err != nil {
				return err
			}
			payload, _ := jsonx.Marshal(map[string]any{"user_id": st.UserID, "provider": provider})
			return uc.emit(ctx, tx, "user", st.UserID, actor.User.Revision, "user.profile.updated", string(payload))
		})
		if err != nil {
			return nil, err
		}
		return &OAuthResult{Redirect: "/account/security?bound=" + provider}, nil
	}
	identity, err := uc.Identities.FindBySubject(ctx, nil, provider, profile.Issuer, profile.Subject)
	if err != nil {
		return nil, ErrOAuthNotBound
	}
	user, err := uc.Users.Get(ctx, nil, identity.UserID)
	if err != nil {
		return nil, ErrOAuthNotBound
	}
	if user.Status != UserStatusEnabled {
		return nil, ErrUnauthenticated
	}
	mfa, merr := uc.MFA.Get(ctx, nil, user.ID)
	if merr != nil && !errors.Is(merr, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	if mfa != nil && mfa.Enabled() {
		challengeID := uc.IDs.NewID()
		expires := uc.Clock.Now().Add(5 * time.Minute)
		payload, _ := jsonx.Marshal(map[string]any{"identity_version": user.IdentityVersion, "ip": ip, "ua": SummizeAgent(ua)})
		if err := uc.Challenges.Put(ctx, Challenge{ID: challengeID, Purpose: "mfa", Payload: string(payload), UserID: user.ID, ExpiresAt: expires}); err != nil {
			return nil, ErrDependency
		}
		target := "/login?mfa_challenge=" + challengeID
		if st.Next != "" {
			target += "&next=" + url.QueryEscape(st.Next)
		}
		return &OAuthResult{Status: "mfa_required", ChallengeID: challengeID, ChallengeExpires: expires, Redirect: target}, nil
	}
	cred, err := uc.Credentials.Get(ctx, nil, user.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	session, raw, err := uc.issueSession(ctx, user, ua, ip)
	if err != nil {
		return nil, err
	}
	result := &OAuthResult{
		Session: session, RawToken: raw, User: uc.publicUser(ctx, user),
		Redirect: "/auth/callback/" + provider + "?status=success",
	}
	if st.Next != "" {
		result.Redirect = st.Next
	}
	if cred != nil && cred.MustChangePassword {
		result.Redirect = "/account/security?password_change_required=1"
		if st.Next != "" {
			result.Redirect += "&next=" + url.QueryEscape(st.Next)
		}
	}
	return result, nil
}

var _ = fmt.Sprintf
