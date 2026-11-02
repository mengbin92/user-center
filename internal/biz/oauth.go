package biz

import (
	"context"
	"fmt"
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
	Provider    string `json:"provider"`
	Mode        string `json:"mode"`
	UserID      int64  `json:"user_id"`
	RedirectURI string `json:"redirect_uri"`
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
func (uc *AuthUsecase) StartOAuth(ctx context.Context, provider, mode string, actor *ActorContext) (string, string, time.Time, error) {
	p, err := uc.oauthProvider(provider)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if mode == "" {
		mode = "login"
	}
	if mode != "login" && mode != "bind" {
		return "", "", time.Time{}, Validation("不支持的第三方登录模式")
	}
	state := oauthState{Provider: provider, Mode: mode, RedirectURI: uc.oauthRedirectURI(provider)}
	if mode == "bind" {
		if actor == nil || actor.User == nil {
			return "", "", time.Time{}, ErrUnauthenticated
		}
		state.UserID = actor.User.ID
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
	if st.Mode == "bind" {
		if actor == nil || actor.User == nil || actor.User.ID != st.UserID {
			return nil, ErrUnauthenticated
		}
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
	if state, merr := uc.MFA.Get(ctx, nil, user.ID); merr == nil && state.Enabled() {
		challengeID := uc.IDs.NewID()
		expires := uc.Clock.Now().Add(5 * time.Minute)
		payload, _ := jsonx.Marshal(map[string]any{"user_id": user.ID, "ip": ip, "ua": SummizeAgent(ua)})
		if err := uc.Challenges.Put(ctx, Challenge{ID: challengeID, Purpose: "mfa", Payload: string(payload), UserID: user.ID, ExpiresAt: expires}); err != nil {
			return nil, ErrDependency
		}
		return &OAuthResult{Status: "mfa_required", ChallengeID: challengeID, ChallengeExpires: expires, Redirect: "/login?mfa_challenge=" + challengeID}, nil
	}
	session, raw, err := uc.issueSession(ctx, user, ua, ip)
	if err != nil {
		return nil, err
	}
	cred, _ := uc.Credentials.Get(ctx, nil, user.ID)
	result := &OAuthResult{
		Session: session, RawToken: raw, User: uc.publicUser(ctx, user),
		Redirect: "/auth/callback/" + provider + "?status=success",
	}
	if cred != nil && cred.MustChangePassword {
		result.Redirect = "/account/security?password_change_required=1"
	}
	return result, nil
}

var _ = fmt.Sprintf
