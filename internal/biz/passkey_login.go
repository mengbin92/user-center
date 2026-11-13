package biz

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// Passkey passwordless login (ported from micro-one-api v0.41). This is a
// first factor: the assertion replaces username + password. Accounts that
// still have TOTP enabled owe the second factor afterwards, exactly like the
// password path.
//
// The public begin endpoint must not reveal whether an account exists, is
// enabled, or owns a passkey. Every one of those cases receives a challenge
// with the same shape; decoys are bound to user 0 and fail at complete with
// the same reason as a real account's invalid assertion.
const (
	PasskeyLoginPurpose = "webauthn_login"

	passkeyLoginChallengeTTL = 5 * time.Minute
	passkeyLoginIPLimit      = 30
	passkeyLoginIPWindow     = 5 * time.Minute
)

type PasskeyLoginChallenge struct {
	ChallengeID        string
	Challenge          string
	RPID               string
	AllowCredentialIDs []string
	ExpiresAt          time.Time
}

type PasskeyLoginInput struct {
	ChallengeID string
	Assertion   WebAuthnAssertion
	Remember    bool
	IP          string
	UserAgent   string
}

func (uc *AuthUsecase) BeginPasskeyLogin(ctx context.Context, identifier, ip string) (*PasskeyLoginChallenge, error) {
	if ok, err := uc.Limiter.Allow(ctx, "passkey-login:"+ip, passkeyLoginIPLimit, passkeyLoginIPWindow); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, Validation("请输入用户名或邮箱")
	}
	rpID, origin, err := uc.webAuthnRP()
	if err != nil {
		return nil, ErrDependency
	}

	var user *User
	if strings.Contains(identifier, "@") {
		user, err = uc.Users.GetByEmail(ctx, nil, NormalizeEmail(identifier))
	} else {
		user, err = uc.Users.GetByUsername(ctx, nil, NormalizeUsername(identifier))
	}
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return nil, ErrDependency
		}
		return uc.decoyPasskeyLoginChallenge(ctx, identifier, rpID, origin)
	}
	if user == nil || user.Status != UserStatusEnabled {
		return uc.decoyPasskeyLoginChallenge(ctx, identifier, rpID, origin)
	}
	if uc.WebAuthn == nil {
		return nil, ErrDependency
	}
	creds, err := uc.WebAuthn.ListByUser(ctx, nil, user.ID)
	if err != nil {
		return nil, ErrDependency
	}
	if len(creds) == 0 {
		return uc.decoyPasskeyLoginChallenge(ctx, identifier, rpID, origin)
	}
	allow := make([]string, 0, len(creds))
	for _, cred := range creds {
		allow = append(allow, cred.CredentialID)
	}
	id, raw, expires, err := uc.putPasskeyLoginChallenge(ctx, user.ID, user.IdentityVersion, rpID, origin)
	if err != nil {
		return nil, ErrDependency
	}
	return &PasskeyLoginChallenge{
		ChallengeID: id, Challenge: raw, RPID: rpID,
		AllowCredentialIDs: allow, ExpiresAt: expires,
	}, nil
}

// decoyPasskeyLoginChallenge mirrors a real challenge. The single fake
// credential is deterministic per identifier, so probing the same account
// twice sees a stable list instead of an empty one. It is keyed with the
// server secret rather than the raw identifier so a client cannot recompute
// the fake ID and tell a decoy from a real credential.
func (uc *AuthUsecase) decoyPasskeyLoginChallenge(ctx context.Context, identifier, rpID, origin string) (*PasskeyLoginChallenge, error) {
	mac := hmac.New(sha256.New, []byte(uc.CodeSecret))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(identifier))))
	allow := []string{base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
	id, raw, expires, err := uc.putPasskeyLoginChallenge(ctx, 0, 0, rpID, origin)
	if err != nil {
		return nil, ErrDependency
	}
	return &PasskeyLoginChallenge{
		ChallengeID: id, Challenge: raw, RPID: rpID,
		AllowCredentialIDs: allow, ExpiresAt: expires,
	}, nil
}

func (uc *AuthUsecase) putPasskeyLoginChallenge(ctx context.Context, userID int64, identityVersion uint64, rpID, origin string) (string, string, time.Time, error) {
	raw, err := newToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(passkeyLoginChallengeTTL)
	payload, _ := jsonx.Marshal(webAuthnChallengePayload{
		Challenge: raw, UserID: itoa(userID), IdentityVersion: uitoa(identityVersion),
		RPID: rpID, Origin: origin,
	})
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: PasskeyLoginPurpose, Payload: string(payload),
		UserID: userID, ExpiresAt: expires,
	}); err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	return id, raw, expires, nil
}

// CompletePasskeyLogin verifies the assertion and lands on the shared login
// tail. The challenge is consumed inside the same transaction that advances
// the credential counter, so two concurrent completions cannot both mint a
// session.
func (uc *AuthUsecase) CompletePasskeyLogin(ctx context.Context, in PasskeyLoginInput) (*LoginResult, error) {
	if uc.WebAuthn == nil {
		return nil, ErrDependency
	}
	if ok, err := uc.Limiter.Allow(ctx, "passkey-login:"+in.IP, passkeyLoginIPLimit, passkeyLoginIPWindow); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}
	c, err := uc.Challenges.Get(ctx, PasskeyLoginPurpose, in.ChallengeID)
	if err != nil {
		return nil, ErrChallengeInvalid
	}
	var payload webAuthnChallengePayload
	if jsonx.Unmarshal([]byte(c.Payload), &payload) != nil {
		return nil, ErrChallengeInvalid
	}
	rpID, origin, err := uc.webAuthnRP()
	if err != nil {
		return nil, ErrDependency
	}
	if payload.RPID != rpID || payload.Origin != origin {
		return nil, ErrChallengeInvalid
	}
	userID, err := strconv.ParseInt(payload.UserID, 10, 64)
	if err != nil {
		return nil, ErrChallengeInvalid
	}
	// Decoy ceremonies are bound to user 0. Reject them before any account
	// lookup so their failure is indistinguishable from a real account's
	// invalid assertion.
	if userID == 0 {
		_ = uc.Challenges.Delete(ctx, in.ChallengeID)
		return nil, ErrChallengeInvalid
	}
	user, err := uc.Users.Get(ctx, nil, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrChallengeInvalid
		}
		return nil, ErrDependency
	}
	if user.Status != UserStatusEnabled {
		uc.recordSecurity(ctx, user.ID, "", "login", "denied", in.IP, in.UserAgent, "")
		return nil, ErrChallengeInvalid
	}
	if payload.IdentityVersion != uitoa(user.IdentityVersion) {
		return nil, ErrChallengeInvalid
	}

	now := uc.Clock.Now().UTC()
	var (
		mfaEnabled bool
		session    *Session
		rawToken   string
		failed     bool
	)
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		// Lock first: issueSessionLocked counts and inserts sessions under the
		// same row lock every other login path uses.
		if err := uc.Users.LockUser(ctx, tx, user.ID); err != nil {
			return ErrDependency
		}
		if err := uc.Flows.Complete(ctx, tx, in.ChallengeID, PasskeyLoginPurpose, user.ID, "session"); err != nil {
			return err
		}
		actor := ActorContext{
			User: user, Session: &Session{ID: "passkey-login", UserID: user.ID},
			IP: in.IP, UserAgent: in.UserAgent,
		}
		if err := uc.verifyWebAuthnAssertion(ctx, tx, actor, payload.Challenge, in.Assertion, now); err != nil {
			failed = true
			return err
		}
		state, err := uc.MFA.Get(ctx, tx, user.ID)
		if err != nil && !errors.Is(err, ErrResourceNotFound) {
			return ErrDependency
		}
		mfaEnabled = state != nil && state.Enabled()
		if mfaEnabled {
			return nil
		}
		session, rawToken, err = uc.issueSessionLocked(ctx, tx, user, in.UserAgent, in.IP, ApplicationCode)
		return err
	})
	if err != nil {
		if failed {
			uc.recordSecurity(ctx, user.ID, "", "login", "failure", in.IP, in.UserAgent, "")
		}
		return nil, err
	}
	_ = uc.Challenges.Delete(ctx, in.ChallengeID)

	if mfaEnabled {
		challengeID, expires, err := uc.putPasskeyLoginMFAChallenge(ctx, user, in)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			Status: "mfa_required", ChallengeID: challengeID, ChallengeExpires: expires,
			User: uc.publicUser(ctx, user),
		}, nil
	}
	uc.recordSecurity(ctx, user.ID, session.ID, "login", "success", in.IP, in.UserAgent, "")
	if session.EvictedSessions > 0 {
		uc.recordSecurity(ctx, user.ID, session.ID, "session_evict", "success", in.IP, in.UserAgent, "")
	}
	result := &LoginResult{
		Status: "authenticated", User: uc.publicUser(ctx, user), Session: session,
		RawToken: rawToken, RecycledSessions: session.EvictedSessions,
	}
	if cred, cerr := uc.Credentials.Get(ctx, nil, user.ID); cerr == nil && cred != nil {
		result.PasswordChangeRequired = cred.MustChangePassword
		if settings, serr := uc.Settings.GetAuth(ctx, nil); serr == nil {
			result.PasswordChangeRequired = result.PasswordChangeRequired ||
				PasswordExpired(cred.ChangedAt, settings.PasswordPolicy(), uc.Clock.Now())
		}
	}
	return result, nil
}

// putPasskeyLoginMFAChallenge keeps the shared /auth/mfa/complete contract:
// an account that still has TOTP enabled must present it after the passkey.
// Passkeys are not offered as the second factor here because one was just
// used as the first.
func (uc *AuthUsecase) putPasskeyLoginMFAChallenge(ctx context.Context, user *User, in PasskeyLoginInput) (string, time.Time, error) {
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(passkeyLoginChallengeTTL)
	payload, _ := jsonx.Marshal(map[string]any{
		"identity_version": user.IdentityVersion, "ip": in.IP,
		"ua": SummizeAgent(in.UserAgent), "remember": in.Remember,
		"app_id": "", "webauthn_challenge": "",
	})
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: "mfa", Payload: string(payload), UserID: user.ID, ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, ErrDependency
	}
	return id, expires, nil
}
