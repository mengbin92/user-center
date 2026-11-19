package biz

import (
	"context"
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
// enabled, or owns a passkey. Discoverable credentials keep account-specific
// credential IDs out of the public reply.
const (
	PasskeyLoginPurpose = "webauthn_login"

	passkeyLoginChallengeTTL = 5 * time.Minute
	passkeyLoginIPLimit      = 30
	passkeyLoginIPWindow     = 5 * time.Minute
)

type PasskeyLoginChallenge struct {
	ChallengeID string
	Challenge   string
	RPID        string
	ExpiresAt   time.Time
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
	if uc.WebAuthn == nil {
		return nil, ErrDependency
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
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}
	var userID int64
	var version uint64
	if user != nil && user.Status == UserStatusEnabled {
		userID, version = user.ID, user.IdentityVersion
	}
	id, raw, expires, err := uc.putPasskeyLoginChallenge(ctx, userID, version, rpID, origin)
	if err != nil {
		return nil, ErrDependency
	}
	return &PasskeyLoginChallenge{
		ChallengeID: id, Challenge: raw, RPID: rpID, ExpiresAt: expires,
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
		_ = uc.Challenges.Delete(ctx, PasskeyLoginPurpose, in.ChallengeID)
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
		if err := uc.lockUserGeneration(ctx, tx, user.ID, user.IdentityVersion); err != nil {
			if errors.Is(err, ErrSessionRevoked) {
				return ErrChallengeInvalid
			}
			return err
		}
		if err := uc.Flows.Complete(ctx, tx, in.ChallengeID, PasskeyLoginPurpose, user.ID, "session"); err != nil {
			return err
		}
		if err := uc.verifyWebAuthnAssertion(ctx, tx, user.ID, payload.Challenge, in.Assertion, now, true); err != nil {
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
			err = uc.webAuthnAssertionError(ctx, ActorContext{
				User: user, IP: in.IP, UserAgent: in.UserAgent,
			}, err)
		}
		return nil, err
	}
	_ = uc.Challenges.Delete(ctx, PasskeyLoginPurpose, in.ChallengeID)

	if mfaEnabled {
		// Only TOTP and recovery codes are eligible after a passkey was used
		// as the primary factor.
		return uc.newLoginMFAChallenge(ctx, user, LoginInput{IP: in.IP, UserAgent: in.UserAgent, Remember: in.Remember}, ApplicationCode, nil)
	}
	uc.recordSecurity(ctx, user.ID, session.ID, "login", "success", in.IP, in.UserAgent, "")
	if session.EvictedSessions > 0 {
		uc.recordSecurity(ctx, user.ID, session.ID, "session_evict", "success", in.IP, in.UserAgent, "")
	}
	result := &LoginResult{
		Status: "authenticated", User: uc.publicUser(ctx, user), Session: session,
		RawToken: rawToken, Remember: in.Remember, RecycledSessions: session.EvictedSessions,
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
