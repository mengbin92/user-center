package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
	"github.com/mengbin92/user-center/pkg/totp"
)

func (uc *SecurityUsecase) Status(ctx context.Context, actor ActorContext) (mfaEnabled, passwordAvailable bool, remaining int, stepUpUntil time.Time, err error) {
	state, err := uc.MFA.Get(ctx, nil, actor.User.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return false, false, 0, time.Time{}, ErrDependency
	}
	cred, cerr := uc.Credentials.Get(ctx, nil, actor.User.ID)
	passwordAvailable = cerr == nil && cred.PasswordHash != ""
	until := uc.stepUpUntil(ctx, actor)
	if state == nil {
		return false, passwordAvailable, 0, until, nil
	}
	return state.Enabled(), passwordAvailable, len(state.RecoveryHashes), until, nil
}

func (uc *SecurityUsecase) Setup(ctx context.Context, actor ActorContext, currentPassword string) (string, string, time.Time, error) {
	if err := uc.Services.confirmPassword(ctx, actor.User.ID, currentPassword); err != nil {
		return "", "", time.Time{}, err
	}
	existing, err := uc.MFA.Get(ctx, nil, actor.User.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return "", "", time.Time{}, ErrDependency
	}
	if existing != nil && existing.Enabled() {
		return "", "", time.Time{}, Validation("多因素认证已启用")
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	enc, err := uc.Secrets.Encrypt(secret)
	if err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	expires := uc.Clock.Now().Add(10 * time.Minute)
	state := &MFAState{
		UserID:         actor.User.ID,
		PendingSecret:  enc,
		PendingSession: actor.Session.ID,
		PendingUntil:   expires,
		Revision:       1,
	}
	if existing != nil {
		state.Revision = existing.Revision + 1
		state.Secret = existing.Secret
		state.RecoveryHashes = existing.RecoveryHashes
		state.LastStep = existing.LastStep
	}
	if err := uc.MFA.Save(ctx, nil, state); err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	issuer := "User Center"
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(actor.User.Username), secret, url.QueryEscape(issuer))
	return secret, uri, expires, nil
}

func (uc *SecurityUsecase) Confirm(ctx context.Context, actor ActorContext, code string) ([]string, error) {
	state, err := uc.MFA.Get(ctx, nil, actor.User.ID)
	if err != nil || state.PendingSecret == "" {
		return nil, ErrMFAInvalid
	}
	if uc.Clock.Now().After(state.PendingUntil) || state.PendingSession != actor.Session.ID {
		return nil, ErrMFAInvalid
	}
	secret, err := uc.Secrets.Decrypt(state.PendingSecret)
	if err != nil {
		return nil, ErrDependency
	}
	step, ok := totp.Match(secret, code, uc.Clock.Now(), -1)
	if !ok {
		return nil, ErrMFAInvalid
	}
	codes, hashes, err := generateRecoveryCodes()
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now().UTC()
	state.Secret = state.PendingSecret
	state.LastStep = step
	state.RecoveryHashes = hashes
	state.PendingSecret = ""
	state.PendingSession = ""
	state.PendingUntil = time.Time{}
	state.Revision++
	state.Failures = 0
	state.LockedUntil = time.Time{}

	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.MFA.Save(ctx, tx, state); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "credential.mfa.enable", itoa(actor.User.ID), "{}", "{}", "{}", "self-service MFA enrollment", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": actor.User.ID, "mfa_enabled": true, "at": now})
		return uc.emit(ctx, tx, "user", actor.User.ID, actor.User.Revision, "credential.changed", string(payload))
	})
	if err != nil {
		return nil, err
	}
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "mfa_enable", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return codes, nil
}

func (uc *SecurityUsecase) Disable(ctx context.Context, actor ActorContext, password, code string) error {
	if err := uc.Services.confirmPassword(ctx, actor.User.ID, password); err != nil {
		return err
	}
	if err := uc.verifyMFA(ctx, actor.User.ID, code); err != nil {
		return err
	}
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.MFA.Delete(ctx, tx, actor.User.ID); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "credential.mfa.disable", itoa(actor.User.ID), "{}", "{}", "{}", "self-service MFA disable", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": actor.User.ID, "mfa_enabled": false})
		return uc.emit(ctx, tx, "user", actor.User.ID, actor.User.Revision, "credential.changed", string(payload))
	})
	if err != nil {
		return err
	}
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "mfa_disable", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return nil
}

func (uc *SecurityUsecase) RotateRecoveryCodes(ctx context.Context, actor ActorContext, password, code string) ([]string, error) {
	if err := uc.Services.confirmPassword(ctx, actor.User.ID, password); err != nil {
		return nil, err
	}
	if err := uc.verifyMFA(ctx, actor.User.ID, code); err != nil {
		return nil, err
	}
	codes, hashes, err := generateRecoveryCodes()
	if err != nil {
		return nil, ErrDependency
	}
	state, err := uc.MFA.Get(ctx, nil, actor.User.ID)
	if err != nil || !state.Enabled() {
		return nil, ErrMFADisabled
	}
	state.RecoveryHashes = hashes
	state.Revision++
	if err := uc.MFA.Save(ctx, nil, state); err != nil {
		return nil, ErrDependency
	}
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "mfa_recovery_rotate", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return codes, nil
}

func (uc *SecurityUsecase) Verify(ctx context.Context, actor ActorContext, password, code string) (time.Time, error) {
	if err := uc.Services.confirmPassword(ctx, actor.User.ID, password); err != nil {
		return time.Time{}, err
	}
	if err := uc.verifyMFA(ctx, actor.User.ID, code); err != nil {
		return time.Time{}, err
	}
	until := uc.Clock.Now().Add(uc.StepUpTTL)
	if err := uc.StepUp.Put(ctx, actor.Session.ID, until); err != nil {
		return time.Time{}, ErrDependency
	}
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "step_up", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return until, nil
}

// verifyMFA accepts a TOTP code or a single recovery code. It enforces the
// per-user failure lockout and persists the consumed TOTP step.
func (uc *SecurityUsecase) verifyMFA(ctx context.Context, userID int64, code string) error {
	state, err := uc.MFA.Get(ctx, nil, userID)
	if err != nil || !state.Enabled() {
		return ErrMFADisabled
	}
	now := uc.Clock.Now()
	if !state.LockedUntil.IsZero() && now.Before(state.LockedUntil) {
		return ErrMFALocked
	}
	secret, err := uc.Secrets.Decrypt(state.Secret)
	if err != nil {
		return ErrDependency
	}
	if step, ok := totp.Match(secret, code, now, state.LastStep); ok {
		state.LastStep = step
		state.Failures = 0
		state.LockedUntil = time.Time{}
		state.Revision++
		if err := uc.MFA.Save(ctx, nil, state); err != nil {
			return ErrDependency
		}
		return nil
	}
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(normalized))
	hash := hex.EncodeToString(sum[:])
	for i, h := range state.RecoveryHashes {
		if h == hash {
			state.RecoveryHashes = append(append([]string{}, state.RecoveryHashes[:i]...), state.RecoveryHashes[i+1:]...)
			state.Failures = 0
			state.Revision++
			if err := uc.MFA.Save(ctx, nil, state); err != nil {
				return ErrDependency
			}
			return nil
		}
	}
	state.Failures++
	if state.Failures >= 5 {
		state.LockedUntil = now.Add(5 * time.Minute)
		state.Failures = 0
	}
	state.Revision++
	_ = uc.MFA.Save(ctx, nil, state)
	if !state.LockedUntil.IsZero() {
		return ErrMFALocked
	}
	return ErrMFAInvalid
}

// LoginMFA verifies a second factor during the login challenge flow.
func (uc *AuthUsecase) verifyMFA(ctx context.Context, userID int64, code string) error {
	return (&SecurityUsecase{Services: uc.Services}).verifyMFA(ctx, userID, code)
}

func generateRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 0, 8)
	hashes := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		raw, err := newToken(6)
		if err != nil {
			return nil, nil, err
		}
		normalized := strings.ToUpper(raw)[:8]
		code := normalized[:4] + "-" + normalized[4:]
		sum := sha256.Sum256([]byte(normalized))
		codes = append(codes, code)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	return codes, hashes, nil
}

// AuthConfig exposes the effective authentication policy to security views.
func (uc *SecurityUsecase) AuthConfig(ctx context.Context) (*AuthSettings, error) {
	s, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	return s, nil
}
