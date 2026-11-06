package biz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type RegisterInput struct {
	Username     string
	Email        string
	Password     string
	Code         string
	ChallengeID  string
	TermsVersion string
}

type LoginInput struct {
	Username  string
	Password  string
	Remember  bool
	IP        string
	UserAgent string
}

type LoginResult struct {
	Status                 string
	ChallengeID            string
	ChallengeExpires       time.Time
	User                   *User
	Session                *Session
	RawToken               string
	PasswordChangeRequired bool
	// RecycledSessions is how many older sessions the per-user cap reclaimed
	// while issuing this one. Non-zero means another device was signed out.
	RecycledSessions int
	// Present when a passkey can satisfy this MFA challenge.
	WebAuthnChallenge     string
	WebAuthnRPID          string
	WebAuthnCredentialIDs []string
}

func (uc *AuthUsecase) AuthConfig(ctx context.Context) (*AuthSettings, error) {
	s, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	return s, nil
}

func (uc *AuthUsecase) CreateRegistrationChallenge(ctx context.Context, email, ip string) (string, time.Time, error) {
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return "", time.Time{}, ErrDependency
	}
	if !settings.RegistrationEnabled {
		return "", time.Time{}, Validation("当前未开放注册")
	}
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return "", time.Time{}, err
	}
	if !emailDomainAllowed(email, settings.AllowedEmailDomains) {
		return "", time.Time{}, Validation("该邮箱域名不允许注册")
	}
	if ok, err := uc.Limiter.Allow(ctx, "reg:"+ip, 10, time.Hour); err != nil {
		return "", time.Time{}, ErrDependency
	} else if !ok {
		return "", time.Time{}, ErrRateLimited
	}
	code, err := GenerateCode()
	if err != nil {
		return "", time.Time{}, ErrDependency
	}
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(uc.ChallengeTTL)
	if err := uc.Challenges.Put(ctx, Challenge{
		ID:        id,
		Purpose:   "registration",
		CodeHash:  HMACCode(uc.CodeSecret, "registration", code),
		Email:     email,
		ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, ErrDependency
	}
	if err := uc.Mail.Send(ctx, email, "用户中心注册验证码", fmt.Sprintf("你的注册验证码是 %s，%d 分钟内有效。如非本人操作请忽略。", code, int(uc.ChallengeTTL.Minutes()))); err != nil {
		return "", time.Time{}, ErrDependency
	}
	return id, expires, nil
}

func (uc *AuthUsecase) Register(ctx context.Context, in RegisterInput) (*User, error) {
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	if !settings.RegistrationEnabled {
		return nil, Validation("当前未开放注册")
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = NormalizeEmail(in.Email)
	if err := ValidateUsername(in.Username); err != nil {
		return nil, err
	}
	if UsernameReserved(in.Username) {
		return nil, Validation("该用户名为系统保留字")
	}
	if err := ValidateEmail(in.Email); err != nil {
		return nil, err
	}
	if !emailDomainAllowed(in.Email, settings.AllowedEmailDomains) {
		return nil, Validation("该邮箱域名不允许注册")
	}
	if err := ValidatePassword(in.Password, settings.PasswordPolicy()); err != nil {
		return nil, err
	}
	if in.TermsVersion == "" {
		return nil, Validation("必须同意服务条款")
	}
	if ok, err := uc.Limiter.Allow(ctx, "register:"+in.Email, 10, time.Hour); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}

	var challenge *Challenge
	if settings.EmailVerificationRequired {
		if in.ChallengeID == "" || in.Code == "" {
			return nil, ErrChallengeInvalid
		}
		c, err := uc.Challenges.Verify(ctx, "registration", in.ChallengeID, in.Code)
		if err != nil {
			return nil, err
		}
		if c.Email != in.Email {
			return nil, ErrChallengeInvalid
		}
		challenge = &c
	}

	if _, err := uc.Users.GetByUsername(ctx, nil, NormalizeUsername(in.Username)); err == nil {
		return nil, ErrUsernameExists
	} else if !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}
	if _, err := uc.Users.GetByEmail(ctx, nil, in.Email); err == nil {
		// Do not reveal whether an address is registered.
		return nil, ErrChallengeInvalid
	} else if !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}

	hash, err := HashPassword(in.Password)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now().UTC()
	user := &User{
		Username:           in.Username,
		UsernameNormalized: NormalizeUsername(in.Username),
		DisplayName:        in.Username,
		Email:              in.Email,
		EmailNormalized:    in.Email,
		EmailVerified:      settings.EmailVerificationRequired,
		Status:             UserStatusEnabled,
		Revision:           1,
		IdentityVersion:    1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if !settings.EmailVerificationRequired {
		user.EmailVerified = false
	}

	var created *User
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		u, err := uc.Users.Create(ctx, tx, user)
		if err != nil {
			return err
		}
		created = u
		if err := uc.Credentials.Create(ctx, tx, &Credential{
			UserID:          u.ID,
			PasswordHash:    hash,
			Algorithm:       "bcrypt",
			PasswordVersion: 1,
			ChangedAt:       now,
			Revision:        1,
			UpdatedAt:       now,
		}); err != nil {
			return err
		}
		// Seed the history with the first password so "reuse the last N" is
		// meaningful from the very first change, not only after one rotation.
		if err := uc.RecordPasswordHistory(ctx, tx, u.ID, hash, settings.PasswordPolicy()); err != nil {
			return ErrDependency
		}
		member, err := uc.IAM.GetRoleByCode(ctx, tx, "member")
		if err != nil {
			return fmt.Errorf("default member role missing: %w", err)
		}
		if _, err := uc.IAM.CreateAssignment(ctx, tx, &Assignment{
			UserID: u.ID, RoleID: member.ID,
			Boundary: authorization.Scope{All: true},
			StartsAt: now, Origin: OriginDefault, Revision: 1,
			CreatedAt: now,
		}); err != nil {
			return err
		}
		if challenge != nil {
			if err := uc.Flows.Complete(ctx, tx, challenge.ID, "registration", u.ID, "user"); err != nil {
				return err
			}
		}
		if err := uc.audit(ctx, tx, ActorContext{}, "account.register", itoa(u.ID), "{}", "{}", "{}", "self registration", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": u.ID, "username": u.Username, "created_at": now})
		if err := uc.emit(ctx, tx, "user", u.ID, u.Revision, "user.created", string(payload)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if challenge != nil {
		_ = uc.Challenges.Delete(ctx, challenge.ID)
	}
	return created, nil
}

func (uc *AuthUsecase) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	return uc.login(ctx, in, ApplicationCode)
}

// LoginForApplication issues a session bound to the calling integration
// application. It shares the HTTP login path (rate limits, failure counters,
// MFA challenge semantics) so gRPC cannot be used to bypass them.
func (uc *AuthUsecase) LoginForApplication(ctx context.Context, in LoginInput, appID string) (*LoginResult, error) {
	return uc.login(ctx, in, appID)
}

func (uc *AuthUsecase) login(ctx context.Context, in LoginInput, appID string) (*LoginResult, error) {
	if ok, err := uc.Limiter.Allow(ctx, "login:"+in.IP, 30, 5*time.Minute); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}
	identifier := strings.TrimSpace(in.Username)
	var user *User
	var err error
	if strings.Contains(identifier, "@") {
		user, err = uc.Users.GetByEmail(ctx, nil, NormalizeEmail(identifier))
	} else {
		user, err = uc.Users.GetByUsername(ctx, nil, NormalizeUsername(identifier))
	}
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return nil, ErrDependency
		}
		uc.recordSecurity(ctx, 0, "", "login", "failure", in.IP, in.UserAgent, "")
		return nil, ErrInvalidCredentials
	}
	if ok, err := uc.Limiter.Allow(ctx, fmt.Sprintf("login-user:%d", user.ID), uc.MaxLoginAttempts, 5*time.Minute); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}
	cred, err := uc.Credentials.Get(ctx, nil, user.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	if err != nil || cred.PasswordHash == "" || !VerifyPassword(cred.PasswordHash, in.Password) {
		uc.recordSecurity(ctx, user.ID, "", "login", "failure", in.IP, in.UserAgent, "")
		return nil, ErrInvalidCredentials
	}
	if user.Status != UserStatusEnabled {
		uc.recordSecurity(ctx, user.ID, "", "login", "denied", in.IP, in.UserAgent, "")
		return nil, ErrUnauthenticated
	}
	mfa, err := uc.MFA.Get(ctx, nil, user.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	var webAuthnCreds []*WebAuthnCredential
	if uc.WebAuthn != nil {
		var werr error
		webAuthnCreds, werr = uc.WebAuthn.ListByUser(ctx, nil, user.ID)
		if werr != nil {
			return nil, ErrDependency
		}
	}
	if (mfa != nil && mfa.Enabled()) || len(webAuthnCreds) > 0 {
		challengeID := uc.IDs.NewID()
		expires := uc.Clock.Now().Add(5 * time.Minute)
		challengeApp := ""
		if appID != ApplicationCode {
			challengeApp = appID
		}
		waChallenge := ""
		rpID := ""
		allow := []string{}
		if len(webAuthnCreds) > 0 {
			var err error
			waChallenge, err = newToken(32)
			if err != nil {
				return nil, ErrDependency
			}
			rpID, _, err = uc.webAuthnRP()
			if err != nil {
				return nil, err
			}
			for _, cred := range webAuthnCreds {
				allow = append(allow, cred.CredentialID)
			}
		}
		payload, _ := jsonx.Marshal(map[string]any{
			"identity_version": user.IdentityVersion, "ip": in.IP,
			"ua": SummizeAgent(in.UserAgent), "remember": in.Remember,
			"app_id": challengeApp, "webauthn_challenge": waChallenge,
		})
		if err := uc.Challenges.Put(ctx, Challenge{ID: challengeID, Purpose: "mfa", Payload: string(payload), UserID: user.ID, ExpiresAt: expires}); err != nil {
			return nil, ErrDependency
		}
		return &LoginResult{
			Status: "mfa_required", ChallengeID: challengeID, ChallengeExpires: expires,
			User: uc.publicUser(ctx, user), WebAuthnChallenge: waChallenge,
			WebAuthnRPID: rpID, WebAuthnCredentialIDs: allow,
		}, nil
	}

	session, raw, err := uc.issueSessionFor(ctx, user, in.UserAgent, in.IP, appID)
	if err != nil {
		return nil, err
	}
	// Report expiry in the login reply so the UI can route straight to the
	// change-password screen. ValidateSession enforces the same rule on every
	// later request, so this is a UX hint, not the only guard.
	changeRequired := cred.MustChangePassword
	if settings, serr := uc.Settings.GetAuth(ctx, nil); serr == nil {
		changeRequired = changeRequired || PasswordExpired(cred.ChangedAt, settings.PasswordPolicy(), uc.Clock.Now())
	}
	if session.EvictedSessions > 0 {
		uc.recordSecurity(ctx, user.ID, session.ID, "session_evict", "success", in.IP, in.UserAgent, "")
	}
	return &LoginResult{
		Status: "authenticated", User: uc.publicUser(ctx, user), Session: session,
		RawToken: raw, PasswordChangeRequired: changeRequired,
		RecycledSessions: session.EvictedSessions,
	}, nil
}

func (uc *AuthUsecase) CompleteMFA(ctx context.Context, challengeID, code, ip, ua string) (*LoginResult, error) {
	return uc.completeMFA(ctx, challengeID, code, ip, ua, ApplicationCode, false, nil)
}

// CompleteMFAWithWebAuthn satisfies a login MFA challenge with a passkey
// assertion instead of a TOTP/recovery code.
func (uc *AuthUsecase) CompleteMFAWithWebAuthn(ctx context.Context, assertion WebAuthnAssertion, ip, ua string) (*LoginResult, error) {
	return uc.completeMFA(ctx, assertion.ChallengeID, "", ip, ua, ApplicationCode, false, &assertion)
}

// CompleteMFAForApplication consumes a gRPC-issued MFA challenge. The challenge
// must have been created for the same application; an HTTP challenge (app_id
// empty) is rejected so the two surfaces cannot be mixed.
func (uc *AuthUsecase) CompleteMFAForApplication(ctx context.Context, challengeID, code, ip, ua, appID string) (*LoginResult, error) {
	return uc.completeMFA(ctx, challengeID, code, ip, ua, appID, true, nil)
}

func (uc *AuthUsecase) completeMFA(ctx context.Context, challengeID, code, ip, ua, appID string, requireApp bool, assertion *WebAuthnAssertion) (*LoginResult, error) {
	if ok, err := uc.Limiter.Allow(ctx, "mfa:"+ip, 20, 5*time.Minute); err != nil {
		return nil, ErrDependency
	} else if !ok {
		return nil, ErrRateLimited
	}
	c, err := uc.Challenges.Get(ctx, "mfa", challengeID)
	if err != nil {
		return nil, ErrChallengeInvalid
	}
	user, err := uc.Users.Get(ctx, nil, c.UserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if user.Status != UserStatusEnabled {
		return nil, ErrUnauthenticated
	}
	var payload struct {
		IdentityVersion   uint64 `json:"identity_version"`
		IP                string `json:"ip"`
		UA                string `json:"ua"`
		Remember          bool   `json:"remember"`
		AppID             string `json:"app_id"`
		WebAuthnChallenge string `json:"webauthn_challenge"`
	}
	if err := jsonx.Unmarshal([]byte(c.Payload), &payload); err != nil || payload.IdentityVersion != user.IdentityVersion {
		return nil, ErrChallengeInvalid
	}
	if requireApp && (payload.AppID == "" || payload.AppID != appID) {
		return nil, ErrChallengeInvalid
	}
	if !requireApp {
		if payload.AppID != "" {
			return nil, ErrChallengeInvalid // an integration challenge is not redeemable over HTTP
		}
		appID = ApplicationCode
	} else {
		appID = payload.AppID
	}
	if assertion != nil && (requireApp || payload.WebAuthnChallenge == "") {
		return nil, ErrChallengeInvalid
	}
	if assertion == nil {
		if err := uc.verifyMFA(ctx, user.ID, code); err != nil {
			uc.recordSecurity(ctx, user.ID, "", "mfa", "failure", ip, ua, "")
			return nil, err
		}
	}
	if payload.IP == "" {
		payload.IP = ip
	}
	if payload.UA == "" {
		payload.UA = ua
	}
	cred, err := uc.Credentials.Get(ctx, nil, user.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	var session *Session
	var raw string
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Flows.Complete(ctx, tx, challengeID, "mfa", user.ID, "session"); err != nil {
			return err
		}
		if assertion != nil {
			factorActor := ActorContext{User: user, Session: &Session{ID: "login", UserID: user.ID}}
			if err := uc.verifyWebAuthnAssertion(ctx, tx, factorActor, payload.WebAuthnChallenge, *assertion, uc.Clock.Now().UTC()); err != nil {
				uc.recordSecurity(ctx, user.ID, "", "mfa", "failure", ip, ua, "")
				return err
			}
		}
		var err error
		session, raw, err = uc.issueSessionTxFor(ctx, tx, user, payload.UA, payload.IP, appID)
		return err
	})
	if err != nil {
		return nil, err
	}
	uc.recordSecurity(ctx, user.ID, session.ID, "login", "success", payload.IP, payload.UA, "")
	_ = uc.Challenges.Delete(ctx, challengeID)
	result := &LoginResult{
		Status: "authenticated", User: uc.publicUser(ctx, user), Session: session, RawToken: raw,
		RecycledSessions: session.EvictedSessions,
	}
	if cred != nil {
		result.PasswordChangeRequired = cred.MustChangePassword
		if settings, serr := uc.Settings.GetAuth(ctx, nil); serr == nil {
			result.PasswordChangeRequired = result.PasswordChangeRequired || PasswordExpired(cred.ChangedAt, settings.PasswordPolicy(), uc.Clock.Now())
		}
	}
	return result, nil
}

func (uc *AuthUsecase) issueSession(ctx context.Context, user *User, ua, ip string) (*Session, string, error) {
	return uc.issueSessionTx(ctx, nil, user, ua, ip)
}

func (uc *AuthUsecase) issueSessionFor(ctx context.Context, user *User, ua, ip, appID string) (*Session, string, error) {
	return uc.issueSessionTxFor(ctx, nil, user, ua, ip, appID)
}

func (uc *AuthUsecase) issueSessionTx(ctx context.Context, tx Tx, user *User, ua, ip string) (*Session, string, error) {
	return uc.issueSessionTxFor(ctx, tx, user, ua, ip, ApplicationCode)
}

func (uc *AuthUsecase) issueSessionTxFor(ctx context.Context, tx Tx, user *User, ua, ip, appID string) (*Session, string, error) {
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, "", ErrDependency
	}
	raw, hash, err := GenerateSessionToken()
	if err != nil {
		return nil, "", ErrDependency
	}
	now := uc.Clock.Now().UTC()
	ttl := uc.SessionTTL
	if settings.SessionTTLMinutes > 0 {
		ttl = time.Duration(settings.SessionTTLMinutes) * time.Minute
	}
	idle := uc.IdleTimeout
	if settings.IdleTimeoutMinutes > 0 {
		idle = time.Duration(settings.IdleTimeoutMinutes) * time.Minute
	}
	activeRoles, err := uc.activeRoleSubset(ctx, user.ID)
	if err != nil {
		return nil, "", err
	}
	evicted := 0
	if settings.MaxSessionsPerUser > 0 {
		evicted, err = uc.evictExcessSessions(ctx, tx, user.ID, settings.MaxSessionsPerUser, now)
		if err != nil {
			return nil, "", ErrDependency
		}
	}
	s := &Session{
		ID:              uc.IDs.NewID(),
		UserID:          user.ID,
		ApplicationCode: appID,
		TokenHash:       hash,
		UserAgent:       SummizeAgent(ua),
		IPMasked:        MaskIP(ip),
		IssuedAt:        now,
		LastSeenAt:      now,
		ExpiresAt:       now.Add(ttl),
		IdleExpiresAt:   now.Add(idle),
		IdentityVersion: user.IdentityVersion,
		Revision:        1,
		ActiveRoleIDs:   activeRoles,
		EvictedSessions: evicted,
	}
	if err := uc.Sessions.Create(ctx, tx, s); err != nil {
		return nil, "", ErrDependency
	}
	if tx == nil {
		uc.recordSecurity(ctx, user.ID, s.ID, "login", "success", ip, ua, "")
	}
	return s, raw, nil
}

// evictExcessSessions keeps at most limit live sessions per user by revoking
// the least recently used ones before the new session is inserted. Revocation
// is server-side (revoked_at), so the evicted device gets a 401 on its next
// request rather than merely disappearing from a list.
func (uc *AuthUsecase) evictExcessSessions(ctx context.Context, tx Tx, userID int64, limit int, now time.Time) (int, error) {
	rows, err := uc.Sessions.ListByUser(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	live := make([]*Session, 0, len(rows))
	for _, s := range rows {
		if s.Valid(now) {
			live = append(live, s)
		}
	}
	// +1 accounts for the session about to be created.
	excess := len(live) + 1 - limit
	if excess <= 0 {
		return 0, nil
	}
	if excess > len(live) {
		excess = len(live)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].LastSeenAt.Before(live[j].LastSeenAt) })
	for i := 0; i < excess; i++ {
		if err := uc.Sessions.Revoke(ctx, tx, live[i].ID, &now); err != nil {
			return 0, err
		}
		_ = uc.StepUp.Delete(ctx, StepUpKey(live[i]))
	}
	return excess, nil
}

func (uc *AuthUsecase) activeRoleSubset(ctx context.Context, userID int64) ([]int64, error) {
	assignments, err := uc.IAM.ListAssignmentsForUser(ctx, nil, userID)
	if err != nil {
		return nil, err
	}
	constraints, err := uc.IAM.ListConstraints(ctx, nil)
	if err != nil {
		return nil, err
	}
	roles, err := uc.IAM.ListRoles(ctx, nil, RoleFilter{})
	if err != nil {
		return nil, err
	}
	byID := map[int64]*Role{}
	for _, r := range roles {
		byID[r.ID] = r
	}
	now := uc.Clock.Now()
	var out []int64
	for _, a := range assignments {
		if !a.Active(now) {
			continue
		}
		if r := byID[a.RoleID]; r == nil || r.Status != RoleStatusActive {
			continue
		}
		candidate := append(append([]int64{}, out...), a.RoleID)
		if CheckConstraints(candidate, constraints) != nil {
			continue
		}
		out = append(out, a.RoleID)
	}
	return out, nil
}

func (uc *AuthUsecase) Logout(ctx context.Context, actor ActorContext) error {
	if actor.Session == nil {
		return nil
	}
	now := uc.Clock.Now().UTC()
	if err := uc.Sessions.Revoke(ctx, nil, actor.Session.ID, &now); err != nil {
		return ErrDependency
	}
	_ = uc.StepUp.Delete(ctx, StepUpKey(actor.Session))
	return nil
}

func (uc *AuthUsecase) CreatePasswordResetChallenge(ctx context.Context, identifier, ip string) (string, time.Time, error) {
	if ok, err := uc.Limiter.Allow(ctx, "reset:"+ip, 10, time.Hour); err != nil {
		return "", time.Time{}, ErrDependency
	} else if !ok {
		return "", time.Time{}, ErrRateLimited
	}
	identifier = strings.TrimSpace(identifier)
	var user *User
	var err error
	if strings.Contains(identifier, "@") {
		user, err = uc.Users.GetByEmail(ctx, nil, NormalizeEmail(identifier))
	} else {
		user, err = uc.Users.GetByUsername(ctx, nil, NormalizeUsername(identifier))
	}
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return "", time.Time{}, ErrDependency
	}
	// Always return a challenge-shaped response to avoid account enumeration.
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(uc.ResetTTL)
	if err != nil || user == nil || user.Status == UserStatusArchived || user.Email == "" {
		return id, expires, nil
	}
	code, err := GenerateCode()
	if err != nil {
		return "", time.Time{}, ErrDependency
	}
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: "password_reset",
		CodeHash: HMACCode(uc.CodeSecret, "password_reset", code),
		UserID:   user.ID, Email: user.Email, ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, ErrDependency
	}
	_ = uc.Mail.Send(ctx, user.Email, "用户中心密码重置验证码", fmt.Sprintf("你的密码重置验证码是 %s，%d 分钟内有效。如非本人操作请忽略。", code, int(uc.ResetTTL.Minutes())))
	return id, expires, nil
}

func (uc *AuthUsecase) ResetPassword(ctx context.Context, challengeID, code, newPassword string) error {
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return ErrDependency
	}
	policy := settings.PasswordPolicy()
	if err := ValidatePassword(newPassword, policy); err != nil {
		return err
	}
	challenge, err := uc.Challenges.Verify(ctx, "password_reset", challengeID, code)
	if err != nil {
		return err
	}
	user, err := uc.Users.Get(ctx, nil, challenge.UserID)
	if err != nil {
		return ErrChallengeInvalid
	}
	// Reuse is checked before the challenge is consumed: a rejected password
	// must not burn the one-time code, otherwise the user has to wait for a new
	// email just because they repeated an old password.
	if current, cerr := uc.Credentials.Get(ctx, nil, user.ID); cerr == nil {
		if err := uc.CheckPasswordReuse(ctx, nil, user.ID, newPassword, policy, current); err != nil {
			return err
		}
	} else if !errors.Is(cerr, ErrResourceNotFound) {
		return ErrDependency
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return ErrDependency
	}
	now := uc.Clock.Now().UTC()
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Flows.Complete(ctx, tx, challenge.ID, "password_reset", user.ID, "password_reset"); err != nil {
			return err
		}
		credential, err := uc.Credentials.Get(ctx, tx, user.ID)
		if err != nil {
			return ErrDependency
		}
		version, err := uc.Credentials.UpdatePassword(ctx, tx, user.ID, hash, "bcrypt", credential.Revision, false)
		if err != nil {
			return err
		}
		_ = version
		if err := uc.RecordPasswordHistory(ctx, tx, user.ID, hash, policy); err != nil {
			return ErrDependency
		}
		newVersion, err := uc.Users.BumpIdentityVersion(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		if err := uc.Sessions.RevokeAllForUser(ctx, tx, user.ID, &now); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, ActorContext{}, "credential.password.reset", itoa(user.ID), "{}", "{}", "{}", "self-service password reset", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": user.ID, "identity_version": newVersion})
		return uc.emit(ctx, tx, "user", user.ID, newVersion, "credential.changed", string(payload))
	})
	if err != nil {
		return err
	}
	_ = uc.Challenges.Delete(ctx, challengeID)
	uc.recordSecurity(ctx, user.ID, "", "password_reset", "success", "", "", "")
	return nil
}

func (uc *AuthUsecase) publicUser(ctx context.Context, u *User) *User {
	roles, _ := uc.Users.RolesForUser(ctx, nil, u.ID)
	u.Roles = roles
	return u
}

func emailDomainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range allowed {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}

// MFAEnrollmentRequired reports whether the account must bind a second factor
// before management calls are accepted. Authentication itself is not blocked,
// otherwise a root account could never enroll.
func (uc *AuthUsecase) MFAEnrollmentRequired(ctx context.Context, user *User) bool {
	if user == nil {
		return false
	}
	isAdmin := false
	for _, r := range user.Roles {
		if r.Code == "root" || r.Code == "admin" {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return false
	}
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil || !settings.MFARequiredForAdmins {
		return false
	}
	return !uc.HasSecondFactor(ctx, user.ID)
}
