package biz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mengbin92/user-center/domain/authorization"
	"golang.org/x/crypto/bcrypt"
)

// ActorContext is the verified transport identity handed to every usecase.
type ActorContext struct {
	User                   *User
	Session                *Session
	Actor                  authorization.Actor
	RequestID              string
	IP                     string
	UserAgent              string
	PasswordChangeRequired bool
	ExpectedTargetRevision uint64
	ExpectedPolicyRevision uint64
}

type actorKey struct{}

func WithActor(ctx context.Context, a ActorContext) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

func ActorFromContext(ctx context.Context) (ActorContext, bool) {
	a, ok := ctx.Value(actorKey{}).(ActorContext)
	return a, ok
}

func RequireActor(ctx context.Context) (ActorContext, error) {
	a, ok := ActorFromContext(ctx)
	if !ok || a.User == nil || a.Session == nil {
		return ActorContext{}, ErrUnauthenticated
	}
	return a, nil
}

// RequestIDFromContext is populated by the HTTP middleware.
type requestIDKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey{}).(string)
	return v
}

func uitoa(v uint64) string { return strconv.FormatUint(v, 10) }
func itoa(v int64) string   { return strconv.FormatInt(v, 10) }

func ParseID(raw, field string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, Validation(field + " 不能为空")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, Validation(field + " 不合法")
	}
	return id, nil
}

func ParseRevision(raw, field string) (uint64, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, Validation(field + " 不能为空")
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		return 0, Validation(field + " 不合法")
	}
	return n, nil
}

func ParseTime(raw, field string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, Validation(field + " 必须是 RFC3339 时间")
	}
	return t.UTC(), nil
}

// Session token and CSRF helpers.

func newToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func GenerateSessionToken() (string, string, error) {
	raw, err := newToken(32)
	if err != nil {
		return "", "", err
	}
	return raw, HashToken(raw), nil
}

func GenerateCode() (string, error) {
	// Six decimal digits with uniform distribution.
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

func HMACCode(secret, purpose, code string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// Password policy and hashing.

// Password classes used by composition rules. A class counts once however many
// times it appears; spaces and non-ASCII letters are not classes, so a
// passphrase of words still needs punctuation or a digit to reach three.
const (
	passwordClassUpper = 1 << iota
	passwordClassLower
	passwordClassDigit
	passwordClassSymbol
)

// passwordClasses returns which of the four classes appear in pw.
func passwordClasses(pw string) int {
	var mask int
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			mask |= passwordClassUpper
		case r >= 'a' && r <= 'z':
			mask |= passwordClassLower
		case r >= '0' && r <= '9':
			mask |= passwordClassDigit
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			// Non-ASCII letters and digits carry no class of their own: forcing
			// "must contain uppercase" on a Chinese password is not meaningful.
			// They still count toward length.
		case unicode.IsSpace(r):
			// Whitespace is neither a symbol nor a class.
		default:
			mask |= passwordClassSymbol
		}
	}
	return bits.OnesCount(uint(mask))
}

// ValidatePassword is the single password-policy gate. Register, self-service
// change, reset-by-code and admin-issued initial passwords all call it, so the
// rules cannot drift apart between entry points.
//
// Violations return PASSWORD_POLICY_VIOLATION rather than VALIDATION_FAILED:
// the UI needs to show the concrete reason next to the field, and a generic
// "request invalid" makes the strongest requirement invisible.
func ValidatePassword(pw string, policy PasswordPolicy) error {
	minLen := policy.MinLength
	if minLen < 8 {
		minLen = 8
	}
	if utf8.RuneCountInString(pw) < minLen {
		return PasswordPolicyError(fmt.Sprintf("密码至少需要 %d 个字符", minLen))
	}
	if len(pw) > 72 {
		return PasswordPolicyError("密码不能超过 72 个字节")
	}
	if strings.TrimSpace(pw) != pw {
		return PasswordPolicyError("密码首尾不能包含空白字符")
	}
	if classes := policy.MinClasses; classes > 0 {
		if classes > 4 {
			classes = 4
		}
		if got := passwordClasses(pw); got < classes {
			return PasswordPolicyError(fmt.Sprintf(
				"密码需至少包含 %d 类字符（大写字母、小写字母、数字、符号），当前只有 %d 类", classes, got))
		}
	}
	return nil
}

// PasswordExpired reports whether a password set at changedAt has outlived the
// policy. A zero changedAt means the age is unknown (accounts that predate the
// policy): those are never treated as expired, and are stamped on next change.
func PasswordExpired(changedAt time.Time, policy PasswordPolicy, now time.Time) bool {
	if policy.ExpiryDays <= 0 || changedAt.IsZero() {
		return false
	}
	return now.After(changedAt.AddDate(0, 0, policy.ExpiryDays))
}

// credentialRestricted answers the one question every credential entry point
// has to ask: "is this account allowed to act normally, or must it set a new
// password first".
//
// It exists so the answer cannot differ by protocol. The browser gate lives in
// ValidateSession (which turns it into ActorContext.PasswordChangeRequired),
// and the OIDC and internal gRPC surfaces call this helper. Before that split,
// `MustChangePassword` was checked in three places and expiry in only two, so a
// refresh token kept minting new tokens for an expired password.
//
// Expiry and "must change" collapse into the same gate on purpose: both mean
// "this credential has to be replaced", and having two flags would mean two
// enforcement paths that inevitably drift.
func (s *Services) credentialRestricted(ctx context.Context, tx Tx, credential *Credential) (bool, error) {
	if credential == nil {
		return false, nil
	}
	if credential.MustChangePassword {
		return true, nil
	}
	settings, err := s.Settings.GetAuth(ctx, tx)
	if err != nil {
		return false, ErrDependency
	}
	return PasswordExpired(credential.ChangedAt, settings.PasswordPolicy(), s.Clock.Now()), nil
}

// CheckPasswordReuse rejects a candidate that matches the account's current
// password or anything inside the history window. current may be nil when the
// account has no password yet (OAuth-only accounts).
//
// Only bcrypt comparisons happen here; the stored values are hashes, so a
// database dump does not expose previous passwords.
func (s *Services) CheckPasswordReuse(ctx context.Context, tx Tx, userID int64, candidate string, policy PasswordPolicy, current *Credential) error {
	if policy.HistoryCount <= 0 {
		return nil
	}
	if current != nil && current.PasswordHash != "" && VerifyPassword(current.PasswordHash, candidate) {
		return PasswordPolicyError("新密码不能与当前密码相同")
	}
	hashes, err := s.Credentials.RecentPasswordHashes(ctx, tx, userID, policy.HistoryCount)
	if err != nil {
		return ErrDependency
	}
	for _, h := range hashes {
		if VerifyPassword(h, candidate) {
			return PasswordPolicyError(fmt.Sprintf("新密码不能与最近 %d 次使用过的密码相同", policy.HistoryCount))
		}
	}
	return nil
}

// RecordPasswordHistory appends the newly set hash so the next change can
// detect reuse. Callers must invoke it inside the same transaction that writes
// the credential: a history row without the matching credential (or the
// reverse) would make the reuse rule lie.
func (s *Services) RecordPasswordHistory(ctx context.Context, tx Tx, userID int64, hash string, policy PasswordPolicy) error {
	if policy.HistoryCount <= 0 {
		return nil
	}
	return s.Credentials.RecordPasswordHash(ctx, tx, userID, hash, policy.HistoryCount)
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func VerifyPassword(hash, pw string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func NormalizeUsername(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
func NormalizeEmail(v string) string    { return strings.ToLower(strings.TrimSpace(v)) }

func ValidateUsername(v string) error {
	if len(v) < 3 || len(v) > 128 {
		return Validation("用户名长度必须为 3-128 个字符")
	}
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			continue
		}
		return Validation("用户名只能包含字母、数字、下划线、短横线和点")
	}
	return nil
}

// ValidateEmail performs pragmatic syntax validation; deliverability is
// proven by the verification challenge, not by a regex.
func ValidateEmail(v string) error {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 254 {
		return Validation("邮箱不合法")
	}
	at := strings.LastIndexByte(v, '@')
	if at <= 0 || at == len(v)-1 || strings.Contains(v[:at], " ") || strings.Contains(v[at+1:], ".") == false {
		return Validation("邮箱不合法")
	}
	if strings.Contains(v, "\n") || strings.Contains(v, "\r") {
		return Validation("邮箱不合法")
	}
	return nil
}

func MaskIP(ip string) string {
	if ip == "" {
		return ""
	}
	if i := strings.LastIndexByte(ip, '.'); i > 0 {
		return ip[:i+1] + "x"
	}
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) > 1 {
			return strings.Join(parts[:2], ":") + ":xxxx"
		}
	}
	return "x"
}

func SummizeAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > 120 {
		return ua[:120]
	}
	return ua
}

// Transactional audit + outbox helpers shared by usecases.

// auditIn writes an audit event scoped to one organization. Tenant audit
// queries filter on the same organization_id, so a tenant never sees platform
// events and platform audit keeps full visibility.
func (s *Services) auditIn(ctx context.Context, tx Tx, actor ActorContext, orgID int64, action, target, reason string) error {
	e := &AuditEvent{
		EventID:        s.IDs.NewID(),
		Action:         action,
		Target:         target,
		Reason:         reason,
		Result:         "success",
		RequestID:      auditRequestID(ctx, actor),
		OccurredAt:     s.Clock.Now().UTC(),
		OrganizationID: orgID,
		Before:         "{}", After: "{}", Diff: "{}",
	}
	if actor.User != nil {
		e.ActorUserID = actor.User.ID
	}
	if actor.Session != nil {
		e.ActorSessionID = actor.Session.ID
	}
	return s.Audit.Append(ctx, tx, e)
}

// auditRequestID prefers the transport request id and falls back to the actor
// metadata supplied by internal gRPC callers.
func auditRequestID(ctx context.Context, actor ActorContext) string {
	if id := RequestID(ctx); id != "" {
		return id
	}
	return actor.RequestID
}

func (s *Services) audit(ctx context.Context, tx Tx, actor ActorContext, action, target, before, after, diff, reason string, result string) error {
	e := &AuditEvent{
		EventID:    s.IDs.NewID(),
		Action:     action,
		Target:     target,
		Before:     before,
		After:      after,
		Diff:       diff,
		Result:     result,
		Reason:     reason,
		RequestID:  auditRequestID(ctx, actor),
		OccurredAt: s.Clock.Now().UTC(),
	}
	if actor.User != nil {
		e.ActorUserID = actor.User.ID
	}
	if actor.Session != nil {
		e.ActorSessionID = actor.Session.ID
	}
	if actor.Actor.ServiceID != "" {
		e.ActorServiceID = actor.Actor.ServiceID
	}
	if static, err := s.Policy.PolicyRevision(ctx, tx); err == nil {
		e.Versions = fmt.Sprintf(`{"policy":%d}`, static)
	}
	return s.Audit.Append(ctx, tx, e)
}

func (s *Services) emit(ctx context.Context, tx Tx, aggregateType string, aggregateID int64, revision uint64, eventType, payload string) error {
	var err error
	payload, err = eventWirePayload(payload)
	if err != nil {
		return ErrDependency
	}
	return s.Outbox.Append(ctx, tx, &Event{
		EventID:           s.IDs.NewID(),
		AggregateType:     aggregateType,
		AggregateID:       aggregateID,
		AggregateRevision: revision,
		EventType:         eventType,
		SchemaVersion:     1,
		Payload:           payload,
		OccurredAt:        s.Clock.Now().UTC(),
	})
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrResourceNotFound)
}

// confirmPassword is shared by self-service and administrative credential
// verification. It never reveals whether the account has a password.
func (s *Services) confirmPassword(ctx context.Context, userID int64, password string) error {
	cred, err := s.Credentials.Get(ctx, nil, userID)
	if err != nil || cred.PasswordHash == "" || !VerifyPassword(cred.PasswordHash, password) {
		return Validation("当前密码不正确")
	}
	return nil
}

func (s *Services) recordSecurity(ctx context.Context, userID int64, sessionID, kind, result, ip, ua, requestID string) {
	_ = s.Events.Append(ctx, nil, &SecurityEvent{
		ID:               s.IDs.NewID(),
		UserID:           userID,
		SessionID:        sessionID,
		Kind:             kind,
		Result:           result,
		IPMasked:         MaskIP(ip),
		UserAgentSummary: SummizeAgent(ua),
		RequestID:        requestID,
		OccurredAt:       s.Clock.Now().UTC(),
	})
}
