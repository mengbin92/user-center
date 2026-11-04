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
	"strconv"
	"strings"
	"time"
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

func ValidatePassword(pw string, minLen int) error {
	if minLen < 8 {
		minLen = 8
	}
	if utf8.RuneCountInString(pw) < minLen {
		return Validation(fmt.Sprintf("密码至少需要 %d 个字符", minLen))
	}
	if len(pw) > 72 {
		return Validation("密码不能超过 72 个字节")
	}
	if strings.TrimSpace(pw) != pw {
		return Validation("密码首尾不能包含空白字符")
	}
	return nil
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
		RequestID:      RequestID(ctx),
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
		RequestID:  RequestID(ctx),
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
