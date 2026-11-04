package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	khttp "github.com/go-kratos/kratos/v3/transport/http"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"github.com/mengbin92/user-center/platform/httpx"
)

const timeLayout = time.RFC3339

const (
	SessionCookie = "uc_session"
	CSRFCookie    = "uc_csrf"
)

type CookieConfig struct {
	Secure bool
	Domain string
	TTL    time.Duration
}

type Deps struct {
	Cookies CookieConfig
	CSRFKey string
}

func id(v int64) string   { return strconv.FormatInt(v, 10) }
func rev(v uint64) string { return strconv.FormatUint(v, 10) }

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func tptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ts(*t)
}

func userProto(u *biz.User) *usercv1.User {
	if u == nil {
		return nil
	}
	out := &usercv1.User{
		Id: id(u.ID), Username: u.Username, DisplayName: u.DisplayName,
		Email: u.Email, EmailVerified: u.EmailVerified, Status: u.Status,
		Revision: rev(u.Revision), IdentityVersion: rev(u.IdentityVersion),
		CreatedAt: ts(u.CreatedAt), UpdatedAt: ts(u.UpdatedAt),
		ArchivedAt: tptr(u.ArchivedAt), MfaEnabled: u.MFAEnabled,
	}
	for _, r := range u.Roles {
		out.Roles = append(out.Roles, &usercv1.RoleRef{Id: id(r.ID), Code: r.Code, Name: r.Name})
	}
	return out
}

func roleProto(r *biz.Role) *usercv1.Role {
	if r == nil {
		return nil
	}
	out := &usercv1.Role{
		Id: id(r.ID), Code: r.Code, Name: r.Name, Description: r.Description,
		Builtin: r.Builtin, Status: r.Status, Revision: rev(r.Revision),
	}
	if r.MaxMembers != nil {
		out.MaxMembers = *r.MaxMembers
	}
	for _, in := range r.Inherits {
		out.Inherits = append(out.Inherits, id(in))
	}
	for _, g := range r.Grants {
		out.Grants = append(out.Grants, grantProto(g))
	}
	return out
}

func grantProto(g biz.Grant) *usercv1.Grant {
	return &usercv1.Grant{Operation: g.Operation, Effect: string(g.Effect), Scope: scopeProto(g.Scope)}
}

func scopeProto(s authorization.Scope) *usercv1.Scope {
	out := &usercv1.Scope{All: s.All, Self: s.Self}
	for _, uid := range s.UserIDs {
		out.UserIds = append(out.UserIds, id(uid))
	}
	return out
}

func scopeBiz(s *usercv1.Scope) (authorization.Scope, error) {
	out := authorization.Scope{}
	if s == nil {
		out.All = true
		return out, nil
	}
	out.All, out.Self = s.All, s.Self
	for _, raw := range s.UserIds {
		uid, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || uid <= 0 {
			return out, biz.Validation("scope.user_ids 不合法")
		}
		out.UserIDs = append(out.UserIDs, uid)
	}
	if out.Empty() {
		return out, biz.Validation("scope 不能为空")
	}
	return out, nil
}

func grantsBiz(gs []*usercv1.Grant) ([]biz.Grant, error) {
	out := make([]biz.Grant, 0, len(gs))
	for _, g := range gs {
		if g == nil {
			continue
		}
		scope, err := scopeBiz(g.Scope)
		if err != nil {
			return nil, err
		}
		out = append(out, biz.Grant{Operation: g.Operation, Effect: authorization.Effect(g.Effect), Scope: scope})
	}
	return out, nil
}

func requestMeta(ctx context.Context) biz.ActorContext {
	info := httpx.From(ctx)
	actor, _ := biz.ActorFromContext(ctx)
	actor.RequestID = info.RequestID
	actor.IP = info.IP
	actor.UserAgent = info.UserAgent
	return actor
}

func setSessionCookie(ctx context.Context, deps Deps, token string, expires time.Time) {
	khttp.SetCookie(ctx, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: deps.Cookies.Secure, SameSite: http.SameSiteLaxMode,
		Domain: deps.Cookies.Domain, Expires: expires,
	})
}

func clearSessionCookie(ctx context.Context, deps Deps) {
	khttp.SetCookie(ctx, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: deps.Cookies.Secure, SameSite: http.SameSiteLaxMode,
		Domain: deps.Cookies.Domain, MaxAge: -1,
	})
}

func ensureCSRF(ctx context.Context, deps Deps) string {
	info := httpx.From(ctx)
	if info.CSRF != "" {
		return info.CSRF
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	khttp.SetCookie(ctx, &http.Cookie{
		Name: CSRFCookie, Value: token, Path: "/", HttpOnly: false,
		Secure: deps.Cookies.Secure, SameSite: http.SameSiteLaxMode, Domain: deps.Cookies.Domain,
	})
	return token
}

// SignCSRF is used by the transport to verify the double-submit token.
func SignCSRF(key, token string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func parseIDField(raw, field string) (int64, error) { return biz.ParseID(raw, field) }

func parseRevisionField(raw, field string) (uint64, error) {
	return biz.ParseRevision(raw, field)
}

func parseInt32(v int32, def int) int {
	if v <= 0 {
		return def
	}
	return int(v)
}

func pageSize(v int32) int {
	if v <= 0 {
		return 20
	}
	if v > 100 {
		return 100
	}
	return int(v)
}

// requireReason enforces the audit contract: management writes must carry a
// non-empty reason. Silently substituting a default removes the operator's
// intent from the audit trail.
func requireReason(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", biz.Validation("管理写操作必须提供 reason")
	}
	if len([]rune(v)) > 512 {
		return "", biz.Validation("reason 不能超过 512 个字符")
	}
	return v, nil
}

func authzError(err error) error { return err }

func fingerprintOf(parts ...any) string {
	raw, _ := jsonx.Marshal(parts)
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func join(v []string) string { return strings.Join(v, ",") }
