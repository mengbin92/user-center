package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/mengbin92/user-center/platform/httpx"
)

type Middleware struct {
	sessions   *biz.SessionUsecase
	log        *zap.Logger
	secure     bool
	domain     string
	trustProxy bool
}

func NewMiddleware(sessions *biz.SessionUsecase, sec *conf.Security, log *zap.Logger) *Middleware {
	m := &Middleware{sessions: sessions, log: log}
	if sec != nil {
		m.secure = sec.CookieSecure
		m.domain = sec.CookieDomain
		m.trustProxy = sec.TrustProxyHeaders
	}
	return m
}

func (m *Middleware) CookieSecure() bool   { return m.secure }
func (m *Middleware) CookieDomain() string { return m.domain }

func (m *Middleware) Filter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := m.prepare(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require protects raw (non-proto) routes with the same auth/CSRF rules.
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := m.prepare(w, r)
		if !ok {
			return
		}
		if _, has := biz.ActorFromContext(ctx); !has {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "登录状态无效或已过期")
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) prepare(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	ctx := r.Context()
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID == "" || len(requestID) > 64 {
		requestID = uuid.NewString()
	}
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	if isUnsafe(r.Method) && strings.HasPrefix(r.URL.Path, "/api/v1/") {
		const maxRequestBody = 1 << 20
		if r.ContentLength > maxRequestBody {
			writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "请求内容不能超过 1 MiB")
			return ctx, false
		}
		if r.Body != nil {
			body := http.MaxBytesReader(w, r.Body, maxRequestBody)
			raw, err := io.ReadAll(body)
			_ = body.Close()
			var limitErr *http.MaxBytesError
			if errors.As(err, &limitErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "请求内容不能超过 1 MiB")
				return ctx, false
			}
			if err != nil {
				writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "无法读取请求内容")
				return ctx, false
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
	}

	info := httpx.Info{
		RequestID: requestID,
		IP:        clientIP(r, m.trustProxy),
		UserAgent: r.UserAgent(),
	}
	if c, err := r.Cookie(service.CSRFCookie); err == nil && c.Value != "" {
		info.CSRF = c.Value
	} else {
		token := randomToken()
		http.SetCookie(w, &http.Cookie{
			Name: service.CSRFCookie, Value: token, Path: "/", HttpOnly: false,
			Secure: m.secure, SameSite: http.SameSiteLaxMode, Domain: m.domain,
			MaxAge: 86400,
		})
		info.CSRF = token
	}
	ctx = httpx.With(ctx, info)
	ctx = biz.WithRequestID(ctx, requestID)
	r = r.WithContext(ctx)

	if isUnsafe(r.Method) && strings.HasPrefix(r.URL.Path, "/api/v1/") {
		header := r.Header.Get("X-CSRF-Token")
		if header == "" || header != info.CSRF {
			writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "CSRF 校验失败，请刷新页面后重试")
			return ctx, false
		}
	}

	if c, err := r.Cookie(service.SessionCookie); err == nil && c.Value != "" {
		actor, err := m.sessions.ValidateSession(ctx, c.Value)
		if err == nil {
			actor.RequestID = requestID
			actor.IP = info.IP
			actor.UserAgent = info.UserAgent
			ctx = biz.WithActor(ctx, actor)
		} else if errors.Is(err, biz.ErrSessionRevoked) || errors.Is(err, biz.ErrUnauthenticated) {
			http.SetCookie(w, &http.Cookie{
				Name: service.SessionCookie, Value: "", Path: "/", HttpOnly: true,
				Secure: m.secure, SameSite: http.SameSiteLaxMode, Domain: m.domain, MaxAge: -1,
			})
		} else if requiresAuth(r.URL.Path) {
			writeError(w, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "依赖服务暂不可用")
			return ctx, false
		}
	}

	if requiresAuth(r.URL.Path) {
		actor, has := biz.ActorFromContext(ctx)
		if !has {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "登录状态无效或已过期")
			return ctx, false
		}
		if actor.PasswordChangeRequired && requiresPasswordChange(r.URL.Path) {
			writeError(w, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "首次登录必须先修改初始密码")
			return ctx, false
		}
	}
	return ctx, true
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// authenticatedPrefixes lists the path families that require a session. Keep it
// in sync with the gateway route table: a missing prefix silently disables both
// the 401 gate and the password-change gate below.
var authenticatedPrefixes = []string{"/api/v1/me", "/api/v1/admin", "/api/v1/orgs"}

// managementPrefixes are the paths blocked until an initial password is
// changed. /api/v1/me stays reachable so the user can complete the change.
var managementPrefixes = []string{"/api/v1/admin", "/api/v1/orgs"}

func requiresAuth(path string) bool {
	return hasAnyPrefix(path, authenticatedPrefixes)
}

func requiresPasswordChange(path string) bool {
	return hasAnyPrefix(path, managementPrefixes)
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeError(w http.ResponseWriter, status int, reason, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body, _ := jsonx.Marshal(map[string]any{
		"code": status, "reason": reason, "message": message,
		"metadata": map[string]string{"request_id": w.Header().Get("X-Request-ID")},
	})
	_, _ = w.Write(body)
}
