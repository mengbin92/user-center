package server

import (
	"errors"
	"fmt"
	"html"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/obs"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

func mountOIDCRoutes(handle func(string, string, http.HandlerFunc), mw *Middleware, uc *biz.OIDCUsecase) {
	discovery := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidcMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		body, _ := jsonx.Marshal(uc.Discovery())
		_, _ = w.Write(body)
	})
	jwks := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidcMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		body, _ := jsonx.Marshal(uc.JWKS())
		_, _ = w.Write(body)
	})
	authorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !oidcMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		q, ok := oidcForm(w, r, true)
		if !ok {
			return
		}
		actor, loggedIn := biz.ActorFromContext(r.Context())
		req := biz.OIDCAuthorizeRequest{
			ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"),
			ResponseType: q.Get("response_type"), Scope: q.Get("scope"),
			State: q.Get("state"), Nonce: q.Get("nonce"),
			CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
			Prompt: q.Get("prompt"), MaxAge: q.Get("max_age"),
		}
		target, err := uc.AuthorizeRequest(r.Context(), actor, req)
		if err != nil {
			if redirect, _, ok := uc.ErrorRedirect(err); ok {
				http.Redirect(w, r, redirect, http.StatusFound)
				return
			}
			var oe *biz.OIDCError
			if !loggedIn && errors.As(err, &oe) && oe.Code == "login_required" && oe.RedirectURI == "" {
				next := "/oidc/authorize?" + q.Encode()
				http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
				return
			}
			writeOIDCError(w, err)
			return
		}
		if strings.HasPrefix(target, "/account/security?") {
			next := "/oidc/authorize?" + q.Encode()
			target += "&next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	token := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidcMethods(w, r, http.MethodPost) {
			return
		}
		form, ok := oidcForm(w, r, false)
		if !ok {
			return
		}
		clientID, secret := form.Get("client_id"), form.Get("client_secret")
		if r.Header.Get("Authorization") != "" {
			if len(r.Header.Values("Authorization")) != 1 || form.Has("client_secret") {
				writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods")
				return
			}
			basicID, basicSecret, ok := r.BasicAuth()
			if !ok {
				writeOIDCJSONError(w, http.StatusUnauthorized, "invalid_client", "HTTP Basic client authentication required")
				return
			}
			var err error
			clientID, err = url.QueryUnescape(basicID)
			if err == nil {
				secret, err = url.QueryUnescape(basicSecret)
			}
			if err != nil {
				writeOIDCJSONError(w, http.StatusUnauthorized, "invalid_client", "invalid client authentication encoding")
				return
			}
			if form.Has("client_id") && form.Get("client_id") != clientID {
				writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "conflicting client identifiers")
				return
			}
		}
		resp, err := uc.Token(r.Context(), biz.OIDCTokenRequest{
			GrantType: form.Get("grant_type"), Code: form.Get("code"),
			RedirectURI: form.Get("redirect_uri"), ClientID: clientID, ClientSecret: secret,
			CodeVerifier: form.Get("code_verifier"), RefreshToken: form.Get("refresh_token"), Scope: form.Get("scope"),
		})
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		body, _ := jsonx.Marshal(resp)
		_, _ = w.Write(body)
	})
	userinfo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidcMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		auth := strings.Fields(r.Header.Get("Authorization"))
		if len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") || len(r.Header.Values("Authorization")) != 1 {
			writeOIDCJSONError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
			return
		}
		info, err := uc.UserInfo(r.Context(), auth[1])
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		body, _ := jsonx.Marshal(info)
		_, _ = w.Write(body)
	})
	logout := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !oidcMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		form, ok := oidcForm(w, r, true)
		if !ok {
			return
		}
		actor, _ := biz.ActorFromContext(r.Context())
		redirect, err := uc.Logout(r.Context(), actor, biz.OIDCLogoutRequest{
			IDTokenHint:           form.Get("id_token_hint"),
			ClientID:              form.Get("client_id"),
			PostLogoutRedirectURI: form.Get("post_logout_redirect_uri"),
			State:                 form.Get("state"),
		})
		if err != nil {
			// A rejected redirect (or a client/hint mismatch) still ends the
			// local session in the usecase. Clear the cookie here instead of
			// leaving a browser that believes it logged out holding a live
			// session token, and render a browser-readable error page.
			var oe *biz.OIDCError
			if errors.As(err, &oe) {
				clearSessionCookie(w, mw)
				writeOIDCLogoutError(w, oe)
				return
			}
			writeOIDCError(w, err)
			return
		}
		clearSessionCookie(w, mw)
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>已退出登录</title></head><body style="font-family:system-ui;padding:48px;text-align:center"><p>已退出用户中心登录。</p><p><a href="/login">重新登录</a></p></body></html>`))
	})
	handle(obs.MethodAny, "/.well-known/openid-configuration", mw.Filter(discovery).ServeHTTP)
	handle(obs.MethodAny, "/oidc/jwks", mw.Filter(jwks).ServeHTTP)
	handle(obs.MethodAny, "/oidc/authorize", mw.Filter(authorize).ServeHTTP)
	handle(obs.MethodAny, "/oidc/token", mw.Filter(token).ServeHTTP)
	handle(obs.MethodAny, "/oidc/userinfo", mw.Filter(userinfo).ServeHTTP)
	handle(obs.MethodAny, "/oidc/logout", mw.Filter(logout).ServeHTTP)
}

func oidcMethods(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, method := range allowed {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeOIDCJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "HTTP method is not allowed")
	return false
}

func oidcForm(w http.ResponseWriter, r *http.Request, allowQuery bool) (url.Values, bool) {
	const maxBody = 1 << 20
	if r.ContentLength > maxBody || len(r.URL.RawQuery) > maxBody {
		writeOIDCJSONError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request exceeds 1 MiB")
		return nil, false
	}
	if !allowQuery && r.URL.RawQuery != "" {
		writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "token parameters must be sent in the request body")
		return nil, false
	}
	if r.Method == http.MethodPost {
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/x-www-form-urlencoded" {
			writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "form-encoded body required")
			return nil, false
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeOIDCJSONError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request exceeds 1 MiB")
		} else {
			writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form parameters")
		}
		return nil, false
	}
	for _, values := range r.Form {
		if len(values) != 1 {
			writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "duplicate parameters are not allowed")
			return nil, false
		}
	}
	return r.Form, true
}

func writeOIDCError(w http.ResponseWriter, err error) {
	var oe *biz.OIDCError
	if errors.As(err, &oe) {
		status := oe.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		writeOIDCJSONError(w, status, oe.Code, oe.Description)
		return
	}
	writeOIDCJSONError(w, http.StatusInternalServerError, "server_error", "temporary server failure")
}

func writeOIDCJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		switch code {
		case "invalid_client":
			w.Header().Set("WWW-Authenticate", `Basic realm="user-center"`)
		case "invalid_token":
			w.Header().Set("WWW-Authenticate", `Bearer realm="user-center", error="invalid_token"`)
		}
	}
	w.WriteHeader(status)
	body, _ := jsonx.Marshal(map[string]string{"error": code, "error_description": description})
	_, _ = w.Write(body)
}

// clearSessionCookie removes the browser session cookie with the same
// attributes used when it was set, so the deletion actually matches.
func clearSessionCookie(w http.ResponseWriter, mw *Middleware) {
	http.SetCookie(w, &http.Cookie{
		Name: service.SessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
		Secure: mw.CookieSecure(), SameSite: http.SameSiteLaxMode, Domain: mw.CookieDomain(),
	})
}

// writeOIDCLogoutError renders a readable page for a logout request whose
// redirect could not be honoured. The local session has already been revoked;
// the page must not imply otherwise.
func writeOIDCLogoutError(w http.ResponseWriter, oe *biz.OIDCError) {
	status := oe.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>已退出登录</title></head><body style="font-family:system-ui;padding:48px;text-align:center"><p>已退出用户中心登录，但无法返回应用：</p><p><code>%s</code> %s</p><p><a href="/login">重新登录</a></p></body></html>`,
		html.EscapeString(oe.Code), html.EscapeString(oe.Description))
}
