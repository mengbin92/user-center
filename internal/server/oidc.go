package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	khttp "github.com/go-kratos/kratos/v3/transport/http"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

func mountOIDCRoutes(srv *khttp.Server, mw *Middleware, uc *biz.OIDCUsecase, publicBase string) {
	discovery := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		body, _ := jsonx.Marshal(uc.Discovery())
		_, _ = w.Write(body)
	})
	jwks := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		body, _ := jsonx.Marshal(uc.JWKS())
		_, _ = w.Write(body)
	})
	authorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := biz.ActorFromContext(r.Context())
		if !ok {
			next := r.URL.RequestURI()
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		if actor.PasswordChangeRequired {
			http.Redirect(w, r, "/account/security?password_change_required=1", http.StatusFound)
			return
		}
		q := r.URL.Query()
		req := biz.OIDCAuthorizeRequest{
			ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"),
			ResponseType: q.Get("response_type"), Scope: q.Get("scope"),
			State: q.Get("state"), Nonce: q.Get("nonce"),
			CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
			Prompt: q.Get("prompt"),
		}
		target, err := uc.AuthorizeRequest(r.Context(), actor, req)
		if err != nil {
			if redirect, _, ok := uc.ErrorRedirect(err); ok {
				http.Redirect(w, r, redirect, http.StatusFound)
				return
			}
			writeOIDCError(w, err, "")
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	token := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOIDCJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeOIDCJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
			return
		}
		clientID := r.Form.Get("client_id")
		secret := r.Form.Get("client_secret")
		if basicID, basicSecret, ok := r.BasicAuth(); ok {
			clientID, secret = basicID, basicSecret
		}
		resp, err := uc.Token(r.Context(), biz.OIDCTokenRequest{
			GrantType: r.Form.Get("grant_type"), Code: r.Form.Get("code"),
			RedirectURI: r.Form.Get("redirect_uri"), ClientID: clientID, ClientSecret: secret,
			CodeVerifier: r.Form.Get("code_verifier"), RefreshToken: r.Form.Get("refresh_token"),
		})
		if err != nil {
			writeOIDCError(w, err, "")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		body, _ := jsonx.Marshal(resp)
		_, _ = w.Write(body)
	})
	userinfo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(raw, "Bearer ") {
			writeOIDCJSONError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
			return
		}
		info, err := uc.UserInfo(r.Context(), strings.TrimSpace(strings.TrimPrefix(raw, "Bearer ")))
		if err != nil {
			writeOIDCError(w, err, "")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		body, _ := jsonx.Marshal(info)
		_, _ = w.Write(body)
	})
	srv.HandleFunc("/.well-known/openid-configuration", mw.Filter(discovery).ServeHTTP)
	srv.HandleFunc("/oidc/jwks", mw.Filter(jwks).ServeHTTP)
	srv.HandleFunc("/oidc/authorize", mw.Filter(authorize).ServeHTTP)
	srv.HandleFunc("/oidc/token", mw.Filter(token).ServeHTTP)
	srv.HandleFunc("/oidc/userinfo", mw.Filter(userinfo).ServeHTTP)
	_ = publicBase
}

func writeOIDCError(w http.ResponseWriter, err error, fallbackRedirect string) {
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
	w.WriteHeader(status)
	body, _ := jsonx.Marshal(map[string]string{"error": code, "error_description": description})
	_, _ = w.Write(body)
}
