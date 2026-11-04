package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	khttp "github.com/go-kratos/kratos/v3/transport/http"
	"go.uber.org/zap"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/mengbin92/user-center/platform/httpx"
)

type HTTPServer struct {
	*khttp.Server
}

// ArtifactDir is a named Wire provider so it cannot collide with other strings.
type ArtifactDir string

func NewArtifactDir() ArtifactDir {
	if v := os.Getenv("ARTIFACT_DIR"); v != "" {
		return ArtifactDir(v)
	}
	return ArtifactDir("artifacts")
}

func NewHTTPServer(
	cfg *conf.Server,
	sec *conf.Security,
	mw *Middleware,
	log *zap.Logger,
	auth *service.AuthService,
	me *service.MeService,
	admin *service.AdminUserService,
	iam *service.IAMService,
	audit *service.AuditService,
	settings *service.SettingsService,
	integrationAdmin *service.IntegrationAdminService,
	oidcAdmin *service.OIDCAdminService,
	organizations *service.OrganizationService,
	users *biz.UserUsecase,
	artifactDir ArtifactDir,
) *HTTPServer {
	addr := ":8080"
	timeout := 30
	publicBase := "http://localhost:5173"
	if cfg != nil && cfg.Http != nil {
		if cfg.Http.Addr != "" {
			addr = cfg.Http.Addr
		}
		if cfg.Http.TimeoutSeconds > 0 {
			timeout = int(cfg.Http.TimeoutSeconds)
		}
		if cfg.Http.PublicBaseUrl != "" {
			publicBase = cfg.Http.PublicBaseUrl
		}
	}
	_ = publicBase

	srv := khttp.NewServer(
		khttp.Address(addr),
		khttp.Timeout(time.Duration(timeout)*time.Second),
		khttp.ErrorEncoder(encodeError),
		khttp.Filter(mw.Filter),
	)
	usercv1.RegisterAuthServiceHTTPServer(srv, auth)
	usercv1.RegisterMeServiceHTTPServer(srv, me)
	usercv1.RegisterAdminUserServiceHTTPServer(srv, admin)
	usercv1.RegisterIAMServiceHTTPServer(srv, iam)
	usercv1.RegisterAuditServiceHTTPServer(srv, audit)
	usercv1.RegisterSettingsServiceHTTPServer(srv, settings)
	usercv1.RegisterIntegrationAdminServiceHTTPServer(srv, integrationAdmin)
	usercv1.RegisterOIDCAdminServiceHTTPServer(srv, oidcAdmin)
	usercv1.RegisterOrganizationServiceHTTPServer(srv, organizations)

	srv.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mountOAuthRoutes(srv, mw, auth, publicBase)
	mountOIDCRoutes(srv, mw, oidcAdmin.Usecase())

	// CSV artifact download is a raw stream; it re-verifies the actor, job
	// ownership and expiry on every request.
	download := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, _ := biz.ActorFromContext(r.Context())
		rawID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/exports/")
		rawID = strings.TrimSuffix(rawID, "/download")
		jobID, err := biz.ParseID(rawID, "id")
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		job, err := users.GetExport(r.Context(), actor, jobID)
		if err != nil || job.Status != biz.ExportReady {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在或尚未完成")
			return
		}
		if job.ExpiresAt.Before(time.Now().UTC()) {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务已过期")
			return
		}
		name := filepath.Base(job.ArtifactName)
		path := filepath.Join(string(artifactDir), name)
		f, err := os.Open(path)
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出文件不存在")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeContent(w, r, name, job.CreatedAt, f)
	}))
	srv.HandleFunc("/api/v1/admin/exports/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		download.ServeHTTP(w, r)
	})

	webDir := os.Getenv("WEB_DIST")
	if webDir == "" {
		webDir = "web/dist"
	}
	if stat, err := os.Stat(webDir); err == nil && stat.IsDir() {
		srv.HandlePrefix("/", spaHandler(webDir, log))
	}

	return &HTTPServer{Server: srv}
}

func mountOAuthRoutes(srv *khttp.Server, mw *Middleware, auth *service.AuthService, publicBase string) {
	authUC := auth.Usecase()
	stateCookie := "uc_oauth_state"
	start := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := oauthProviderFromPath(r.URL.Path)
		mode := r.URL.Query().Get("mode")
		if mode == "" {
			mode = "login"
		}
		var actor *biz.ActorContext
		if a, ok := biz.ActorFromContext(r.Context()); ok {
			actor = &a
		}
		url, state, expires, err := authUC.StartOAuth(r.Context(), provider, mode, r.URL.Query().Get("next"), actor)
		if err != nil {
			target := "/login?oauth_error=oauth_failed"
			if actor != nil {
				target = "/account/security?oauth_error=oauth_failed"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: stateCookie, Value: state, Path: "/api/v1/auth/", HttpOnly: true,
			Secure: mw.CookieSecure(), SameSite: http.SameSiteLaxMode, Domain: mw.CookieDomain(),
			Expires: expires, MaxAge: int(time.Until(expires).Seconds()),
		})
		http.Redirect(w, r, url, http.StatusFound)
	})
	callback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := oauthProviderFromPath(r.URL.Path)
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		cookie, err := r.Cookie(stateCookie)
		failTarget := "/login?oauth_error=state_invalid"
		if _, ok := biz.ActorFromContext(r.Context()); ok {
			failTarget = "/account/security?oauth_error=state_invalid"
		}
		if err != nil || state == "" || cookie.Value != state || code == "" {
			http.Redirect(w, r, failTarget, http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/api/v1/auth/", HttpOnly: true, MaxAge: -1, Secure: mw.CookieSecure(), Domain: mw.CookieDomain()})
		var actor *biz.ActorContext
		if a, ok := biz.ActorFromContext(r.Context()); ok {
			actor = &a
		}
		info := httpx.From(r.Context())
		result, err := authUC.CompleteOAuth(r.Context(), provider, state, code, actor, info.IP, info.UserAgent)
		if err != nil {
			reason := "oauth_failed"
			if errors.Is(err, biz.ErrOAuthNotBound) {
				reason = "not_bound"
			}
			target := "/login?oauth_error=" + reason
			if actor != nil {
				target = "/account/security?oauth_error=" + reason
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		if result.RawToken != "" {
			http.SetCookie(w, &http.Cookie{
				Name: service.SessionCookie, Value: result.RawToken, Path: "/", HttpOnly: true,
				Secure: mw.CookieSecure(), SameSite: http.SameSiteLaxMode, Domain: mw.CookieDomain(),
				Expires: result.Session.ExpiresAt,
			})
		}
		http.Redirect(w, r, result.Redirect, http.StatusFound)
	})
	srv.HandleFunc("/api/v1/auth/providers/{provider}/start", mw.Filter(start).ServeHTTP)
	srv.HandleFunc("/api/v1/auth/providers/{provider}/callback", mw.Filter(callback).ServeHTTP)
}

func oauthProviderFromPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/auth/providers/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func spaHandler(dir string, log *zap.Logger) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/healthz") {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "资源不存在")
			return
		}
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean != "." {
			if info, err := os.Stat(filepath.Join(dir, clean)); err == nil && !info.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
		}
		index := filepath.Join(dir, "index.html")
		if _, err := os.Stat(index); err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "前端资源未构建")
			return
		}
		http.ServeFile(w, r, index)
	})
}
