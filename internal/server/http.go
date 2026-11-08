package server

import (
	"encoding/json"
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
	"github.com/mengbin92/user-center/internal/obs"
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
	metrics *obs.Metrics,
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

	mw.WithWriteLimiter(NewWriteLimiter(cfg, mw.Limiter(), metrics))
	srv := khttp.NewServer(
		khttp.Address(addr),
		khttp.Timeout(time.Duration(timeout)*time.Second),
		khttp.ErrorEncoder(encodeError),
		// Metrics wraps the auth filter: a 401/403 short-circuit must still be
		// counted, otherwise the error-rate panels silently under-report.
		khttp.Filter(metrics.HTTP, mw.Filter),
	)
	// Route classification is a closed table, not a guess: the metric label and
	// the slow-request log both read from it. Proto routes are added by
	// WalkRoute below; raw handlers have no method matcher and are therefore
	// invisible to WalkRoute, so every one of them registers its template at the
	// point it is mounted. The same RouteSet is handed to the middleware so both
	// the counter and the log agree on one label.
	routes := metrics.Routes()
	mw.WithRoutes(routes)
	handle := func(method, template string, h http.HandlerFunc) {
		routes.Add(method, template)
		srv.HandleFunc(template, h)
	}

	usercv1.RegisterAuthServiceHTTPServer(srv, auth)
	usercv1.RegisterMeServiceHTTPServer(srv, me)
	usercv1.RegisterAdminUserServiceHTTPServer(srv, admin)
	usercv1.RegisterIAMServiceHTTPServer(srv, iam)
	usercv1.RegisterAuditServiceHTTPServer(srv, audit)
	usercv1.RegisterSettingsServiceHTTPServer(srv, settings)
	usercv1.RegisterIntegrationAdminServiceHTTPServer(srv, integrationAdmin)
	usercv1.RegisterOIDCAdminServiceHTTPServer(srv, oidcAdmin)
	usercv1.RegisterOrganizationServiceHTTPServer(srv, organizations)

	// Everything the protobuf registrations above mounted is added at the end
	// of this function, after the raw routes are registered too.

	// Liveness: the process is up and the HTTP loop is running. It deliberately
	// does not touch the database -- a liveness check that fails when a
	// dependency is down causes a restart loop that cannot fix the dependency
	// and destroys the logs needed to diagnose it.
	handle(obs.MethodAny, "/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Readiness: can this instance serve traffic right now. Container health
	// checks and load balancers must use this one; /healthz returning 200 while
	// the database is gone is exactly the failure this endpoint exists to make
	// visible (found by the S13 restore drill: dropping the database left the
	// container reporting healthy).
	handle(obs.MethodAny, "/readyz", func(w http.ResponseWriter, r *http.Request) {
		ready, checks := metrics.Ready(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		status := "ok"
		if !ready {
			status = "unavailable"
		}
		payload := struct {
			Status string            `json:"status"`
			Checks map[string]string `json:"checks"`
		}{Status: status, Checks: checks}
		_ = json.NewEncoder(w).Encode(payload)
	})

	mountOAuthRoutes(handle, mw, auth, publicBase)
	mountOIDCRoutes(handle, mw, oidcAdmin.Usecase())

	// CSV artifact download is a raw stream; it re-verifies the actor, job
	// ownership and expiry on every request. Platform and tenant downloads
	// share exactly one streaming path.
	serveArtifact := func(w http.ResponseWriter, r *http.Request, job *biz.ExportJob) {
		if job == nil || job.Status != biz.ExportReady || job.ExpiresAt.Before(time.Now().UTC()) {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在或已过期")
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
	}
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
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		serveArtifact(w, r, job)
	}))
	handle(obs.MethodAny, "/api/v1/admin/exports/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		download.ServeHTTP(w, r)
	})

	orgDownload := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 8 || parts[0] != "api" || parts[4] != "audits" || parts[5] != "exports" {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		orgID, err := biz.ParseID(parts[3], "id")
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		jobID, err := biz.ParseID(parts[6], "export_id")
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		job, err := organizations.AuditExportForDownload(r.Context(), orgID, jobID)
		if err != nil {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "导出任务不存在")
			return
		}
		serveArtifact(w, r, job)
	}))
	handle(obs.MethodAny, "/api/v1/orgs/{id}/audits/exports/{export_id}/download", func(w http.ResponseWriter, r *http.Request) {
		orgDownload.ServeHTTP(w, r)
	})

	webDir := os.Getenv("WEB_DIST")
	if webDir == "" {
		webDir = "web/dist"
	}
	if stat, err := os.Stat(webDir); err == nil && stat.IsDir() {
		// The SPA is a prefix catch-all, not a template: every client-side
		// history route shares it. obs collapses those into one "spa" label.
		srv.HandlePrefix("/", spaHandler(webDir, log))
	}

	// Everything mounted above. WalkRoute only returns routes that carry a
	// method matcher, which is exactly the set the generated protobuf code
	// creates; the raw routes registered through handle() are already in.
	if err := srv.WalkRoute(func(route khttp.RouteInfo) error {
		routes.Add(route.Method, route.Path)
		return nil
	}); err != nil {
		log.Warn("route table incomplete", zap.Error(err))
	}

	return &HTTPServer{Server: srv}
}

func mountOAuthRoutes(handle func(string, string, http.HandlerFunc), mw *Middleware, auth *service.AuthService, publicBase string) {
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
	handle(obs.MethodAny, "/api/v1/auth/providers/{provider}/start", mw.Filter(start).ServeHTTP)
	handle(obs.MethodAny, "/api/v1/auth/providers/{provider}/callback", mw.Filter(callback).ServeHTTP)
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
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/healthz") || strings.HasPrefix(r.URL.Path, "/readyz") {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "资源不存在")
			return
		}
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean != "." && filepath.IsLocal(clean) {
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
