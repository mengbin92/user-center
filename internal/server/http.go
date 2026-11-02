package server

import (
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
		khttp.Filter(mw.Filter),
	)
	usercv1.RegisterAuthServiceHTTPServer(srv, auth)
	usercv1.RegisterMeServiceHTTPServer(srv, me)
	usercv1.RegisterAdminUserServiceHTTPServer(srv, admin)
	usercv1.RegisterIAMServiceHTTPServer(srv, iam)
	usercv1.RegisterAuditServiceHTTPServer(srv, audit)
	usercv1.RegisterSettingsServiceHTTPServer(srv, settings)

	srv.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

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
