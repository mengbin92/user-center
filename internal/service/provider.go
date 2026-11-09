package service

import (
	"time"

	"github.com/google/wire"

	"github.com/mengbin92/user-center/internal/conf"
)

func NewDeps(sec *conf.Security) Deps {
	deps := Deps{CSRFKey: "user-center-csrf"}
	if sec != nil {
		deps.Cookies.Secure = sec.CookieSecure
		deps.Cookies.Domain = sec.CookieDomain
		deps.CSRFKey = sec.CsrfSecret
		if sec.SessionTtlMinutes > 0 {
			deps.Cookies.TTL = time.Duration(sec.SessionTtlMinutes) * time.Minute
		}
	}
	if deps.CSRFKey == "" {
		deps.CSRFKey = "development-only-csrf-key"
	}
	return deps
}

var ProviderSet = wire.NewSet(
	NewDeps,
	NewAuthService,
	NewMeService,
	NewAdminUserService,
	NewIAMService,
	NewAuditService,
	NewSettingsService,
	NewIntegrationService,
	NewIntegrationAdminService,
	NewOIDCAdminService,
	NewOrganizationService,
	NewSCIMService,
	NewDirectoryAdminService,
)
