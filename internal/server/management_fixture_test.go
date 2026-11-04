package server_test

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/service"
	"github.com/stretchr/testify/require"
)

// management keeps the older happy-path fixtures current with the explicit
// version contract. Denial tests use do directly to exercise missing fields.
func (h *harness) management(method, path string, body any, token string, csrf bool) *httptest.ResponseRecorder {
	if values, ok := body.(map[string]any); ok {
		policy, err := h.svc.Policy.PolicyRevision(context.Background(), nil)
		require.NoError(h.t, err)
		if _, has := values["expected_policy_revision"]; !has && (strings.HasPrefix(path, "/api/v1/admin/iam/") || strings.HasPrefix(path, "/api/v1/admin/oidc-clients") || path == "/api/v1/admin/users" || strings.HasPrefix(path, "/api/v1/admin/users/")) {
			values["expected_policy_revision"] = strconv.FormatUint(policy, 10)
		}
		if strings.HasPrefix(path, "/api/v1/admin/users/") {
			part := strings.Split(strings.TrimPrefix(path, "/api/v1/admin/users/"), "/")[0]
			part = strings.Split(part, ":")[0]
			if id, err := strconv.ParseInt(part, 10, 64); err == nil {
				user, err := h.svc.Users.Get(context.Background(), nil, id)
				require.NoError(h.t, err)
				if _, has := values["expected_revision"]; !has {
					values["expected_revision"] = strconv.FormatUint(user.Revision, 10)
				}
			}
		}
	}
	return h.do(method, path, body, token, csrf)
}

func fixtureStepUp(h *harness) {
	h.t.Helper()
	parsed, err := url.Parse("http://example.com")
	require.NoError(h.t, err)
	for _, cookie := range h.jar.Cookies(parsed) {
		if cookie.Name != service.SessionCookie {
			continue
		}
		session, err := h.svc.Sessions.GetByTokenHash(context.Background(), nil, biz.HashToken(cookie.Value))
		require.NoError(h.t, err)
		require.NoError(h.t, h.svc.StepUp.Put(context.Background(), biz.StepUpKey(session), time.Now().Add(time.Minute)))
		return
	}
	h.t.Fatal("session cookie missing")
}
