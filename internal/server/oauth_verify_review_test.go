package server_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/totp"
	"github.com/stretchr/testify/require"
)

func newOAuthOnlyHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user, err := h.svc.Users.Create(ctx, nil, &biz.User{Username: "oauth.only", UsernameNormalized: "oauth.only", DisplayName: "OAuth User", Email: "oauth@example.com", EmailNormalized: "oauth@example.com", EmailVerified: true, Status: biz.UserStatusEnabled, Revision: 1, IdentityVersion: 1, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	member, err := h.svc.IAM.GetRoleByCode(ctx, nil, "member")
	require.NoError(t, err)
	_, err = h.svc.IAM.CreateAssignment(ctx, nil, &biz.Assignment{UserID: user.ID, RoleID: member.ID, Boundary: authorization.Scope{All: true}, StartsAt: now, Origin: biz.OriginLegacy, Revision: 1, CreatedAt: now})
	require.NoError(t, err)
	_, err = h.svc.Identities.Create(ctx, nil, &biz.ExternalIdentity{UserID: user.ID, Provider: "mock", Issuer: "mock", ProviderSubject: "subject-1", Display: "Verified User"})
	require.NoError(t, err)
	oauthComplete(t, h, "login")
	rec := h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "oauth.only", decode[map[string]any](t, rec)["username"])
	return h
}

func oauthStateFor(t *testing.T, h *harness, mode string) string {
	t.Helper()
	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/start?mode="+mode, nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "uc_oauth_state" {
			return cookie.Value
		}
	}
	t.Fatalf("no OAuth state: %s", rec.Header().Get("Location"))
	return ""
}

func oauthComplete(t *testing.T, h *harness, mode string) {
	t.Helper()
	state := oauthStateFor(t, h, mode)
	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.NotContains(t, rec.Header().Get("Location"), "oauth_error=")
	if mode == "verify" {
		require.Equal(t, "/account/security?verified=mock", rec.Header().Get("Location"))
	}
}

func setOAuthOnlyPassword(h *harness) int {
	return h.do(http.MethodPost, "/api/v1/me/password:change", map[string]any{"current_password": "", "new_password": "OAuthPassword-123"}, "", true).Code
}

func TestOAuthOnlyPasswordRequiresRecentBoundIdentityProof(t *testing.T) {
	h := newOAuthOnlyHarness(t)
	require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h))
	rec := h.do(http.MethodPost, "/api/v1/me/mfa:setup", map[string]any{"current_password": ""}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	oauthComplete(t, h, "verify")
	require.Equal(t, http.StatusOK, setOAuthOnlyPassword(h))
	rec = h.login("oauth.only", "OAuthPassword-123")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "authenticated", decode[map[string]any](t, rec)["status"])
}

func TestOAuthOnlyEnabledMFAStillRequiresSecondFactorToSetPassword(t *testing.T) {
	h := newOAuthOnlyHarness(t)
	oauthComplete(t, h, "verify")
	secret := enrollMFA(t, h, "")
	// Enrolling a new factor invalidates the old generation's primary proof.
	code, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	rec := h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{"current_password": "", "code": code}, "", true)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	oauthComplete(t, h, "verify")
	require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h), "primary proof must not bypass enabled MFA")
	rec = h.do(http.MethodPost, "/api/v1/me/security:verify", map[string]any{"current_password": "", "code": code}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, setOAuthOnlyPassword(h))
}

type otherSubjectProvider struct{ mockOAuthProvider }

func (otherSubjectProvider) Exchange(context.Context, string, string) (biz.OAuthProfile, error) {
	return biz.OAuthProfile{Subject: "different-subject", Issuer: "mock", Display: "Someone Else"}, nil
}

func TestOAuthVerifyRejectsDifferentProviderSubjectWithoutBindingIt(t *testing.T) {
	h := newOAuthOnlyHarness(t)
	state := oauthStateFor(t, h, "verify")
	h.svc.OAuth["mock"] = otherSubjectProvider{}
	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "oauth_error=")
	require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h))
	user, err := h.svc.Users.GetByUsername(context.Background(), nil, "oauth.only")
	require.NoError(t, err)
	identities, err := h.svc.Identities.ListByUser(context.Background(), nil, user.ID)
	require.NoError(t, err)
	require.Len(t, identities, 1)
	require.Equal(t, "subject-1", identities[0].ProviderSubject)
}

func restoreOAuthCookie(t *testing.T, h *harness, state string) {
	t.Helper()
	parsed, err := url.Parse("http://example.com/api/v1/auth/")
	require.NoError(t, err)
	h.jar.SetCookies(parsed, []*http.Cookie{{Name: "uc_oauth_state", Value: state, Path: "/api/v1/auth/"}})
}

func TestOAuthVerifyStateCannotMoveToAnotherSessionOrCredentialGeneration(t *testing.T) {
	t.Run("another session", func(t *testing.T) {
		h := newOAuthOnlyHarness(t)
		state := oauthStateFor(t, h, "verify")
		oauthComplete(t, h, "login")
		restoreOAuthCookie(t, h, state)
		rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
		require.Contains(t, rec.Header().Get("Location"), "oauth_error=")
		require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h))
	})
	t.Run("another generation", func(t *testing.T) {
		h := newOAuthOnlyHarness(t)
		state := oauthStateFor(t, h, "verify")
		user, err := h.svc.Users.GetByUsername(context.Background(), nil, "oauth.only")
		require.NoError(t, err)
		sessions, err := h.svc.Sessions.ListByUser(context.Background(), nil, user.ID)
		require.NoError(t, err)
		version, err := h.svc.Users.BumpIdentityVersion(context.Background(), nil, user.ID)
		require.NoError(t, err)
		require.NoError(t, h.svc.Sessions.SetIdentityVersion(context.Background(), nil, sessions[0].ID, version))
		rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
		require.Contains(t, rec.Header().Get("Location"), "oauth_error=")
		require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h))
	})
}

type futureClock struct{ now time.Time }

func (c futureClock) Now() time.Time { return c.now }

func TestOAuthVerifyProofExpiresAndStateCannotReplay(t *testing.T) {
	h := newOAuthOnlyHarness(t)
	state := oauthStateFor(t, h, "verify")
	h.svc.Challenges = retainingChallenges{h.svc.Challenges}
	rec := h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Equal(t, "/account/security?verified=mock", rec.Header().Get("Location"))
	restoreOAuthCookie(t, h, state)
	rec = h.do(http.MethodGet, "/api/v1/auth/providers/mock/callback?state="+state+"&code=ok", nil, "", false)
	require.Contains(t, rec.Header().Get("Location"), "oauth_error=")
	h.svc.Clock = futureClock{now: time.Now().Add(6 * time.Minute)}
	require.Equal(t, http.StatusForbidden, setOAuthOnlyPassword(h))
}
