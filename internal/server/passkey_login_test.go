package server_test

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/mengbin92/user-center/pkg/totp"
	"github.com/stretchr/testify/require"
)

// Passwordless passkey login is the v0.41 authentication path ported from
// micro-one-api: assertion first, then the ordinary session tail. These tests
// exercise the real CBOR/COSE verification fixture, not a stub.
func TestPasskeyPasswordlessLoginLifecycle(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixture := newWebAuthnFixture(t)
	reg := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	registerPasskey(t, h, fixture, reg["challenge_id"].(string), reg["challenge"].(string))

	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	h.jar, _ = cookiejar.New(nil)
	h.refreshCSRF()

	rec := h.do(http.MethodPost, "/api/v1/auth/passkey/login:begin",
		map[string]any{"username": "root"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	begin := decode[map[string]any](t, rec)
	require.NotEmpty(t, begin["challenge_id"])
	require.NotEmpty(t, begin["challenge"])
	require.Equal(t, fixture.rpID, begin["rp_id"])
	require.Contains(t, begin["allow_credential_ids"], fixture.credIDText)

	authData, clientData, signature := fixture.assertion(t, begin["challenge"].(string), 2)
	body := map[string]any{
		"challenge_id": begin["challenge_id"], "credential_id": fixture.credIDText,
		"authenticator_data": authData, "client_data_json": clientData, "signature": signature,
	}
	rec = h.do(http.MethodPost, "/api/v1/auth/passkey/login:complete", body, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	login := decode[map[string]any](t, rec)
	require.Equal(t, "authenticated", login["status"])
	require.Equal(t, "root", login["user"].(map[string]any)["username"])

	rec = h.do(http.MethodGet, "/api/v1/me", nil, "", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The ceremony is one-shot: replaying the same challenge must not mint a
	// second session.
	rec = h.do(http.MethodPost, "/api/v1/auth/passkey/login:complete", body, "", true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Equal(t, "CHALLENGE_INVALID", decode[map[string]any](t, rec)["reason"])
}

func TestPasskeyPasswordlessLoginStillOwesTOTP(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	secret := enrollMFA(t, h, "ChangeMe-12345")
	fixture := newWebAuthnFixture(t)
	reg := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	registerPasskey(t, h, fixture, reg["challenge_id"].(string), reg["challenge"].(string))

	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	h.jar, _ = cookiejar.New(nil)
	h.refreshCSRF()

	rec := h.do(http.MethodPost, "/api/v1/auth/passkey/login:begin",
		map[string]any{"username": "root"}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	begin := decode[map[string]any](t, rec)
	authData, clientData, signature := fixture.assertion(t, begin["challenge"].(string), 2)
	rec = h.do(http.MethodPost, "/api/v1/auth/passkey/login:complete", map[string]any{
		"challenge_id": begin["challenge_id"], "credential_id": fixture.credIDText,
		"authenticator_data": authData, "client_data_json": clientData, "signature": signature,
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	reply := decode[map[string]any](t, rec)
	require.Equal(t, "mfa_required", reply["status"])
	require.NotEmpty(t, reply["challenge_id"])
	for _, cookie := range rec.Result().Cookies() {
		require.NotEqual(t, "uc_session", cookie.Name, "an MFA-pending login must not set a session")
	}

	code, err := totp.Code(secret, time.Now().Unix()/30+1, 6)
	require.NoError(t, err)
	rec = h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
		"challenge_id": reply["challenge_id"], "code": code,
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "authenticated", decode[map[string]any](t, rec)["status"])
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/api/v1/me", nil, "", false).Code)
}

// Unknown, disabled and passkey-less accounts must answer begin with the same
// shape, and complete must fail with the same reason, so the public endpoints
// cannot be used to enumerate accounts or passkey ownership.
func TestPasskeyLoginDecoyParity(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixture := newWebAuthnFixture(t)
	reg := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	registerPasskey(t, h, fixture, reg["challenge_id"].(string), reg["challenge"].(string))
	fixtureStepUp(h)
	rec := h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "no.passkey", "email": "no.passkey@example.com",
		"initial_password": "NoPasskey-12345", "reason": "decoy parity fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = h.management(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "disabled.user", "email": "disabled@example.com",
		"initial_password": "DisabledPass-12345", "reason": "decoy parity fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	disabledID := decode[map[string]any](t, rec)["id"].(string)
	rec = h.management(http.MethodPost, "/api/v1/admin/users/"+disabledID+":set-status", map[string]any{
		"status": "disabled", "reason": "decoy parity fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	h.jar, _ = cookiejar.New(nil)
	h.refreshCSRF()

	fakeAssertion := map[string]any{
		"credential_id":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"authenticator_data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"client_data_json":   "e30",
		"signature":          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, identifier := range []string{"does.not.exist", "no.passkey", "disabled.user", "root"} {
		rec := h.do(http.MethodPost, "/api/v1/auth/passkey/login:begin",
			map[string]any{"username": identifier}, "", true)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		begin := decode[map[string]any](t, rec)
		require.NotEmpty(t, begin["challenge_id"])
		require.NotEmpty(t, begin["challenge"])
		allow, ok := begin["allow_credential_ids"].([]any)
		require.True(t, ok)
		require.Len(t, allow, 1, "the decoy must not send an empty allow list")

		body := map[string]any{"challenge_id": begin["challenge_id"]}
		for key, value := range fakeAssertion {
			body[key] = value
		}
		rec = h.do(http.MethodPost, "/api/v1/auth/passkey/login:complete", body, "", true)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Equal(t, "CHALLENGE_INVALID", decode[map[string]any](t, rec)["reason"])
	}
}
