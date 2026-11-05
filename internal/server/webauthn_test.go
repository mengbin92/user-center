package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// webAuthnFixture is a software P-256 authenticator used to exercise the real
// CBOR/COSE parsing and signature verification path end to end.
type webAuthnFixture struct {
	priv       *ecdsa.PrivateKey
	credID     []byte
	credIDText string
	cose       []byte
	counter    uint32
	rpID       string
	origin     string
}

func newWebAuthnFixture(t *testing.T) *webAuthnFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	cose, err := cbor.Marshal(map[int64]any{
		1: int64(2), 3: int64(-7), -1: int64(1),
		-2: priv.PublicKey.X.Bytes(), -3: priv.PublicKey.Y.Bytes(),
	})
	require.NoError(t, err)
	return &webAuthnFixture{
		priv: priv, credID: credID, credIDText: base64.RawURLEncoding.EncodeToString(credID),
		cose: cose, counter: 1, rpID: "localhost", origin: "http://localhost:5173",
	}
}

func (f *webAuthnFixture) authData(attested bool, counter uint32) []byte {
	rpHash := sha256.Sum256([]byte(f.rpID))
	out := append([]byte{}, rpHash[:]...)
	flags := byte(0x01)
	if attested {
		flags |= 0x40
	}
	out = append(out, flags)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], counter)
	out = append(out, count[:]...)
	if attested {
		out = append(out, make([]byte, 16)...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(f.credID)))
		out = append(out, length[:]...)
		out = append(out, f.credID...)
		out = append(out, f.cose...)
	}
	return out
}

func (f *webAuthnFixture) registration(t *testing.T, challenge string) (string, string, string) {
	t.Helper()
	clientData, _ := json.Marshal(map[string]string{
		"type": "webauthn.create", "challenge": challenge, "origin": f.origin,
	})
	attestation, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{},
		"authData": f.authData(true, f.counter),
	})
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(attestation),
		base64.RawURLEncoding.EncodeToString(clientData), f.credIDText
}

func (f *webAuthnFixture) assertion(t *testing.T, challenge string, counter uint32) (string, string, string) {
	t.Helper()
	clientData, _ := json.Marshal(map[string]string{
		"type": "webauthn.get", "challenge": challenge, "origin": f.origin,
	})
	authData := f.authData(false, counter)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, digest[:])
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(authData),
		base64.RawURLEncoding.EncodeToString(clientData),
		base64.RawURLEncoding.EncodeToString(sig)
}

func registerPasskey(t *testing.T, h *harness, f *webAuthnFixture, challengeID, challenge string) {
	t.Helper()
	att, client, credID := f.registration(t, challenge)
	rec := h.do(http.MethodPost, "/api/v1/me/webauthn/credentials:confirm", map[string]any{
		"challenge_id": challengeID, "credential_id": credID,
		"attestation_object": att, "client_data_json": client,
		"transports": []string{"internal"}, "name": "测试 Passkey",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestWebAuthnFullLifecycle(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	f := newWebAuthnFixture(t)

	// Registration: attestation none, RP ID hash, challenge, origin.
	reg := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	require.Equal(t, "localhost", reg["rp_id"])
	registerPasskey(t, h, f, reg["challenge_id"].(string), reg["challenge"].(string))

	list := decode[map[string]any](t, h.do(http.MethodGet, "/api/v1/me/webauthn/credentials", nil, "", false))
	require.Len(t, list["items"], 1)
	credentialID := list["items"].([]any)[0].(map[string]any)["id"].(string)

	// A passkey is a second factor and satisfies the admin MFA policy.
	security := h.do(http.MethodGet, "/api/v1/me/security", nil, "", false)
	require.Equal(t, true, decode[map[string]any](t, security)["mfa_enabled"])

	// Assertion -> Step-up proof.
	assertChallenge := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/assertions:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	authData, clientData, sig := f.assertion(t, assertChallenge["challenge"].(string), 2)
	verified := h.do(http.MethodPost, "/api/v1/me/webauthn/assertions:verify", map[string]any{
		"challenge_id": assertChallenge["challenge_id"], "credential_id": f.credIDText,
		"authenticator_data": authData, "client_data_json": clientData,
		"signature": sig, "current_password": "ChangeMe-12345",
	}, "", true)
	require.Equal(t, http.StatusOK, verified.Code, verified.Body.String())
	require.Equal(t, true, decode[map[string]any](t, verified)["verified"])

	// Replaying the same challenge is rejected.
	replay := h.do(http.MethodPost, "/api/v1/me/webauthn/assertions:verify", map[string]any{
		"challenge_id": assertChallenge["challenge_id"], "credential_id": f.credIDText,
		"authenticator_data": authData, "client_data_json": clientData,
		"signature": sig, "current_password": "ChangeMe-12345",
	}, "", true)
	require.NotEqual(t, http.StatusOK, replay.Code)

	// sign_count regression is refused and audited.
	regressed := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/assertions:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	backAuth, backClient, backSig := f.assertion(t, regressed["challenge"].(string), 2)
	back := h.do(http.MethodPost, "/api/v1/me/webauthn/assertions:verify", map[string]any{
		"challenge_id": regressed["challenge_id"], "credential_id": f.credIDText,
		"authenticator_data": backAuth, "client_data_json": backClient,
		"signature": backSig, "current_password": "ChangeMe-12345",
	}, "", true)
	require.Equal(t, http.StatusConflict, back.Code)
	require.Contains(t, back.Body.String(), "WEBAUTHN_SIGN_COUNT_REGRESSION")

	// The last second factor cannot be removed without a replacement.
	last := h.do(http.MethodPost, "/api/v1/me/webauthn/credentials/"+credentialID+":delete",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true)
	require.Equal(t, http.StatusConflict, last.Code)
	require.Contains(t, last.Body.String(), "LAST_SECOND_FACTOR")

	// Login MFA can be satisfied by the passkey instead of TOTP.
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)
	login := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/auth/login",
		map[string]any{"username": "root", "password": "ChangeMe-12345"}, "", true))
	require.Equal(t, "mfa_required", login["status"])
	wa := login["webauthn"].(map[string]any)
	require.NotEmpty(t, wa["challenge"])
	authData, clientData, sig = f.assertion(t, wa["challenge"].(string), 3)
	completed := h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
		"challenge_id": login["challenge_id"], "credential_id": f.credIDText,
		"authenticator_data": authData, "client_data_json": clientData, "signature": sig,
	}, "", true)
	require.Equal(t, http.StatusOK, completed.Code, completed.Body.String())
	require.Equal(t, "authenticated", decode[map[string]any](t, completed)["status"])
}

func TestWebAuthnRejectsWrongOriginAndAttestationFormat(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	f := newWebAuthnFixture(t)
	reg := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))

	// Wrong origin in clientDataJSON.
	f.origin = "https://evil.example"
	att, client, credID := f.registration(t, reg["challenge"].(string))
	rec := h.do(http.MethodPost, "/api/v1/me/webauthn/credentials:confirm", map[string]any{
		"challenge_id": reg["challenge_id"], "credential_id": credID,
		"attestation_object": att, "client_data_json": client,
	}, "", true)
	require.NotEqual(t, http.StatusOK, rec.Code)

	// Non-"none" attestation is rejected on a fresh challenge.
	f.origin = "http://localhost:5173"
	reg2 := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "ChangeMe-12345"}, "", true))
	clientData, _ := json.Marshal(map[string]string{
		"type": "webauthn.create", "challenge": reg2["challenge"].(string), "origin": f.origin,
	})
	packed, err := cbor.Marshal(map[string]any{
		"fmt": "packed", "attStmt": map[string]any{}, "authData": f.authData(true, 1),
	})
	require.NoError(t, err)
	rec2 := h.do(http.MethodPost, "/api/v1/me/webauthn/credentials:confirm", map[string]any{
		"challenge_id": reg2["challenge_id"], "credential_id": f.credIDText,
		"attestation_object": base64.RawURLEncoding.EncodeToString(packed),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientData),
	}, "", true)
	require.Equal(t, http.StatusBadRequest, rec2.Code)
	require.True(t, strings.Contains(rec2.Body.String(), "attestation"))
}
