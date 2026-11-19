package biz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// WebAuthn registration and Step-up require primary authentication.
// Attestation is restricted to "none" so no certificate chain is stored.

const (
	WebAuthnRegisterPurpose = "webauthn_register"
	WebAuthnAssertPurpose   = "webauthn_assert"

	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttestedData = 0x40
)

type WebAuthnAssertion struct {
	ChallengeID       string
	CredentialID      string
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

type WebAuthnRegistrationChallenge struct {
	ChallengeID           string
	Challenge             string
	RPID                  string
	RPName                string
	UserID                string
	UserName              string
	ExpiresAt             time.Time
	ExistingCredentialIDs []string
}

type WebAuthnAssertionChallenge struct {
	ChallengeID        string
	Challenge          string
	RPID               string
	AllowCredentialIDs []string
	ExpiresAt          time.Time
}

type webAuthnChallengePayload struct {
	Challenge       string `json:"challenge"`
	UserID          string `json:"user_id"`
	IdentityVersion string `json:"identity_version"`
	SessionID       string `json:"session_id"`
	RPID            string `json:"rp_id"`
	Origin          string `json:"origin"`
}

func (s *Services) webAuthnRP() (string, string, error) {
	u, err := url.Parse(s.PublicBaseURL)
	if err != nil || u.Hostname() == "" {
		return "", "", ErrDependency
	}
	origin := u.Scheme + "://" + u.Host
	return u.Hostname(), origin, nil
}

func (uc *WebAuthnUsecase) newChallenge(ctx context.Context, actor ActorContext, purpose string) (string, string, time.Time, error) {
	rpID, origin, err := uc.webAuthnRP()
	if err != nil {
		return "", "", time.Time{}, err
	}
	raw, err := newToken(32)
	if err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(5 * time.Minute)
	payload, _ := jsonx.Marshal(webAuthnChallengePayload{
		Challenge: raw, UserID: itoa(actor.User.ID),
		IdentityVersion: uitoa(actor.User.IdentityVersion), SessionID: actor.Session.ID,
		RPID: rpID, Origin: origin,
	})
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: purpose, Payload: string(payload), UserID: actor.User.ID, ExpiresAt: expires,
	}); err != nil {
		return "", "", time.Time{}, ErrDependency
	}
	return id, raw, expires, nil
}

func (uc *WebAuthnUsecase) loadChallenge(ctx context.Context, actor ActorContext, purpose, id string) (webAuthnChallengePayload, Challenge, error) {
	var payload webAuthnChallengePayload
	c, err := uc.Challenges.Get(ctx, purpose, id)
	if err != nil {
		return payload, c, ErrChallengeInvalid
	}
	if jsonx.Unmarshal([]byte(c.Payload), &payload) != nil || payload.UserID != itoa(actor.User.ID) ||
		payload.IdentityVersion != uitoa(actor.User.IdentityVersion) {
		return payload, c, ErrChallengeInvalid
	}
	if payload.SessionID != "" && payload.SessionID != actor.Session.ID {
		return payload, c, ErrChallengeInvalid
	}
	rpID, origin, err := uc.webAuthnRP()
	if err != nil || payload.RPID != rpID || payload.Origin != origin {
		return payload, c, ErrChallengeInvalid
	}
	return payload, c, nil
}

func (uc *WebAuthnUsecase) RegistrationChallenge(ctx context.Context, actor ActorContext, password string) (*WebAuthnRegistrationChallenge, error) {
	if err := uc.confirmPrimaryAuthentication(ctx, actor, password); err != nil {
		return nil, err
	}
	rpID, _, err := uc.webAuthnRP()
	if err != nil {
		return nil, err
	}
	id, raw, expires, err := uc.newChallenge(ctx, actor, WebAuthnRegisterPurpose)
	if err != nil {
		return nil, err
	}
	creds, err := uc.WebAuthn.ListByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	existing := make([]string, 0, len(creds))
	for _, c := range creds {
		existing = append(existing, c.CredentialID)
	}
	return &WebAuthnRegistrationChallenge{
		ChallengeID: id, Challenge: raw, RPID: rpID, RPName: "用户中心",
		UserID: itoa(actor.User.ID), UserName: actor.User.Username,
		ExpiresAt: expires, ExistingCredentialIDs: existing,
	}, nil
}

func (uc *WebAuthnUsecase) ConfirmRegistration(ctx context.Context, actor ActorContext, in WebAuthnRegistrationInput) (*WebAuthnCredential, error) {
	payload, _, err := uc.loadChallenge(ctx, actor, WebAuthnRegisterPurpose, in.ChallengeID)
	if err != nil {
		return nil, err
	}
	cred, err := parseAttestation(in.AttestationObject, in.ClientDataJSON, in.CredentialID, payload)
	if err != nil {
		return nil, err
	}
	cred.UserID = actor.User.ID
	cred.Name = strings.TrimSpace(in.Name)
	if cred.Name == "" {
		cred.Name = "Passkey"
	}
	cred.Transports = in.Transports
	var created *WebAuthnCredential
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.lockUserGeneration(ctx, tx, actor.User.ID, actor.Session.IdentityVersion); err != nil {
			return err
		}
		if err := uc.Flows.Complete(ctx, tx, in.ChallengeID, WebAuthnRegisterPurpose, actor.User.ID, "webauthn_credential"); err != nil {
			return ErrChallengeInvalid
		}
		row, err := uc.WebAuthn.Create(ctx, tx, cred)
		if err != nil {
			return err
		}
		created = row
		version, err := uc.refreshCredentialSessions(ctx, tx, actor)
		if err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "credential.webauthn.register", itoa(row.ID), "{}", "{}", "{}", "self-service passkey registration", "success"); err != nil {
			return err
		}
		payload := string(mustJSON(map[string]any{"user_id": actor.User.ID, "identity_version": version}))
		return uc.emit(ctx, tx, "user", actor.User.ID, version, "credential.changed", payload)
	})
	if err != nil {
		return nil, err
	}
	_ = uc.Challenges.Delete(ctx, WebAuthnRegisterPurpose, in.ChallengeID)
	return created, nil
}

type WebAuthnRegistrationInput struct {
	ChallengeID       string
	CredentialID      string
	AttestationObject []byte
	ClientDataJSON    []byte
	Transports        []string
	Name              string
}

func (uc *WebAuthnUsecase) List(ctx context.Context, actor ActorContext) ([]*WebAuthnCredential, error) {
	creds, err := uc.WebAuthn.ListByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	return creds, nil
}

func (uc *WebAuthnUsecase) Delete(ctx context.Context, actor ActorContext, id int64, password string) error {
	if err := uc.confirmPrimaryAuthentication(ctx, actor, password); err != nil {
		return err
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.lockUserGeneration(ctx, tx, actor.User.ID, actor.Session.IdentityVersion); err != nil {
			return err
		}
		if _, err := uc.WebAuthn.Get(ctx, tx, actor.User.ID, id); err != nil {
			if errors.Is(err, ErrResourceNotFound) {
				return err
			}
			return ErrDependency
		}
		creds, err := uc.WebAuthn.ListByUser(ctx, tx, actor.User.ID)
		if err != nil {
			return ErrDependency
		}
		state, err := uc.MFA.Get(ctx, tx, actor.User.ID)
		if err != nil && !errors.Is(err, ErrResourceNotFound) {
			return ErrDependency
		}
		if (state == nil || !state.Enabled()) && len(creds) <= 1 {
			return ConflictCode("LAST_SECOND_FACTOR", "删除最后一个第二因素前请先绑定替代方式")
		}
		if err := uc.WebAuthn.Delete(ctx, tx, actor.User.ID, id); err != nil {
			return err
		}
		version, err := uc.refreshCredentialSessions(ctx, tx, actor)
		if err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "credential.webauthn.delete", itoa(id), "{}", "{}", "{}", "self-service passkey removal", "success"); err != nil {
			return err
		}
		payload := string(mustJSON(map[string]any{"user_id": actor.User.ID, "identity_version": version}))
		return uc.emit(ctx, tx, "user", actor.User.ID, version, "credential.changed", payload)
	})
}

func (uc *WebAuthnUsecase) AssertionChallenge(ctx context.Context, actor ActorContext, password string) (*WebAuthnAssertionChallenge, error) {
	if err := uc.confirmPrimaryAuthentication(ctx, actor, password); err != nil {
		return nil, err
	}
	creds, err := uc.WebAuthn.ListByUser(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrDependency
	}
	if len(creds) == 0 {
		return nil, Validation("尚未绑定 WebAuthn 凭据")
	}
	rpID, _, err := uc.webAuthnRP()
	if err != nil {
		return nil, err
	}
	id, raw, expires, err := uc.newChallenge(ctx, actor, WebAuthnAssertPurpose)
	if err != nil {
		return nil, err
	}
	allow := make([]string, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, c.CredentialID)
	}
	return &WebAuthnAssertionChallenge{
		ChallengeID: id, Challenge: raw, RPID: rpID,
		AllowCredentialIDs: allow, ExpiresAt: expires,
	}, nil
}

// VerifyAssertion validates a passkey assertion and, when stepUp is true,
// promotes it to a session-bound Step-up proof.
func (uc *WebAuthnUsecase) VerifyAssertion(ctx context.Context, actor ActorContext, in WebAuthnAssertion, password string, stepUp bool) (time.Time, error) {
	if stepUp {
		if err := uc.confirmPrimaryAuthentication(ctx, actor, password); err != nil {
			return time.Time{}, err
		}
	}
	payload, _, err := uc.loadChallenge(ctx, actor, WebAuthnAssertPurpose, in.ChallengeID)
	if err != nil {
		return time.Time{}, err
	}
	now := uc.Clock.Now().UTC()
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.Flows.Complete(ctx, tx, in.ChallengeID, WebAuthnAssertPurpose, actor.User.ID, "webauthn_assertion"); err != nil {
			return ErrChallengeInvalid
		}
		return uc.verifyWebAuthnAssertion(ctx, tx, actor.User.ID, payload.Challenge, in, now, false)
	})
	if err != nil {
		return time.Time{}, uc.webAuthnAssertionError(ctx, actor, err)
	}
	_ = uc.Challenges.Delete(ctx, WebAuthnAssertPurpose, in.ChallengeID)
	var until time.Time
	if stepUp {
		until = uc.Clock.Now().Add(uc.StepUpTTL)
		if err := uc.StepUp.Put(ctx, StepUpKey(actor.Session), until); err != nil {
			return time.Time{}, ErrDependency
		}
	}
	uc.recordSecurity(ctx, actor.User.ID, actor.Session.ID, "webauthn_assert", "success", actor.IP, actor.UserAgent, actor.RequestID)
	return until, nil
}

func (s *Services) verifyWebAuthnAssertion(ctx context.Context, tx Tx, userID int64, challenge string, in WebAuthnAssertion, now time.Time, requireUV bool) error {
	rpID, origin, err := s.webAuthnRP()
	if err != nil {
		return ErrDependency
	}
	if err := verifyClientData(in.ClientDataJSON, challenge, "webauthn.get", origin); err != nil {
		return err
	}
	counter, err := parseAuthenticatorData(in.AuthenticatorData, rpID, requireUV)
	if err != nil {
		return err
	}
	cred, err := s.WebAuthn.GetByCredentialID(ctx, tx, in.CredentialID)
	if err != nil {
		return ErrChallengeInvalid
	}
	if cred.UserID != userID {
		return ErrChallengeInvalid
	}
	clientHash := sha256.Sum256(in.ClientDataJSON)
	signed := append(append([]byte{}, in.AuthenticatorData...), clientHash[:]...)
	if err := verifyCOSESignature(cred.PublicKey, signed, in.Signature); err != nil {
		return ErrChallengeInvalid
	}
	if cred.SignCount > 0 && counter <= cred.SignCount {
		return &webAuthnCounterRegression{credentialID: cred.ID, stored: cred.SignCount, observed: counter}
	}
	return s.WebAuthn.UpdateSignCount(ctx, tx, cred.ID, counter, &now, cred.Revision)
}

type webAuthnCounterRegression struct {
	credentialID     int64
	stored, observed uint32
}

func (*webAuthnCounterRegression) Error() string { return "WebAuthn authenticator counter regression" }

func (s *Services) webAuthnAssertionError(ctx context.Context, actor ActorContext, err error) error {
	var regression *webAuthnCounterRegression
	if !errors.As(err, &regression) {
		return err
	}
	// Record the rejection after rollback, when the write connection is free.
	sessionID := ""
	if actor.Session != nil {
		sessionID = actor.Session.ID
	}
	s.recordSecurity(ctx, actor.User.ID, sessionID, "webauthn_sign_count_regression", "failure", actor.IP, actor.UserAgent, actor.RequestID)
	_ = s.audit(ctx, nil, actor, "credential.webauthn.sign_count_regression", itoa(regression.credentialID),
		string(mustJSON(map[string]any{"stored": regression.stored, "observed": regression.observed})), "{}", "{}",
		"authenticator counter regression", "denied")
	return ConflictCode("WEBAUTHN_SIGN_COUNT_REGRESSION", "认证器计数器回退，已拒绝")
}

// --- wire parsing / signature verification ---

func verifyClientData(raw []byte, challenge, expectedType, origin string) error {
	var data struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if jsonx.Unmarshal(raw, &data) != nil || data.Type != expectedType || data.Origin != origin || data.CrossOrigin {
		return ErrChallengeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(data.Challenge), []byte(challenge)) != 1 {
		return ErrChallengeInvalid
	}
	return nil
}

func parseAuthenticatorData(raw []byte, rpID string, requireUV bool) (uint32, error) {
	if len(raw) < 37 {
		return 0, ErrChallengeInvalid
	}
	expected := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(raw[:32], expected[:]) != 1 {
		return 0, ErrChallengeInvalid
	}
	if raw[32]&flagUserPresent == 0 || requireUV && raw[32]&flagUserVerified == 0 {
		return 0, ErrChallengeInvalid
	}
	return binary.BigEndian.Uint32(raw[33:37]), nil
}

func parseAttestation(attestationObject, clientDataJSON []byte, credentialID string, payload webAuthnChallengePayload) (*WebAuthnCredential, error) {
	if err := verifyClientData(clientDataJSON, payload.Challenge, "webauthn.create", payload.Origin); err != nil {
		return nil, err
	}
	var att struct {
		Fmt      string          `cbor:"fmt"`
		AuthData []byte          `cbor:"authData"`
		AttStmt  cbor.RawMessage `cbor:"attStmt"`
	}
	if cbor.Unmarshal(attestationObject, &att) != nil || att.Fmt != "none" {
		return nil, Validation("仅支持 attestation none")
	}
	// "none" attestation has an empty attStmt map.
	if len(att.AttStmt) > 0 && !bytes.Equal(att.AttStmt, []byte{0xa0}) {
		return nil, Validation("attStmt 必须为空")
	}
	auth := att.AuthData
	if len(auth) < 55 || auth[32]&flagUserPresent == 0 || auth[32]&flagAttestedData == 0 {
		return nil, ErrChallengeInvalid
	}
	rpHash := sha256.Sum256([]byte(payload.RPID))
	if subtle.ConstantTimeCompare(auth[:32], rpHash[:]) != 1 {
		return nil, ErrChallengeInvalid
	}
	rest := auth[37:]
	aaguid := hex.EncodeToString(rest[:16])
	credLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if credLen <= 0 || len(rest) < credLen {
		return nil, ErrChallengeInvalid
	}
	rawID := base64.RawURLEncoding.EncodeToString(rest[:credLen])
	if rawID != credentialID {
		return nil, ErrChallengeInvalid
	}
	cose := rest[credLen:]
	var probe map[int64]cbor.RawMessage
	remaining, err := cbor.UnmarshalFirst(cose, &probe)
	if err != nil || len(cose)-len(remaining) == 0 {
		return nil, ErrChallengeInvalid
	}
	publicKey := cose[:len(cose)-len(remaining)]
	// The key must be usable before it is stored.
	if !coseKeySupported(probe) {
		return nil, Validation("不支持的凭据公钥算法")
	}
	return &WebAuthnCredential{
		CredentialID: rawID, PublicKey: publicKey, AAGUID: aaguid,
		SignCount: binary.BigEndian.Uint32(auth[33:37]),
	}, nil
}

func coseKeySupported(m map[int64]cbor.RawMessage) bool {
	var kty, alg int64
	if cbor.Unmarshal(m[1], &kty) != nil || cbor.Unmarshal(m[3], &alg) != nil {
		return false
	}
	return kty == 2 && alg == -7 || kty == 3 && alg == -257
}

func verifyCOSESignature(cose, signed, signature []byte) error {
	var m map[int64]cbor.RawMessage
	if cbor.Unmarshal(cose, &m) != nil {
		return ErrChallengeInvalid
	}
	var kty, alg int64
	if cbor.Unmarshal(m[1], &kty) != nil || cbor.Unmarshal(m[3], &alg) != nil {
		return ErrChallengeInvalid
	}
	digest := sha256.Sum256(signed)
	switch {
	case kty == 2 && alg == -7: // ES256 / P-256
		var crv int64
		var x, y []byte
		if cbor.Unmarshal(m[-1], &crv) != nil || crv != 1 ||
			cbor.Unmarshal(m[-2], &x) != nil || cbor.Unmarshal(m[-3], &y) != nil || len(x) == 0 || len(y) == 0 {
			return ErrChallengeInvalid
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) || !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return ErrChallengeInvalid
		}
		return nil
	case kty == 3 && alg == -257: // RS256
		var n, e []byte
		if cbor.Unmarshal(m[-1], &n) != nil || cbor.Unmarshal(m[-2], &e) != nil || len(n) == 0 || len(e) == 0 {
			return ErrChallengeInvalid
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.E < 3 || rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) != nil {
			return ErrChallengeInvalid
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported COSE key", ErrChallengeInvalid)
	}
}

// HasSecondFactor reports whether an account has any enrolled second factor;
// WebAuthn credentials satisfy the admin MFA policy alongside TOTP.
func (s *Services) HasSecondFactor(ctx context.Context, userID int64) bool {
	return s.hasSecondFactorInTx(ctx, nil, userID)
}

func (s *Services) hasSecondFactorInTx(ctx context.Context, tx Tx, userID int64) bool {
	if state, err := s.MFA.Get(ctx, tx, userID); err == nil && state != nil && state.Enabled() {
		return true
	}
	enrolled, _ := s.hasPasskeyInTx(ctx, tx, userID)
	return enrolled
}

func (s *Services) hasPasskey(ctx context.Context, userID int64) (bool, error) {
	return s.hasPasskeyInTx(ctx, nil, userID)
}

func (s *Services) hasPasskeyInTx(ctx context.Context, tx Tx, userID int64) (bool, error) {
	if s.WebAuthn == nil {
		return false, nil
	}
	creds, err := s.WebAuthn.ListByUser(ctx, tx, userID)
	if err != nil {
		return false, ErrDependency
	}
	return len(creds) > 0, nil
}
