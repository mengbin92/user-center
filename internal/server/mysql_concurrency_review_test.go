package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/internal/service"
)

// lockGate parks the first LockUser caller until the test releases it and
// lets every later caller through. Two passkey completions of one user must
// still serialise on the user row: with the fix, the parked request has not
// read anything yet and sees the winner's session once released; without the
// early lock it has already pinned a pre-insert snapshot and overflows the
// cap. Blocking the first caller only works because the gate is fired before
// the racing request starts.
type lockGate struct {
	biz.UserRepo
	taken   atomic.Bool
	held    chan<- struct{}
	release <-chan struct{}
}

func (g *lockGate) LockUser(ctx context.Context, tx biz.Tx, id int64) error {
	if g.taken.CompareAndSwap(false, true) {
		g.held <- struct{}{}
		<-g.release
	}
	return g.UserRepo.LockUser(ctx, tx, id)
}

func TestMySQLPasskeyLoginSerialisesSessionCapOnUserRow(t *testing.T) {
	h := newMySQLHarness(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(data.IDs{}.NewID(), "-", "")
	user := iamFixtureUser(t, h, "cap-"+suffix[:12])

	settings, err := h.svc.Settings.GetAuth(ctx, nil)
	require.NoError(t, err)
	settings.MaxSessionsPerUser = 1
	_, err = h.svc.Settings.SaveAuth(ctx, nil, settings, settings.Revision)
	require.NoError(t, err)

	// One user, two independent credentials, so the two completions are the
	// real MFA path with real signature verification, not a replayed one.
	require.Equal(t, http.StatusOK, h.login(user.Username, "FixturePass-123").Code)
	fixA := newWebAuthnFixture(t)
	regA := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "FixturePass-123"}, "", true))
	registerPasskey(t, h, fixA, regA["challenge_id"].(string), regA["challenge"].(string))
	fixB := newWebAuthnFixture(t)
	regB := decode[map[string]any](t, h.do(http.MethodPost,
		"/api/v1/me/webauthn/credentials:challenge",
		map[string]any{"current_password": "FixturePass-123"}, "", true))
	registerPasskey(t, h, fixB, regB["challenge_id"].(string), regB["challenge"].(string))
	require.Equal(t, http.StatusOK, h.do(http.MethodPost, "/api/v1/auth/logout", nil, "", true).Code)

	// Two fresh logins: one MFA challenge each.
	loginA := decode[map[string]any](t, h.login(user.Username, "FixturePass-123"))
	require.Equal(t, "mfa_required", loginA["status"])
	loginB := decode[map[string]any](t, h.login(user.Username, "FixturePass-123"))
	require.Equal(t, "mfa_required", loginB["status"])

	held := make(chan struct{}, 1)
	release := make(chan struct{})
	h.svc.Users = &lockGate{UserRepo: h.svc.Users, held: held, release: release}

	complete := func(login map[string]any, fix *webAuthnFixture) *httptest.ResponseRecorder {
		wa := login["webauthn"].(map[string]any)
		authData, clientData, sig := fix.assertion(t, wa["challenge"].(string), 2)
		return h.do(http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{
			"challenge_id": login["challenge_id"], "credential_id": fix.credIDText,
			"authenticator_data": authData, "client_data_json": clientData, "signature": sig,
		}, "", true)
	}

	respA := make(chan *httptest.ResponseRecorder, 1)
	respB := make(chan *httptest.ResponseRecorder, 1)
	go func() { respB <- complete(loginB, fixB) }()
	<-held // B is parked before the user-row lock; A now owns the race
	go func() { respA <- complete(loginA, fixA) }()
	gotA := <-respA
	close(release)
	gotB := <-respB

	// Both completions are real logins: signatures verified, sessions issued.
	for _, rec := range []*httptest.ResponseRecorder{gotA, gotB} {
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, "authenticated", decode[map[string]any](t, rec)["status"])
	}
	// The loser reports the winner's recycled session.
	require.Equal(t, float64(1), decode[map[string]any](t, gotB)["recycled_sessions"])

	rows, err := h.svc.Sessions.ListByUser(ctx, nil, user.ID)
	require.NoError(t, err)
	now := time.Now().UTC()
	valid := map[string]bool{}
	var revoked []string
	for _, s := range rows {
		if s.Valid(now) {
			valid[s.ID] = true
		} else {
			revoked = append(revoked, s.ID)
		}
	}
	require.Len(t, valid, 1, "concurrent passkey logins must not exceed the cap")

	// The session that committed second is the live one; the first was evicted.
	idA := sessionIDByToken(rows, recorderSessionToken(t, gotA))
	idB := sessionIDByToken(rows, recorderSessionToken(t, gotB))
	require.Contains(t, valid, idB)
	require.Contains(t, revoked, idA)
	require.NotContains(t, revoked, idB)

	events, _, err := h.svc.Events.ListByUser(ctx, nil, user.ID, 100, "")
	require.NoError(t, err)
	evicted := 0
	for _, e := range events {
		if e.Kind == "session_evict" {
			evicted++
		}
	}
	require.Equal(t, 1, evicted, "exactly one session_evict security event")
}

func recorderSessionToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == service.SessionCookie {
			return c.Value
		}
	}
	t.Fatal("session cookie missing")
	return ""
}

func sessionIDByToken(rows []*biz.Session, token string) string {
	for _, s := range rows {
		if s.TokenHash == biz.HashToken(token) {
			return s.ID
		}
	}
	return ""
}

// policyTrace reports every PolicyRevision call's entry and return, so the
// test can tell a caller parked on the policy row lock (entry without return)
// from an unimpeded one. Two concurrent assignments only see such a parked
// caller when the production code takes the shared policy lock first.
type policyTrace struct {
	biz.PolicyRepo
	seq      atomic.Int64
	attempts chan<- int
	done     chan<- int
}

func (p *policyTrace) PolicyRevision(ctx context.Context, tx biz.Tx) (uint64, error) {
	n := int(p.seq.Add(1))
	select {
	case p.attempts <- n:
	default:
	}
	rev, err := p.PolicyRepo.PolicyRevision(ctx, tx)
	select {
	case p.done <- n:
	default:
	}
	return rev, err
}

// listGate parks the first ListAssignments caller right after its read until
// the test releases it; later callers pass. With the policy lock in place the
// second request never gets this far while the first is parked, so the
// requests serialise on the lock itself. Without it the second request reads
// the same pre-insert set and both checks pass.
type listGate struct {
	biz.OrgIAMRepo
	taken     atomic.Bool
	held      chan<- struct{}
	otherRead chan<- struct{}
	release   <-chan struct{}
}

func (g *listGate) ListAssignments(ctx context.Context, tx biz.Tx, scope authorization.Context, userID int64) ([]*biz.AssignmentItem, error) {
	items, err := g.OrgIAMRepo.ListAssignments(ctx, tx, scope, userID)
	if g.taken.CompareAndSwap(false, true) {
		select {
		case g.held <- struct{}{}:
		default:
		}
		<-g.release
	} else {
		select {
		case g.otherRead <- struct{}{}:
		default:
		}
	}
	return items, err
}

func TestMySQLOrgAssignRoleSerialisesMutualExclusionOnPolicyLock(t *testing.T) {
	h := newMySQLHarness(t)
	ctx := context.Background()
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	suffix := strings.ReplaceAll(data.IDs{}.NewID(), "-", "")[:12]

	orgID := orgByCode(t, h, "sodx-"+suffix)
	roleX := createOrgRole(t, h, orgID, "approver-"+suffix)
	roleY := createOrgRole(t, h, orgID, "payer-"+suffix)
	memberID := createOrgMemberForConstraint(t, h, orgID, "sodm-"+suffix)

	rec := h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/constraints", map[string]any{
		"kind": "mutual_exclusion", "name": "sodx-" + suffix,
		"role_ids": []string{roleX, roleY}, "enabled": true,
		"reason": "concurrency fixture", "expected_policy_revision": policyRevision(t, h),
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	held := make(chan struct{}, 1)
	otherRead := make(chan struct{}, 1)
	release := make(chan struct{})
	attempts := make(chan int, 16)
	done := make(chan int, 16)
	h.svc.Policy = &policyTrace{PolicyRepo: h.svc.Policy, attempts: attempts, done: done}
	h.svc.OrgIAM = &listGate{OrgIAMRepo: h.svc.OrgIAM, held: held, otherRead: otherRead, release: release}

	assign := func(roleID string) *httptest.ResponseRecorder {
		return h.do(http.MethodPost, "/api/v1/orgs/"+orgID+"/iam/assignments", map[string]any{
			"user_id": memberID, "role_id": roleID, "reason": "concurrent sod",
		}, "", true)
	}
	respA := make(chan *httptest.ResponseRecorder, 1)
	respB := make(chan *httptest.ResponseRecorder, 1)
	go func() { respA <- assign(roleX) }()
	go func() { respB <- assign(roleY) }()

	<-held // the first request read the member's set and is parked pre-insert
	// With the policy lock the other request is now parked on it (an entry
	// without a matching return). Without the lock it has already read the
	// same stale set, and releasing the first request must not rescue it.
	pending := map[int]bool{}
	timer := time.NewTimer(time.Second)
loop:
	for {
		select {
		case n := <-attempts:
			pending[n] = true
		case n := <-done:
			delete(pending, n)
		case <-otherRead:
			break loop
		case <-timer.C:
			if len(pending) == 0 {
				t.Fatal("no interleaving detected: second request neither read nor blocked on the policy lock")
			}
			break loop
		}
	}
	close(release)
	gotA, gotB := <-respA, <-respB

	codes := []int{gotA.Code, gotB.Code}
	require.Contains(t, codes, http.StatusOK, "one grant must commit: %s / %s", gotA.Body.String(), gotB.Body.String())
	require.Contains(t, codes, http.StatusConflict, "the other must hit the constraint: %s / %s", gotA.Body.String(), gotB.Body.String())
	conflict := gotA
	if gotA.Code == http.StatusOK {
		conflict = gotB
	}
	require.Contains(t, conflict.Body.String(), "ROLE_CONSTRAINT_VIOLATION")

	// The stored state must hold exactly the one committed assignment, and no
	// mutually exclusive pair may be present.
	orgInt, err := strconv.ParseInt(orgID, 10, 64)
	require.NoError(t, err)
	memberInt, err := strconv.ParseInt(memberID, 10, 64)
	require.NoError(t, err)
	items, err := h.svc.OrgIAM.ListAssignments(ctx, nil, authorization.Organization(orgInt), memberInt)
	require.NoError(t, err)
	// Adding the member already stored a membership-driven assignment to the
	// built-in member role; the SoD decision is about the explicit grants.
	explicit := 0
	heldIDs := make([]int64, 0, len(items))
	for _, item := range items {
		if item.Assignment != nil && !item.Assignment.Revoked {
			heldIDs = append(heldIDs, item.Assignment.RoleID)
			if item.Assignment.Origin == biz.OriginExplicit {
				explicit++
			}
		}
	}
	require.Equal(t, 1, explicit, "exactly one explicit assignment may be stored")
	constraints, err := h.svc.IAM.ListConstraints(ctx, nil, authorization.Organization(orgInt))
	require.NoError(t, err)
	require.NoError(t, biz.CheckConstraints(heldIDs, constraints))
}
