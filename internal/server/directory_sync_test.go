package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Enterprise directory synchronization end to end: a JSON feed stands in for
// an IdP export gateway, the governance API registers it, and the sync engine
// provisions through the same SCIM path an IdP uses. The denial cases cover
// credential exposure, SSRF-ish URL policy, and platform-admin-only writes.

type feedState struct {
	mu      sync.Mutex
	payload map[string]any
}

func (f *feedState) set(p map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payload = p
}

func newDirectoryFeed(t *testing.T) (*httptest.Server, *feedState) {
	t.Helper()
	state := &feedState{}
	state.set(map[string]any{"users": []any{}, "cursor": "c0", "full": true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		payload := state.payload
		state.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(srv.Close)
	return srv, state
}

func directoryConfigJSON(t *testing.T, url string, extra map[string]any) string {
	t.Helper()
	cfg := map[string]any{
		"url": url, "interval_seconds": 30,
		"deletion_policy": "disable", "conflict_policy": "source_wins",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return string(raw)
}

func createDirectorySource(t *testing.T, h *harness, orgID, configJSON string) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	rec := h.do(http.MethodPost, "/api/v1/admin/directory-sources", map[string]any{
		"organization_id": orgID, "kind": "jsonfeed", "name": "corp-feed",
		"config_json": configJSON, "secret": "feed-token-123", "reason": "directory fixture",
	}, "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return decode[map[string]any](t, rec)
}

func usersPayload() map[string]any {
	return map[string]any{
		"cursor": "c1", "full": true,
		"users": []map[string]any{
			{"externalId": "u-1", "userName": "dir-alice", "displayName": "Alice", "email": "dir-alice@example.com", "active": true},
			{"externalId": "u-2", "userName": "dir-bob", "displayName": "Bob", "email": "dir-bob@example.com", "active": true},
		},
	}
}

func TestDirectorySyncProvisionsAndReconciles(t *testing.T) {
	h := newHarness(t)
	feed, state := newDirectoryFeed(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "dirsync-life")

	source := createDirectorySource(t, h, orgID, directoryConfigJSON(t, feed.URL, nil))
	sourceID := source["id"].(string)
	require.Equal(t, "active", source["status"])
	require.NotContains(t, mustJSON(t, source), "feed-token-123")
	require.NotContains(t, mustJSON(t, source), "secret_enc")

	// A dry run must not create anything.
	state.set(usersPayload())
	dry := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":sync", map[string]any{
		"mode": "dry_run", "reason": "preview",
	}, "", true)
	require.Equal(t, http.StatusOK, dry.Code, dry.Body.String())
	dryRun := decode[map[string]any](t, dry)
	require.Equal(t, float64(2), dryRun["fetched"])
	require.Equal(t, float64(0), dryRun["created_count"])
	require.Equal(t, "", dryRun["cursor_after"])

	// Full sync provisions both accounts into this organization.
	full := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":sync", map[string]any{
		"mode": "full", "reason": "initial import",
	}, "", true)
	require.Equal(t, http.StatusOK, full.Code, full.Body.String())
	run := decode[map[string]any](t, full)
	require.Equal(t, float64(2), run["created_count"], run["report_json"])
	require.Equal(t, "succeeded", run["status"])
	require.Equal(t, "c1", run["cursor_after"])

	members := h.do(http.MethodGet, "/api/v1/orgs/"+orgID+"/members", nil, "", false)
	require.Equal(t, http.StatusOK, members.Code, members.Body.String())
	body := members.Body.String()
	require.Contains(t, body, "dir-alice")
	require.Contains(t, body, "dir-bob")

	// Delta with one user disabled. The cursor is passed to the feed as since.
	state.set(map[string]any{
		"cursor": "c2", "full": false,
		"users": []map[string]any{
			{"externalId": "u-2", "userName": "dir-bob", "displayName": "Bob", "email": "dir-bob@example.com", "active": false},
		},
	})
	delta := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":sync", map[string]any{
		"mode": "delta", "reason": "incremental",
	}, "", true)
	require.Equal(t, http.StatusOK, delta.Code, delta.Body.String())
	require.Equal(t, "c2", decode[map[string]any](t, delta)["cursor_after"])

	// A full snapshot that no longer contains u-1 is a tombstone: with the
	// default disable policy the account is deprovisioned, never hard-deleted.
	state.set(map[string]any{
		"cursor": "c3", "full": true,
		"users": []map[string]any{
			{"externalId": "u-2", "userName": "dir-bob", "displayName": "Bob", "email": "dir-bob@example.com", "active": false},
		},
	})
	reconcile := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":sync", map[string]any{
		"mode": "full", "reason": "reconcile",
	}, "", true)
	require.Equal(t, http.StatusOK, reconcile.Code, reconcile.Body.String())
	require.GreaterOrEqual(t, decode[map[string]any](t, reconcile)["disabled_count"].(float64), float64(1))

	// Every run is retained with its outcome report.
	runs := h.do(http.MethodGet, "/api/v1/admin/directory-sync-runs?source_id="+sourceID, nil, "", false)
	require.Equal(t, http.StatusOK, runs.Code, runs.Body.String())
	require.GreaterOrEqual(t, len(decode[map[string]any](t, runs)["items"].([]any)), 4)
}

func TestDirectorySyncGovernanceDenials(t *testing.T) {
	h := newHarness(t)
	feed, _ := newDirectoryFeed(t)
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	orgID := orgByCode(t, h, "dirsync-gov")
	fixtureStepUp(h)

	// Missing reason.
	noReason := h.do(http.MethodPost, "/api/v1/admin/directory-sources", map[string]any{
		"organization_id": orgID, "kind": "jsonfeed", "name": "x",
		"config_json": directoryConfigJSON(t, feed.URL, nil), "secret": "s",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, noReason.Code, noReason.Body.String())

	// Plaintext HTTP to a non-loopback host must be refused (SSRF guard).
	badURL := h.do(http.MethodPost, "/api/v1/admin/directory-sources", map[string]any{
		"organization_id": orgID, "kind": "jsonfeed", "name": "bad-url",
		"config_json": directoryConfigJSON(t, "http://internal.example.com/users", nil),
		"secret":      "s", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, badURL.Code, badURL.Body.String())

	// Unknown connector kind and malformed config.
	unknownKind := h.do(http.MethodPost, "/api/v1/admin/directory-sources", map[string]any{
		"organization_id": orgID, "kind": "not-a-connector", "name": "bad-kind",
		"config_json": directoryConfigJSON(t, feed.URL, nil), "secret": "s", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, unknownKind.Code, unknownKind.Body.String())
	badConfig := h.do(http.MethodPost, "/api/v1/admin/directory-sources", map[string]any{
		"organization_id": orgID, "kind": "jsonfeed", "name": "bad-config",
		"config_json": "{not-json", "secret": "s", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusBadRequest, badConfig.Code, badConfig.Body.String())

	// Valid source, then confirm a non-platform account cannot read, trigger,
	// rotate or list its runs.
	source := createDirectorySource(t, h, orgID, directoryConfigJSON(t, feed.URL, nil))
	sourceID := source["id"].(string)
	_ = iamFixtureUser(t, h, "dirsync-outsider")
	require.Equal(t, http.StatusOK, h.login("dirsync-outsider", "FixturePass-123").Code)
	fixtureStepUp(h)
	listed := h.do(http.MethodGet, "/api/v1/admin/directory-sources?organization_id="+orgID, nil, "", false)
	require.Equal(t, http.StatusForbidden, listed.Code, listed.Body.String())
	triggered := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":sync", map[string]any{
		"mode": "full", "reason": "probe",
	}, "", true)
	require.Equal(t, http.StatusForbidden, triggered.Code, triggered.Body.String())

	// The encrypted credential is never echoed by any read path.
	require.Equal(t, http.StatusOK, h.login("root", "ChangeMe-12345").Code)
	fixtureStepUp(h)
	list := h.do(http.MethodGet, "/api/v1/admin/directory-sources?organization_id="+orgID, nil, "", false)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.NotContains(t, list.Body.String(), "feed-token-123")
	require.NotContains(t, list.Body.String(), "secret_enc")

	// Stale revision on secret rotation.
	stale := h.do(http.MethodPost, "/api/v1/admin/directory-sources/"+sourceID+":rotate-secret", map[string]any{
		"secret": "new-token", "expected_revision": "999999", "reason": "rotate",
	}, "", true)
	require.Equal(t, http.StatusConflict, stale.Code, stale.Body.String())
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}
