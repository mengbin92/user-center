package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeSnapshotRejectsAmbiguousOrUnsupportedCredentials(t *testing.T) {
	for _, raw := range []string{
		`{"source_commit":"4116899a","users":[],"users":[{"password_hash":"sensitive-hash"}]}`,
		`{"source_commit":"4116899a","users":[{"id":42,"mfa_enabled":true}]}`,
		`{"source_commit":"4116899a","users":[]} {"password_hash":"sensitive-hash"}`,
		`{"source_commit":"4116899a","users":[{"id":"sensitive-hash"}]}`,
		strings.Repeat(" ", (4<<20)+1),
	} {
		_, err := decodeSnapshot([]byte(raw))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "sensitive-hash")
	}
	spec, err := decodeSnapshot([]byte(`{"source_commit":"4116899a","users":[{"id":42,"username":"legacy"}]}`))
	require.NoError(t, err)
	require.EqualValues(t, 42, spec.Users[0].ID)
}
