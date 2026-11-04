package biz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateClientCallbackURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https public", "https://hooks.example.com/events", false},
		{"http loopback for development", "http://127.0.0.1:9099/events", false},
		{"http localhost", "http://localhost:9099/events", false},
		{"plain http public", "http://hooks.example.com/events", true},
		{"link local metadata", "http://169.254.169.254/latest/meta-data", true},
		{"link local https", "https://169.254.169.254/latest/meta-data", true},
		{"user info", "https://user:pass@example.com/hook", true},
		{"fragment", "https://example.com/hook#frag", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClient(&IntegrationClient{
				Code: "svc", ServiceOwner: "billing",
				AllowedMethods: []string{"GetUser"},
				CallbackURL:    tc.url,
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
