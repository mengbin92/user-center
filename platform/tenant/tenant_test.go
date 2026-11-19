package tenant

import (
	"math"
	"testing"
)

func TestFromPath(t *testing.T) {
	for path, want := range map[string]int64{
		"/api/v1/orgs/+42":                          42,
		"/api/v1/orgs/9223372036854775807/sessions": math.MaxInt64,
		"/api/v1/orgs/9223372036854775808/members":  0,
		"/api/v1/orgs/46116860184273879049/members": 0,
		"/arbitrary/api/v1/orgs/42/members":         0,
		"/api/v1/orgs/42?unexpected/members":        0,
		"/api/v1/orgs/invitations:accept":           0,
	} {
		if got := FromPath(path); got != want {
			t.Errorf("FromPath(%q) = %d, want %d", path, got, want)
		}
	}
}
