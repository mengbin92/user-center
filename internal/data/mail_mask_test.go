package data

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskEmailKeepsDomainOnly(t *testing.T) {
	cases := map[string]string{
		"alice@example.com":   "a***@example.com",
		"a@b.co":              "a***@b.co",
		"ALICE@Example.COM":   "A***@Example.COM",
		"no-at-sign":          "***",
		"@example.com":        "***",
		"alice@":              "***",
		"alice@example.com\n": "***",
		"":                    "***",
	}
	for input, want := range cases {
		require.Equal(t, want, maskEmail(input), "input %q", input)
	}
}

// mail logs must not become a second copy of the users table: whatever the
// shape of the address, the local part is never written out.
func TestMaskEmailNeverLeaksLocalPart(t *testing.T) {
	for _, address := range []string{
		"root@example.com",
		"bench01@bench.local",
		"very.long.local.part+tag@sub.example.com",
	} {
		masked := maskEmail(address)
		require.NotContains(t, masked, "root")
		require.NotContains(t, masked, "bench01")
		require.NotContains(t, masked, "very.long")
		require.Contains(t, masked, "@", "the domain stays readable for triage")
	}
}
