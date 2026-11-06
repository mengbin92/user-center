package biz

import (
	"regexp"
	"strings"
	"testing"
	"time"

	kerrors "github.com/go-kratos/kratos/v3/errors"
	"github.com/stretchr/testify/require"
)

func TestRecoveryCodesUseUnambiguousRedeemableAlphabet(t *testing.T) {
	for range 20 {
		codes, hashes, err := generateRecoveryCodes()
		require.NoError(t, err)
		require.Len(t, codes, 8)
		for i, code := range codes {
			require.Regexp(t, regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}$`), code)
			require.Equal(t, hashes[i], HashToken(strings.ReplaceAll(code, "-", "")))
		}
	}
}

func TestPasswordLengthMatchesBcryptBytes(t *testing.T) {
	policy := PasswordPolicy{MinLength: 10}
	// Length is counted in runes but the bcrypt ceiling is bytes: 25 Chinese
	// characters are 75 bytes and must be rejected even though the rune count
	// passes.
	requirePasswordPolicyViolation(t, ValidatePassword(strings.Repeat("密", 9), policy))
	require.NoError(t, ValidatePassword(strings.Repeat("密", 10), policy))
	require.NoError(t, ValidatePassword(strings.Repeat("a", 72), policy))
	requirePasswordPolicyViolation(t, ValidatePassword(strings.Repeat("a", 73), policy))
	requirePasswordPolicyViolation(t, ValidatePassword(strings.Repeat("密", 25), policy))
}

func TestPasswordCompositionRule(t *testing.T) {
	three := PasswordPolicy{MinLength: 8, MinClasses: 3}
	cases := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"lowercase only fails", "abcdefghij", true},
		{"two classes fail", "abcdefgh12", true},
		{"three classes pass", "abcdefgh1!", false},
		{"all four classes pass", "Abcdefgh1!", false},
		// Digits plus symbols is only two classes: the rule counts classes, not
		// "looks complicated".
		{"digits and symbols are two classes", "12345678!@#$", true},
		// Non-ASCII letters carry no class of their own, so a Chinese passphrase
		// still needs punctuation or a digit; it is never silently rejected for
		// being non-English, only for missing classes.
		{"non-ascii letters plus digit plus symbol is two classes", "密码密码密码1！", true},
		{"non-ascii letters plus ascii letters plus digit pass", "密码密码Abcd123", false},
		{"non-ascii letters only fail", "密码密码密码密码", true},
		// A space is not a symbol; trailing spaces are rejected outright.
		{"space between words is not a class", "correct horse battery", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.pw, three)
			if tc.wantErr {
				requirePasswordPolicyViolation(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// A zero MinClasses must accept a long lowercase passphrase: that is the
// documented escape hatch for teams that rely on length instead of composition.
func TestPasswordCompositionDisabledAcceptsPassphrase(t *testing.T) {
	require.NoError(t, ValidatePassword("correct horse battery staple", PasswordPolicy{MinLength: 12}))
}

func TestPasswordExpiry(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	policy := PasswordPolicy{ExpiryDays: 90}

	require.False(t, PasswordExpired(time.Time{}, policy, now), "unknown age must never count as expired")
	require.False(t, PasswordExpired(now.AddDate(0, 0, -89), policy, now))
	require.True(t, PasswordExpired(now.AddDate(0, 0, -91), policy, now))
	require.False(t, PasswordExpired(now.AddDate(0, 0, -365), PasswordPolicy{}, now), "0 days disables expiry")
}

// requirePasswordPolicyViolation asserts the stable error code the web form
// switches on. Asserting the message would make the rule unchangeable.
func requirePasswordPolicyViolation(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var kerr *kerrors.Error
	require.ErrorAs(t, err, &kerr)
	require.Equal(t, "PASSWORD_POLICY_VIOLATION", kerr.Reason)
}
