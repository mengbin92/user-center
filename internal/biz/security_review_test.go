package biz

import (
	"regexp"
	"strings"
	"testing"

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
	require.ErrorIs(t, ValidatePassword(strings.Repeat("密", 9), 10), ErrValidation)
	require.NoError(t, ValidatePassword(strings.Repeat("密", 10), 10))
	require.NoError(t, ValidatePassword(strings.Repeat("a", 72), 10))
	require.ErrorIs(t, ValidatePassword(strings.Repeat("a", 73), 10), ErrValidation)
	require.ErrorIs(t, ValidatePassword(strings.Repeat("密", 25), 10), ErrValidation)
}
