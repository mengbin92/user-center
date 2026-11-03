package biz

import (
	"testing"

	"github.com/mengbin92/user-center/pkg/jsonx"
	"github.com/stretchr/testify/require"
)

func TestEventIdentifiersAndVersionsNeverPassThroughFloat64(t *testing.T) {
	wire, err := eventWirePayload(`{"user_id":9007199254740993,"identity_version":18446744073709551615,"role_ids":[9007199254740993,2],"status":"enabled"}`)
	require.NoError(t, err)
	var payload struct {
		UserID          string   `json:"user_id"`
		IdentityVersion string   `json:"identity_version"`
		RoleIDs         []string `json:"role_ids"`
		Status          string   `json:"status"`
	}
	require.NoError(t, jsonx.Unmarshal([]byte(wire), &payload))
	require.Equal(t, "9007199254740993", payload.UserID)
	require.Equal(t, "18446744073709551615", payload.IdentityVersion)
	require.Equal(t, []string{"9007199254740993", "2"}, payload.RoleIDs)
	require.Equal(t, "enabled", payload.Status)
}

func TestCSVCellsCannotExecuteFormulas(t *testing.T) {
	values := []string{"=1+1", " +SUM(A1:A2)", "@SUM(A1:A2)", "\tformula", "normal", "用户"}
	require.Equal(t, []string{"'=1+1", "' +SUM(A1:A2)", "'@SUM(A1:A2)", "'\tformula", "normal", "用户"}, csvSafeRow(values))
}
