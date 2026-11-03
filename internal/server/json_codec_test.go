package server

import (
	"testing"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/stretchr/testify/require"
)

func TestWireJSONPreservesInt64AndRejectsUnknownFields(t *testing.T) {
	codec := wireJSONCodec{}
	encoded, err := codec.Marshal(&usercv1.OverviewReply{TotalUsers: 9007199254740993})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"total_users":"9007199254740993"`)
	var request usercv1.CreateRoleRequest
	require.NoError(t, codec.Unmarshal([]byte(`{"max_members":"9007199254740993"}`), &request))
	require.EqualValues(t, 9007199254740993, request.MaxMembers)
	require.Error(t, codec.Unmarshal([]byte(`{"operator_user_id":"1"}`), &request))
}
