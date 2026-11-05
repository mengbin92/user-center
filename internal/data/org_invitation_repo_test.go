package data

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
)

// Re-inviting an address revokes old pending tokens. The revision must advance
// so an in-flight accept holding the old snapshot cannot overwrite the
// revoked row with "accepted" and join with the old role.
func TestRevokePendingInvitationsAdvancesRevision(t *testing.T) {
	d := testData(t)
	repo := NewOrganizationRepo(d)
	ctx := context.Background()

	inv, err := repo.CreateInvitation(ctx, nil, &biz.OrganizationInvitation{
		OrganizationID: 1, Email: "race@example.com", EmailNormalized: "race@example.com",
		Role: biz.OrgRoleMember, TokenHash: biz.HashToken("old-token"),
		InvitedBy: 1, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	require.NoError(t, err)

	require.NoError(t, repo.RevokePendingInvitationsForEmail(ctx, nil, 1, "race@example.com"))
	revoked, err := repo.GetInvitation(ctx, nil, inv.ID)
	require.NoError(t, err)
	require.Equal(t, biz.OrgInvitationRevoked, revoked.Status)
	require.Equal(t, inv.Revision+1, revoked.Revision)

	// An accept that read revision 1 before the revoke must lose the CAS.
	_, err = repo.UpdateInvitation(ctx, nil, &biz.OrganizationInvitation{
		ID: inv.ID, Status: biz.OrgInvitationAccepted, AcceptedBy: 2,
	}, inv.Revision)
	require.Error(t, err)

	// Even with the current revision the status guard refuses a second
	// transition: a revoked invitation cannot be resurrected.
	_, err = repo.UpdateInvitation(ctx, nil, &biz.OrganizationInvitation{
		ID: inv.ID, Status: biz.OrgInvitationAccepted, AcceptedBy: 2,
	}, revoked.Revision)
	require.Error(t, err)
}
