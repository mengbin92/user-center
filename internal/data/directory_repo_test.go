package data

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mengbin92/user-center/internal/biz"
)

func TestDirectoryDueSourcesLimitsAfterIntervalFiltering(t *testing.T) {
	d := testData(t)
	organizations := NewOrganizationRepo(d)
	directory := NewDirectoryRepo(d)
	ctx := t.Context()
	now := time.Now().UTC()
	org, err := organizations.CreateOrganization(ctx, nil, &biz.Organization{Code: "directory-test", Name: "Directory"})
	require.NoError(t, err)

	create := func(name string, interval int, lastRun time.Time) int64 {
		t.Helper()
		source, err := directory.CreateSource(ctx, nil, &biz.DirectorySource{
			OrganizationID: org.ID, Name: name, Kind: biz.DirectoryKindJSONFeed,
			Config: biz.DirectoryConfig{Interval: interval}, Status: biz.DirectoryStatusActive,
		})
		require.NoError(t, err)
		require.NoError(t, directory.CompleteAttempt(ctx, nil, source.ID, source.Revision, "", lastRun))
		return source.ID
	}
	create("first-but-not-due", 600, now.Add(-5*time.Minute))
	wantID := create("second-and-due", 30, now.Add(-time.Minute))

	due, err := directory.DueSources(ctx, nil, now, 1)
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, wantID, due[0].ID)
}
