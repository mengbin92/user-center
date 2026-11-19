package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/data"
	"github.com/mengbin92/user-center/platform/tenant"
)

func TestMySQLCutoverVerifiesRollsBackAndPurgesOnlyPlatform(t *testing.T) {
	dsn := os.Getenv("USER_CENTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set USER_CENTER_MYSQL_TEST_DSN to a migrated, isolated MySQL test database")
	}
	runID := strings.ReplaceAll((data.IDs{}).NewID(), "-", "")
	log := zap.NewNop()
	secret := "isolated-mysql-test-secret-at-least-32-bytes"
	d, cleanup, err := data.NewData(&conf.Data{
		Database: &conf.Database{Driver: "mysql", Source: dsn},
		Tenancy:  &conf.Tenancy{SchemaIsolation: true, SchemaPrefix: "uc_test_" + runID + "_"},
	}, &conf.Security{SessionSecret: secret, CsrfSecret: secret, MfaEncryptionKey: secret}, log)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	ctx := t.Context()
	db := d.DB()
	platform, err := d.PlatformDBName()
	require.NoError(t, err)
	orgs := data.NewOrganizationRepo(d)
	org, err := orgs.CreateOrganization(ctx, nil, &biz.Organization{Code: "tenant-cutover-" + runID, Name: "Cutover"})
	require.NoError(t, err)
	orgScope := authorization.Organization(org.ID)
	schema := d.TenantSchemaName(org.ID)
	table := func(name string) string { return identifier(schema) + "." + identifier(name) }
	t.Cleanup(func() {
		for i := len(tableSpecs()) - 1; i >= 0; i-- {
			spec := tableSpecs()[i]
			where := strings.ReplaceAll(spec.where, "{{platform}}", identifier(platform))
			require.NoError(t, db.Exec("DELETE FROM "+identifier(spec.name)+" WHERE "+where, org.ID).Error)
		}
		require.NoError(t, db.Exec("DELETE FROM tenant_schemas WHERE organization_id = ?", org.ID).Error)
		require.NoError(t, db.Exec("DELETE FROM organizations WHERE id = ?", org.ID).Error)
		require.NoError(t, db.Exec("DROP DATABASE IF EXISTS "+identifier(schema)).Error)
	})

	_, err = orgs.AddMember(ctx, nil, &biz.OrganizationMember{OrganizationID: org.ID, UserID: org.ID, Role: biz.OrgRoleOwner})
	require.NoError(t, err)
	orgIAM := data.NewOrgIAMRepo(d)
	parent, err := orgIAM.CreateRole(ctx, nil, orgScope, &biz.Role{Code: "parent", Name: "Parent"})
	require.NoError(t, err)
	child, err := orgIAM.CreateRole(ctx, nil, orgScope, &biz.Role{Code: "child", Name: "Child"})
	require.NoError(t, err)
	_, err = orgIAM.PutRoleGrants(ctx, nil, orgScope, child.ID, []biz.Grant{{
		Operation: biz.PermOrgAuditRead, Effect: authorization.Allow, Scope: authorization.Scope{All: true},
	}}, child.Revision)
	require.NoError(t, err)
	require.NoError(t, db.Exec("INSERT INTO iam_role_inheritance (role_id, inherits_role_id) VALUES (?, ?)", child.ID, parent.ID).Error)
	eventID := "tenant-audit-" + runID
	now := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, db.Exec("INSERT INTO iam_audit_events (event_id, organization_id, action, result, reason, occurred_at) VALUES (?, ?, 'test', 'success', 'expected', ?)", eventID, org.ID, now).Error)

	_, err = d.EnsureTenantSchema(ctx, org.ID)
	require.NoError(t, err)
	require.NoError(t, db.Exec("ALTER TABLE "+table("iam_roles")+" DROP COLUMN context_id").Error)
	require.NoError(t, db.Exec("INSERT INTO "+table("iam_audit_events")+" (event_id, organization_id, action, result, reason, occurred_at) VALUES (?, ?, 'test', 'success', 'mismatch', ?)", eventID, org.ID, now).Error)
	checkCount := func(query string, want int64, args ...any) {
		t.Helper()
		var got int64
		require.NoError(t, countRows(db, query, &got, args...))
		require.Equal(t, want, got, query)
	}

	// Matching row counts alone cannot authorize a purge. Earlier table writes roll back.
	err = cutover(ctx, d, platform, org.ID, false, true, log)
	require.ErrorContains(t, err, "destination contents differ from source")
	checkCount("SELECT COUNT(*) FROM "+table("organization_members"), 0)
	checkCount("SELECT COUNT(*) FROM organization_members WHERE organization_id = ?", 1, org.ID)
	checkCount("SELECT COUNT(*) FROM iam_audit_events WHERE event_id = ?", 1, eventID)
	require.NoError(t, db.Exec("DELETE FROM "+table("iam_audit_events")+" WHERE event_id = ?", eventID).Error)

	require.NoError(t, cutover(ctx, d, platform, org.ID, true, false, log))
	checkCount("SELECT COUNT(*) FROM "+table("organization_members"), 0)
	require.NoError(t, cutover(ctx, d, platform, org.ID, false, false, log))
	checkCount("SELECT COUNT(*) FROM organization_members WHERE organization_id = ?", 1, org.ID)
	require.NoError(t, cutover(ctx, d, platform, org.ID, false, true, log))
	require.NoError(t, cutover(ctx, d, platform, org.ID, false, true, log))
	checkCount("SELECT COUNT(*) FROM organization_members WHERE organization_id = ?", 0, org.ID)
	checkCount("SELECT COUNT(*) FROM iam_role_permissions WHERE role_id = ?", 0, child.ID)
	checkCount("SELECT COUNT(*) FROM iam_role_inheritance WHERE role_id = ?", 0, child.ID)
	checkCount("SELECT COUNT(*) FROM iam_audit_events WHERE event_id = ?", 0, eventID)
	checkCount("SELECT COUNT(*) FROM "+table("organization_members"), 1)
	checkCount("SELECT COUNT(*) FROM "+table("iam_audit_events")+" WHERE event_id = ? AND reason = 'expected'", 1, eventID)

	routed, err := orgIAM.GetRole(tenant.With(ctx, org.ID), nil, orgScope, child.ID)
	require.NoError(t, err)
	require.Equal(t, []int64{parent.ID}, routed.Inherits)
	require.Len(t, routed.Grants, 1)

	require.NoError(t, db.Exec("UPDATE tenant_schemas SET schema_name = ? WHERE organization_id = ?", schema+"_old", org.ID).Error)
	_, err = d.EnsureTenantSchema(ctx, org.ID)
	require.ErrorContains(t, err, "configured tenant schema does not match")
	checkCount("SELECT COUNT(*) FROM tenant_schemas WHERE organization_id = ? AND schema_name = ?", 1, org.ID, schema+"_old")
}
