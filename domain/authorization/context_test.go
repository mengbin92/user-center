package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestContextValidate(t *testing.T) {
	require.NoError(t, Platform().Validate())
	require.NoError(t, Organization(42).Validate())
	require.Equal(t, "organization:42", Organization(42).String())

	require.NoError(t, Context{}.Normalize().Validate(), "zero value normalizes to a valid platform context")
	require.ErrorIs(t, Context{Type: ContextTypeOrganization}.Validate(), ErrContext)
	require.ErrorIs(t, Context{Type: ContextTypeOrganization, OrganizationID: 7, Key: "organization:8"}.Validate(), ErrContext)
	require.ErrorIs(t, Context{Type: ContextTypePlatform, OrganizationID: 7, Key: "platform"}.Validate(), ErrContext)
	require.ErrorIs(t, Context{Type: "tenant", Key: "tenant"}.Validate(), ErrContext)

	require.True(t, Organization(9).Equal(Context{Type: ContextTypeOrganization, OrganizationID: 9, Key: "organization:9"}))
	require.False(t, Organization(9).Equal(Organization(10)))
	require.False(t, Organization(9).Equal(Platform()))
	require.True(t, Context{}.Equal(Platform()), "zero value is platform for stored rows")
}

func TestEvaluateIsContextBound(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	actor := Actor{UserID: 10, SessionID: "s1", ExpiresAt: now.Add(time.Hour)}
	end := now.Add(24 * time.Hour)
	grant := func(ctx Context, scope Scope) GrantSource {
		return GrantSource{
			RoleID: 1, RoleCode: "org_admin", Operation: "organization.member.manage",
			Effect: Allow, RoleScope: scope, Boundary: scope,
			Validity: Interval{StartsAt: now.Add(-time.Hour), ExpiresAt: &end}, Active: true,
			Context: ctx,
		}
	}
	base := Input{
		Actor: actor, Now: now, IdentityValid: true, SessionValid: true,
		Operation: "organization.member.manage", OperationEnabled: true, OperationBound: true,
		SupportedScopes: []ScopeKind{All, Self, Users},
		AllowedContexts: []string{ContextTypeOrganization},
		Context:         Organization(7),
		TargetUserID:    21, ConstraintsPass: true, BusinessRulesPass: true,
	}

	ok := base
	ok.Sources = []GrantSource{grant(Organization(7), Scope{All: true})}
	d := Evaluate(ok)
	require.True(t, d.Allowed, d.Reason)

	// A platform-wide grant must not authorize an organization operation.
	platformSource := base
	platformSource.Sources = []GrantSource{grant(Platform(), Scope{All: true})}
	d = Evaluate(platformSource)
	require.False(t, d.Allowed)
	require.Equal(t, "ALLOW_MISSING", d.Reason)

	// A grant issued in another tenant must not apply.
	otherTenant := base
	otherTenant.Sources = []GrantSource{grant(Organization(8), Scope{All: true})}
	require.False(t, Evaluate(otherTenant).Allowed)

	// Zero-value sources are platform policy and therefore also excluded.
	legacy := base
	legacy.Sources = []GrantSource{grant(Context{}, Scope{All: true})}
	require.False(t, Evaluate(legacy).Allowed)

	// A permission that only declares the platform context refuses the request
	// before any grant is considered.
	unsupported := ok
	unsupported.AllowedContexts = []string{ContextTypePlatform}
	d = Evaluate(unsupported)
	require.False(t, d.Allowed)
	require.Equal(t, "CONTEXT_UNSUPPORTED", d.Reason)

	// Platform decisions never see organization-scoped grants with All scope.
	platformDecision := base
	platformDecision.Context = Platform()
	platformDecision.AllowedContexts = []string{ContextTypePlatform}
	platformDecision.Sources = []GrantSource{grant(Organization(7), Scope{All: true})}
	require.False(t, Evaluate(platformDecision).Allowed)

	// An invalid context is refused instead of silently downgraded.
	invalid := ok
	invalid.Context = Context{Type: ContextTypeOrganization, OrganizationID: 7, Key: "organization:9"}
	d = Evaluate(invalid)
	require.False(t, d.Allowed)
	require.Equal(t, "CONTEXT_INVALID", d.Reason)

	// Deny in the same context still wins; deny in another context does not.
	withDeny := ok
	deny := grant(Organization(7), Scope{All: true})
	deny.Effect = Deny
	withDeny.Sources = append(withDeny.Sources, deny)
	d = Evaluate(withDeny)
	require.False(t, d.Allowed)
	require.Equal(t, "DENY_MATCHED", d.Reason)

	foreignDeny := ok
	denyOther := grant(Organization(8), Scope{All: true})
	denyOther.Effect = Deny
	foreignDeny.Sources = append(foreignDeny.Sources, denyOther)
	require.True(t, Evaluate(foreignDeny).Allowed)
}
