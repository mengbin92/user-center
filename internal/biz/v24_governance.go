package biz

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// V2.4 W3 governance: single assignment preview, organization quota and the
// read-only identity provider configuration view.

type AssignmentPreview struct {
	Eligible       bool
	Reason         string
	Permissions    []AuthorizationGrant
	Denies         []authorization.GrantSource
	Scope          string
	ValidUntil     *time.Time
	PolicyRevision uint64
	RoleStatus     string
	MaxMembers     *int64
}

// PreviewAssignment answers "what would this member get" without writing. It
// delegates eligibility to PreviewBatch (the single shared calculation path)
// and derives the resulting permissions from the same fact loader used by the
// real assignment flow.
func (uc *IAMUsecase) PreviewAssignment(ctx context.Context, actor ActorContext, userID, roleID int64, boundary authorization.Scope, expires *time.Time) (*AssignmentPreview, error) {
	batch, err := uc.PreviewBatch(ctx, actor, []int64{userID}, roleID, boundary, expires)
	if err != nil {
		return nil, err
	}
	role, err := uc.IAM.GetRole(ctx, nil, roleID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	out := &AssignmentPreview{
		Eligible: len(batch.Failures) == 0, RoleStatus: role.Status,
		MaxMembers: role.MaxMembers, ValidUntil: expires,
	}
	if len(batch.Failures) > 0 {
		out.Reason = batch.Failures[0].Reason
	} else if role.Status == RoleStatusArchived {
		out.Eligible = false
		out.Reason = "角色已归档，不能分配"
	} else if role.Status != RoleStatusActive {
		out.Eligible = false
		out.Reason = "角色已停用，不能分配"
	} else if role.MaxMembers != nil && *role.MaxMembers > 0 {
		n, err := uc.IAM.CountActiveAssignmentsForRole(ctx, nil, roleID)
		if err != nil {
			return nil, ErrDependency
		}
		if n >= *role.MaxMembers {
			out.Eligible = false
			out.Reason = "角色成员数已达上限"
		}
	}
	normalized, err := normalizeAssignmentScope(boundary)
	if err != nil {
		return nil, err
	}
	out.Scope = scopeLabel(normalized)
	assignments, err := uc.IAM.ListAssignmentsForUser(ctx, nil, userID)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	active := []int64{}
	for _, a := range assignments {
		if a.Active(now) {
			active = append(active, a.RoleID)
		}
	}
	// Inject the hypothetical assignment into the same fact snapshot and
	// re-resolve sources. This is the identical evaluation the real assignment
	// will produce, without writing anything.
	facts, err := uc.LoadAuthzFacts(ctx, userID, append(slices.Clone(active), roleID))
	if err != nil {
		return nil, ErrDependency
	}
	facts.Assignments = append(facts.Assignments, &Assignment{
		UserID: userID, RoleID: roleID, Boundary: normalized,
		StartsAt: now, ExpiresAt: expires, Origin: OriginExplicit,
		Context: authorization.Platform(),
	})
	facts.ActiveRoleIDs = append(slices.Clone(active), roleID)
	if err := facts.resolveSources(now); err != nil {
		return nil, ErrDependency
	}
	out.PolicyRevision = facts.PolicyRevision
	permissions, err := uc.IAM.ListPermissions(ctx, nil, PermissionFilter{Status: PermissionStatusActive})
	if err != nil {
		return nil, ErrDependency
	}
	enabled := map[string]bool{}
	for _, p := range permissions {
		enabled[p.Code] = p.Binding == BindingBound
	}
	seen := map[string]bool{}
	for _, src := range facts.Sources {
		if !src.Validity.Contains(now) || !enabled[src.Operation] {
			continue
		}
		effective := authorization.IntersectForActor(src.RoleScope, src.Boundary, userID)
		if effective.Empty() {
			continue
		}
		if src.Effect == authorization.Deny {
			out.Denies = append(out.Denies, src)
			continue
		}
		if !src.Active {
			continue
		}
		scope := scopeString(src, userID)
		key := string(src.Effect) + "|" + src.Operation + "|" + src.RoleCode + "|" + scope
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Permissions = append(out.Permissions, AuthorizationGrant{
			Operation: src.Operation, Effect: string(src.Effect), Scope: scope,
			RoleID: src.RoleID, RoleCode: src.RoleCode,
		})
	}
	return out, nil
}

func scopeLabel(s authorization.Scope) string {
	if s.All {
		return "all"
	}
	if s.Self {
		return "self"
	}
	if len(s.UserIDs) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(s.UserIDs))
	for _, id := range s.UserIDs {
		parts = append(parts, itoa(id))
	}
	return "users:" + strings.Join(parts, ",")
}

// --- organization quota (R12) ---

func (uc *SettingsUsecase) GetOrganizationSettings(ctx context.Context, actor ActorContext) (*OrganizationSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.organization.read", 0, true); err != nil {
		return nil, err
	}
	s, err := uc.Settings.GetOrganization(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	return s, nil
}

func (uc *SettingsUsecase) UpdateOrganizationSettings(ctx context.Context, actor ActorContext, in *OrganizationSettings, updateMask string, expected uint64, reason string) (*OrganizationSettings, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.organization.update", 0, true); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	fields, err := mutationFields(updateMask, "quota_enabled", "max_owned_per_user", "count_archived")
	if err != nil {
		return nil, err
	}
	before, err := uc.Settings.GetOrganization(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	merged := *before
	if fields["quota_enabled"] {
		merged.QuotaEnabled = in.QuotaEnabled
	}
	if fields["max_owned_per_user"] {
		merged.MaxOwnedPerUser = in.MaxOwnedPerUser
	}
	if fields["count_archived"] {
		merged.CountArchived = in.CountArchived
	}
	if merged.MaxOwnedPerUser < 1 || merged.MaxOwnedPerUser > 1000 {
		return nil, Validation("每用户组织数量上限必须为 1-1000")
	}
	in = &merged
	var saved *OrganizationSettings
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		s, err := uc.Settings.SaveOrganization(ctx, tx, in, expected)
		if err != nil {
			return err
		}
		saved = s
		return uc.audit(ctx, tx, actor, "settings.organization.update", "organization", "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}

// organizationQuotaGuard runs inside the create transaction. Platform
// administrators are exempt by design.
func (uc *OrganizationUsecase) organizationQuotaGuard(ctx context.Context, tx Tx, actor ActorContext) error {
	if isPlatformAdmin(actor) {
		return nil
	}
	settings, err := uc.Settings.GetOrganization(ctx, tx)
	if err != nil {
		return ErrDependency
	}
	if !settings.QuotaEnabled {
		return nil
	}
	count, err := uc.Organizations.CountOwnedOrganizations(ctx, tx, actor.User.ID, settings.CountArchived)
	if err != nil {
		return ErrDependency
	}
	if int64(settings.MaxOwnedPerUser) <= count {
		_ = uc.audit(ctx, tx, actor, "organization.create.denied", "quota", "{}", "{}",
			string(mustJSON(map[string]any{"count": count, "limit": settings.MaxOwnedPerUser})),
			"organization quota exceeded", "denied")
		return ConflictCode("ORGANIZATION_QUOTA_EXCEEDED", "已达到每用户组织数量上限")
	}
	return nil
}

// --- identity provider configuration view (R9) ---

type ProviderView struct {
	Code                 string
	Name                 string
	Enabled              bool
	CredentialSource     string
	CredentialConfigured bool
	CallbackURL          string
	RequiredEnv          []string
	UpdatedAt            time.Time
}

type ProviderViewReply struct {
	Items    []*ProviderView
	Revision uint64
}

// AuthProviders is read-only: credentials stay in environment variables, are
// never returned, and only their presence is reported.
func (uc *SettingsUsecase) AuthProviders(ctx context.Context, actor ActorContext) (*ProviderViewReply, error) {
	if _, err := uc.Authorize(ctx, actor, "settings.auth.read", 0, true); err != nil {
		return nil, err
	}
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	base := strings.TrimRight(uc.PublicBaseURL, "/")
	defs := []struct {
		code, name string
		env        []string
	}{
		{"github", "GitHub", []string{"OAUTH_GITHUB_CLIENT_ID", "OAUTH_GITHUB_CLIENT_SECRET"}},
		{"google", "Google", []string{"OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GOOGLE_CLIENT_SECRET"}},
	}
	out := &ProviderViewReply{Revision: settings.Revision}
	for _, def := range defs {
		configured := uc.OAuth[def.code] != nil
		enabled := configured
		for _, p := range settings.Providers {
			if p == def.code {
				enabled = configured && enabled
			}
		}
		if !containsProvider(settings.Providers, def.code) {
			enabled = false
		}
		out.Items = append(out.Items, &ProviderView{
			Code: def.code, Name: def.name, Enabled: enabled,
			CredentialSource: "env", CredentialConfigured: configured,
			CallbackURL: base + "/api/v1/auth/providers/" + def.code + "/callback",
			RequiredEnv: def.env, UpdatedAt: settings.UpdatedAt,
		})
	}
	return out, nil
}

func containsProvider(list []string, code string) bool {
	for _, p := range list {
		if p == code {
			return true
		}
	}
	return false
}
