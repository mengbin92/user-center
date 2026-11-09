package biz

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// SCIM 2.0 provisioning.
//
// The tenant boundary is the bearer token, not anything in the request body.
// Every token is bound to exactly one organization, and every identity lookup
// is scoped by that organization. A caller cannot address another tenant's
// user by guessing a SCIM id, because ids are only resolved through the
// (organization_id, kind, external_id) mapping table.
//
// This is deliberately a single-tenant provisioning surface: an IdP that needs
// to feed several organizations gets one token per organization.

const (
	SCIMTokenStatusActive   = "active"
	SCIMTokenStatusDisabled = "disabled"
	SCIMKindUser            = "user"
	SCIMKindGroup           = "group"
)

type SCIMToken struct {
	ID                int64
	OrganizationID    int64
	Name              string
	TokenHash         string
	Status            string
	CredentialVersion int
	Revision          uint64
	CreatedBy         int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastUsedAt        *time.Time
	DisabledAt        *time.Time
}

// SCIMIdentity binds an IdP externalId to a local row. LocalID is a users.id
// for kind=user and a scim_groups.id for kind=group.
type SCIMIdentity struct {
	ID             int64
	OrganizationID int64
	Kind           string
	ExternalID     string
	LocalID        int64
	Revision       uint64
}

type SCIMGroup struct {
	ID             int64
	OrganizationID int64
	DisplayName    string
	Revision       uint64
	ExternalID     string
	MemberIDs      []int64
}

type SCIMUser struct {
	ID          int64
	ExternalID  string
	UserName    string
	DisplayName string
	Email       string
	Active      bool
	Revision    uint64
}

type SCIMUserInput struct {
	ExternalID  string
	UserName    string
	DisplayName string
	Email       string
	Active      *bool
}

type SCIMGroupInput struct {
	ExternalID  string
	DisplayName string
	AddMembers  []int64
	DelMembers  []int64
}

type SCIMRepo interface {
	CreateToken(context.Context, Tx, *SCIMToken) (*SCIMToken, error)
	GetToken(context.Context, Tx, int64) (*SCIMToken, error)
	FindTokenByHash(context.Context, Tx, string) (*SCIMToken, error)
	ListTokens(context.Context, Tx, int64) ([]*SCIMToken, error)
	UpdateToken(context.Context, Tx, *SCIMToken, uint64) (*SCIMToken, error)
	TouchToken(context.Context, Tx, int64, time.Time) error

	GetIdentityByExternal(context.Context, Tx, int64, string, string) (*SCIMIdentity, error)
	GetIdentityByLocal(context.Context, Tx, int64, string, int64) (*SCIMIdentity, error)
	ListIdentities(context.Context, Tx, int64, string) ([]*SCIMIdentity, error)
	UpsertIdentity(context.Context, Tx, *SCIMIdentity) (*SCIMIdentity, error)
	DeleteIdentity(context.Context, Tx, int64, string, int64) error

	CreateGroup(context.Context, Tx, *SCIMGroup) (*SCIMGroup, error)
	GetGroup(context.Context, Tx, int64, int64) (*SCIMGroup, error)
	ListGroups(context.Context, Tx, int64) ([]*SCIMGroup, error)
	UpdateGroup(context.Context, Tx, *SCIMGroup, uint64) (*SCIMGroup, error)
	DeleteGroup(context.Context, Tx, int64, int64) error
	SetGroupMembers(context.Context, Tx, int64, []int64) error
	GroupMembers(context.Context, Tx, int64) ([]int64, error)
}

type SCIMUsecase struct {
	*Services
	SCIM SCIMRepo
}

func NewSCIMUsecase(s *Services, repo SCIMRepo) *SCIMUsecase {
	return &SCIMUsecase{Services: s, SCIM: repo}
}

// ---------------------------------------------------------------------------
// Token governance (browser admin surface)

func (uc *SCIMUsecase) scimAdminGuard(ctx context.Context, actor ActorContext, requireWrite bool) error {
	if !isPlatformAdmin(actor) {
		return ErrPermissionDenied
	}
	if requireWrite {
		return uc.RequireStepUp(ctx, actor)
	}
	return nil
}

func newSCIMCredential() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := "ucs_" + hex.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

func (uc *SCIMUsecase) Tokens(ctx context.Context, actor ActorContext, orgID int64) ([]*SCIMToken, error) {
	if err := uc.scimAdminGuard(ctx, actor, false); err != nil {
		return nil, err
	}
	if orgID <= 0 {
		return nil, Validation("organization_id 不能为空")
	}
	items, err := uc.SCIM.ListTokens(ctx, nil, orgID)
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *SCIMUsecase) CreateToken(ctx context.Context, actor ActorContext, orgID int64, name, reason string) (*SCIMToken, string, error) {
	if err := uc.scimAdminGuard(ctx, actor, true); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, "", Validation("reason 不能为空")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return nil, "", Validation("name 必须为 1–128 个字符")
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil || org.Status != OrgStatusActive {
		return nil, "", Validation("组织不存在或已归档")
	}
	raw, hash, err := newSCIMCredential()
	if err != nil {
		return nil, "", ErrDependency
	}
	now := uc.Clock.Now()
	var created *SCIMToken
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.SCIM.CreateToken(ctx, tx, &SCIMToken{
			OrganizationID: orgID, Name: name, TokenHash: hash,
			Status: SCIMTokenStatusActive, CredentialVersion: 1,
			Revision: 1, CreatedBy: actor.User.ID, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return ErrDependency
		}
		created = row
		return uc.audit(ctx, tx, actor, "scim.token.created", itoa(row.ID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, "", err
	}
	return created, raw, nil
}

func (uc *SCIMUsecase) RotateToken(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string) (*SCIMToken, string, error) {
	if err := uc.scimAdminGuard(ctx, actor, true); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, "", Validation("reason 不能为空")
	}
	raw, hash, err := newSCIMCredential()
	if err != nil {
		return nil, "", ErrDependency
	}
	var rotated *SCIMToken
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		current, err := uc.SCIM.GetToken(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || current.Revision != expected {
			return ConflictRevision(current.Revision)
		}
		current.TokenHash = hash
		current.CredentialVersion++
		current.Status = SCIMTokenStatusActive
		current.DisabledAt = nil
		current.UpdatedAt = uc.Clock.Now()
		row, err := uc.SCIM.UpdateToken(ctx, tx, current, expected)
		if err != nil {
			return err
		}
		rotated = row
		return uc.audit(ctx, tx, actor, "scim.token.rotated", itoa(id), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, "", err
	}
	return rotated, raw, nil
}

func (uc *SCIMUsecase) DisableToken(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string) (*SCIMToken, error) {
	if err := uc.scimAdminGuard(ctx, actor, true); err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	var disabled *SCIMToken
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		current, err := uc.SCIM.GetToken(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || current.Revision != expected {
			return ConflictRevision(current.Revision)
		}
		now := uc.Clock.Now()
		current.Status = SCIMTokenStatusDisabled
		current.DisabledAt = &now
		current.UpdatedAt = now
		row, err := uc.SCIM.UpdateToken(ctx, tx, current, expected)
		if err != nil {
			return err
		}
		disabled = row
		return uc.audit(ctx, tx, actor, "scim.token.disabled", itoa(id), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return disabled, nil
}

// Authenticate resolves a raw SCIM bearer token. The digest lookup is exact,
// and the comparison is constant-time so a caller cannot learn a valid digest
// one byte at a time through timing.
func (uc *SCIMUsecase) Authenticate(ctx context.Context, raw string) (*SCIMToken, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	hash := HashToken(raw)
	token, err := uc.SCIM.FindTokenByHash(ctx, nil, hash)
	if err != nil || token == nil {
		return nil, ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare([]byte(token.TokenHash), []byte(hash)) != 1 {
		return nil, ErrUnauthenticated
	}
	if token.Status != SCIMTokenStatusActive || token.DisabledAt != nil {
		return nil, ErrUnauthenticated
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, token.OrganizationID)
	if err != nil || org.Status != OrgStatusActive {
		return nil, ErrUnauthenticated
	}
	// Best effort: last_used_at is observability, not an authorization fact.
	_ = uc.SCIM.TouchToken(ctx, nil, token.ID, uc.Clock.Now())
	return token, nil
}

// ---------------------------------------------------------------------------
// Provisioning (SCIM protocol surface)

func (uc *SCIMUsecase) scimAudit(ctx context.Context, tx Tx, orgID int64, action, target, reason string) error {
	event := &AuditEvent{
		EventID: uc.IDs.NewID(), ActorServiceID: "scim",
		Action: action, Target: target, Before: "{}", After: "{}", Diff: "{}",
		Result: "success", Reason: reason, OccurredAt: uc.Clock.Now(),
		OrganizationID: orgID,
	}
	payload, err := jsonx.Marshal(event)
	if err == nil {
		event.Versions = string(payload)
	}
	return uc.Audit.Append(ctx, tx, event)
}

// setUserActive maps SCIM's "active" onto organization membership, never onto
// the global account. A global account is shared across tenants, so disabling
// it here would silently lock the same person out of every other organization.
func (uc *SCIMUsecase) setUserActive(ctx context.Context, tx Tx, orgID, userID int64, active bool, member *OrganizationMember) error {
	if active {
		if member.Status == OrgMemberActive {
			return nil
		}
		if _, err := uc.Organizations.RestoreMember(ctx, tx, orgID, userID, OrgRoleMember, nil, 0); err != nil {
			return ErrDependency
		}
		return syncOrgMembershipRole(ctx, uc.Services, tx, orgID, userID, OrgRoleMember, 0)
	}
	if member.Status != OrgMemberActive {
		return nil
	}
	if err := revokeOrgMemberAssignments(ctx, uc.Services, tx, orgID, userID, 0); err != nil {
		return ErrDependency
	}
	return uc.Organizations.RemoveMember(ctx, tx, orgID, userID, member.Revision)
}

func (uc *SCIMUsecase) localUser(ctx context.Context, tx Tx, orgID, userID int64) (*User, *OrganizationMember, error) {
	identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindUser, userID)
	if err != nil || identity == nil {
		return nil, nil, ErrResourceNotFound
	}
	user, err := uc.Users.Get(ctx, tx, userID)
	if err != nil {
		return nil, nil, ErrResourceNotFound
	}
	member, err := uc.Organizations.GetMember(ctx, tx, orgID, userID)
	if err != nil {
		return nil, nil, ErrResourceNotFound
	}
	return user, member, nil
}

func (uc *SCIMUsecase) userView(ctx context.Context, tx Tx, orgID, userID int64) (*SCIMUser, error) {
	user, member, err := uc.localUser(ctx, tx, orgID, userID)
	if err != nil {
		return nil, err
	}
	identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindUser, userID)
	if err != nil {
		return nil, ErrDependency
	}
	return &SCIMUser{
		ID: user.ID, ExternalID: identity.ExternalID, UserName: user.Username,
		DisplayName: user.DisplayName, Email: user.Email,
		Active:   member.Status == OrgMemberActive && user.Status == UserStatusEnabled,
		Revision: user.Revision,
	}, nil
}

func (uc *SCIMUsecase) ListUsers(ctx context.Context, orgID int64) ([]*SCIMUser, error) {
	identities, err := uc.SCIM.ListIdentities(ctx, nil, orgID, SCIMKindUser)
	if err != nil {
		return nil, ErrDependency
	}
	out := make([]*SCIMUser, 0, len(identities))
	for _, identity := range identities {
		view, err := uc.userView(ctx, nil, orgID, identity.LocalID)
		if err != nil {
			// A mapping whose local row was removed is skipped rather than
			// failing the whole list: an IdP reconciliation must still work.
			continue
		}
		out = append(out, view)
	}
	return out, nil
}

func (uc *SCIMUsecase) GetUser(ctx context.Context, orgID, id int64) (*SCIMUser, error) {
	return uc.userView(ctx, nil, orgID, id)
}

// CreateUser provisions one account into the token's organization. A local
// account that already exists but is not a member of this organization is
// REFUSED, not silently attached: otherwise a tenant's SCIM token could pull
// another tenant's user into its own directory by guessing an e-mail address.
func (uc *SCIMUsecase) CreateUser(ctx context.Context, orgID int64, in SCIMUserInput) (*SCIMUser, error) {
	if strings.TrimSpace(in.UserName) == "" {
		return nil, Validation("userName 不能为空")
	}
	externalID := strings.TrimSpace(in.ExternalID)
	if externalID == "" {
		externalID = in.UserName
	}
	var created *SCIMUser
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if existing, err := uc.SCIM.GetIdentityByExternal(ctx, tx, orgID, SCIMKindUser, externalID); err == nil && existing != nil {
			return ConflictCode("SCIM_UNIQUENESS", "externalId 已存在")
		}
		now := uc.Clock.Now()
		var user *User
		if normalized := NormalizeEmail(in.Email); normalized != "" {
			user, _ = uc.Users.GetByEmail(ctx, tx, normalized)
		}
		if user == nil {
			username := strings.TrimSpace(in.UserName)
			if _, err := uc.Users.GetByUsername(ctx, tx, NormalizeUsername(username)); err == nil {
				username = fmt.Sprintf("%s-%s", username, uc.IDs.NewID()[:8])
			}
			var err error
			user, err = uc.Users.Create(ctx, tx, &User{
				Username: username, UsernameNormalized: NormalizeUsername(username),
				DisplayName: firstNonEmpty(in.DisplayName, username),
				Email:       in.Email, EmailNormalized: NormalizeEmail(in.Email),
				Status: UserStatusEnabled, Revision: 1, IdentityVersion: 1,
				CreatedAt: now, UpdatedAt: now,
			})
			if err != nil {
				return ErrDependency
			}
			// A SCIM-provisioned account has no usable local password: it can
			// only be reached through a federated login or an admin reset.
			hash, err := HashPassword(uc.IDs.NewID())
			if err != nil {
				return ErrDependency
			}
			if err := uc.Credentials.Create(ctx, tx, &Credential{
				UserID: user.ID, PasswordHash: hash, Algorithm: "bcrypt", Revision: 1,
			}); err != nil {
				return ErrDependency
			}
			if _, err := uc.Organizations.AddMember(ctx, tx, &OrganizationMember{
				OrganizationID: orgID, UserID: user.ID, Role: OrgRoleMember,
				InvitedBy: 0, JoinedAt: now,
			}); err != nil {
				return ErrDependency
			}
			if err := syncOrgMembershipRole(ctx, uc.Services, tx, orgID, user.ID, OrgRoleMember, 0); err != nil {
				return ErrDependency
			}
		} else {
			member, err := uc.Organizations.GetMember(ctx, tx, orgID, user.ID)
			if err != nil || member.Status != OrgMemberActive {
				return ConflictCode("SCIM_UNIQUENESS", "该邮箱已存在且不属于本组织")
			}
		}
		if _, err := uc.SCIM.UpsertIdentity(ctx, tx, &SCIMIdentity{
			OrganizationID: orgID, Kind: SCIMKindUser, ExternalID: externalID, LocalID: user.ID,
		}); err != nil {
			return ErrDependency
		}
		if in.Active != nil && !*in.Active {
			member, err := uc.Organizations.GetMember(ctx, tx, orgID, user.ID)
			if err == nil {
				if err := uc.setUserActive(ctx, tx, orgID, user.ID, false, member); err != nil {
					return err
				}
			}
		}
		if err := uc.scimAudit(ctx, tx, orgID, "scim.user.created", itoa(user.ID), externalID); err != nil {
			return err
		}
		view, err := uc.userView(ctx, tx, orgID, user.ID)
		if err != nil {
			return err
		}
		created = view
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *SCIMUsecase) ReplaceUser(ctx context.Context, orgID, id int64, in SCIMUserInput) (*SCIMUser, error) {
	return uc.editUser(ctx, orgID, id, in, true)
}

func (uc *SCIMUsecase) PatchUser(ctx context.Context, orgID, id int64, in SCIMUserInput) (*SCIMUser, error) {
	return uc.editUser(ctx, orgID, id, in, false)
}

func (uc *SCIMUsecase) editUser(ctx context.Context, orgID, id int64, in SCIMUserInput, replace bool) (*SCIMUser, error) {
	var out *SCIMUser
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		user, member, err := uc.localUser(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if in.UserName != "" || replace {
			if name := strings.TrimSpace(in.UserName); name != "" {
				user.Username = name
				user.UsernameNormalized = NormalizeUsername(name)
			}
		}
		if in.DisplayName != "" || replace {
			user.DisplayName = firstNonEmpty(in.DisplayName, user.DisplayName)
		}
		if in.Email != "" || replace {
			user.Email = in.Email
			user.EmailNormalized = NormalizeEmail(in.Email)
		}
		user.UpdatedAt = uc.Clock.Now()
		if _, err := uc.Users.Update(ctx, tx, user, user.Revision); err != nil {
			return ErrDependency
		}
		if in.Active != nil {
			if err := uc.setUserActive(ctx, tx, orgID, id, *in.Active, member); err != nil {
				return err
			}
		}
		if strings.TrimSpace(in.ExternalID) != "" {
			if _, err := uc.SCIM.UpsertIdentity(ctx, tx, &SCIMIdentity{
				OrganizationID: orgID, Kind: SCIMKindUser,
				ExternalID: in.ExternalID, LocalID: id,
			}); err != nil {
				return ErrDependency
			}
		}
		if err := uc.scimAudit(ctx, tx, orgID, "scim.user.updated", itoa(id), in.ExternalID); err != nil {
			return err
		}
		view, err := uc.userView(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		out = view
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteUser deprovisions: the organization membership and the externalId
// mapping go away, but the global account is never deleted. Other tenants and
// audit history must survive one tenant's deprovisioning.
func (uc *SCIMUsecase) DeleteUser(ctx context.Context, orgID, id int64) error {
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		_, member, err := uc.localUser(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if err := uc.Organizations.RemoveMember(ctx, tx, orgID, id, member.Revision); err != nil {
			return ErrDependency
		}
		if err := uc.SCIM.DeleteIdentity(ctx, tx, orgID, SCIMKindUser, id); err != nil {
			return ErrDependency
		}
		return uc.scimAudit(ctx, tx, orgID, "scim.user.deleted", itoa(id), "deprovision")
	})
}

// ---------------------------------------------------------------------------
// Groups

func (uc *SCIMUsecase) groupView(ctx context.Context, tx Tx, orgID, id int64) (*SCIMGroup, error) {
	group, err := uc.SCIM.GetGroup(ctx, tx, orgID, id)
	if err != nil || group == nil {
		return nil, ErrResourceNotFound
	}
	identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindGroup, id)
	if err == nil && identity != nil {
		group.ExternalID = identity.ExternalID
	}
	members, err := uc.SCIM.GroupMembers(ctx, tx, id)
	if err != nil {
		return nil, ErrDependency
	}
	group.MemberIDs = members
	return group, nil
}

func (uc *SCIMUsecase) ListGroups(ctx context.Context, orgID int64) ([]*SCIMGroup, error) {
	groups, err := uc.SCIM.ListGroups(ctx, nil, orgID)
	if err != nil {
		return nil, ErrDependency
	}
	for _, g := range groups {
		members, err := uc.SCIM.GroupMembers(ctx, nil, g.ID)
		if err != nil {
			return nil, ErrDependency
		}
		g.MemberIDs = members
		identity, err := uc.SCIM.GetIdentityByLocal(ctx, nil, orgID, SCIMKindGroup, g.ID)
		if err == nil && identity != nil {
			g.ExternalID = identity.ExternalID
		}
	}
	return groups, nil
}

func (uc *SCIMUsecase) GetGroup(ctx context.Context, orgID, id int64) (*SCIMGroup, error) {
	return uc.groupView(ctx, nil, orgID, id)
}

func (uc *SCIMUsecase) CreateGroup(ctx context.Context, orgID int64, in SCIMGroupInput) (*SCIMGroup, error) {
	if strings.TrimSpace(in.DisplayName) == "" {
		return nil, Validation("displayName 不能为空")
	}
	externalID := strings.TrimSpace(in.ExternalID)
	if externalID == "" {
		externalID = in.DisplayName
	}
	var created *SCIMGroup
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if existing, err := uc.SCIM.GetIdentityByExternal(ctx, tx, orgID, SCIMKindGroup, externalID); err == nil && existing != nil {
			return ConflictCode("SCIM_UNIQUENESS", "externalId 已存在")
		}
		group, err := uc.SCIM.CreateGroup(ctx, tx, &SCIMGroup{
			OrganizationID: orgID, DisplayName: in.DisplayName,
			Revision: 1,
		})
		if err != nil {
			return ErrDependency
		}
		if _, err := uc.SCIM.UpsertIdentity(ctx, tx, &SCIMIdentity{
			OrganizationID: orgID, Kind: SCIMKindGroup, ExternalID: externalID, LocalID: group.ID,
		}); err != nil {
			return ErrDependency
		}
		if len(in.AddMembers) > 0 {
			if err := uc.validGroupMembers(ctx, tx, orgID, in.AddMembers); err != nil {
				return err
			}
			if err := uc.SCIM.SetGroupMembers(ctx, tx, group.ID, in.AddMembers); err != nil {
				return ErrDependency
			}
		}
		if err := uc.scimAudit(ctx, tx, orgID, "scim.group.created", itoa(group.ID), externalID); err != nil {
			return err
		}
		view, err := uc.groupView(ctx, tx, orgID, group.ID)
		if err != nil {
			return err
		}
		created = view
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *SCIMUsecase) PatchGroup(ctx context.Context, orgID, id int64, in SCIMGroupInput) (*SCIMGroup, error) {
	var out *SCIMGroup
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		group, err := uc.SCIM.GetGroup(ctx, tx, orgID, id)
		if err != nil || group == nil {
			return ErrResourceNotFound
		}
		if strings.TrimSpace(in.DisplayName) != "" {
			group.DisplayName = in.DisplayName
			if _, err := uc.SCIM.UpdateGroup(ctx, tx, group, group.Revision); err != nil {
				return ErrDependency
			}
		}
		if len(in.AddMembers) > 0 || len(in.DelMembers) > 0 {
			if err := uc.validGroupMembers(ctx, tx, orgID, append(in.AddMembers, in.DelMembers...)); err != nil {
				return err
			}
			current, err := uc.SCIM.GroupMembers(ctx, tx, id)
			if err != nil {
				return ErrDependency
			}
			set := map[int64]bool{}
			for _, uid := range current {
				set[uid] = true
			}
			for _, uid := range in.AddMembers {
				set[uid] = true
			}
			for _, uid := range in.DelMembers {
				delete(set, uid)
			}
			next := make([]int64, 0, len(set))
			for uid := range set {
				next = append(next, uid)
			}
			if err := uc.SCIM.SetGroupMembers(ctx, tx, id, next); err != nil {
				return ErrDependency
			}
		}
		if err := uc.scimAudit(ctx, tx, orgID, "scim.group.updated", itoa(id), in.ExternalID); err != nil {
			return err
		}
		view, err := uc.groupView(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		out = view
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (uc *SCIMUsecase) DeleteGroup(ctx context.Context, orgID, id int64) error {
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.SCIM.GetGroup(ctx, tx, orgID, id); err != nil {
			return ErrResourceNotFound
		}
		if err := uc.SCIM.SetGroupMembers(ctx, tx, id, nil); err != nil {
			return ErrDependency
		}
		if err := uc.SCIM.DeleteGroup(ctx, tx, orgID, id); err != nil {
			return ErrDependency
		}
		if err := uc.SCIM.DeleteIdentity(ctx, tx, orgID, SCIMKindGroup, id); err != nil {
			return ErrDependency
		}
		return uc.scimAudit(ctx, tx, orgID, "scim.group.deleted", itoa(id), "deprovision")
	})
}

// validGroupMembers refuses ids that are not provisioned users of THIS tenant.
// Without it, a SCIM client could put an arbitrary platform user id into a
// group and make the group enumeration disclose foreign accounts.
func (uc *SCIMUsecase) validGroupMembers(ctx context.Context, tx Tx, orgID int64, ids []int64) error {
	for _, uid := range ids {
		if _, _, err := uc.localUser(ctx, tx, orgID, uid); err != nil {
			return Validation("组成员必须是通过 SCIM 供给到本组织的用户")
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
