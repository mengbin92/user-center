package biz

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

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

var ErrSCIMPrecondition = errors.New("If-Match 与当前版本不一致")
var ErrSCIMReadOnlyProfile = errors.New("平台账号资料只能通过账号资料流程修改")

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
	ExternalID       string
	UserName         string
	DisplayName      string
	Email            string
	Active           *bool
	ExpectedRevision uint64
}

type SCIMGroupInput struct {
	ExternalID  string
	DisplayName string
	Members     []SCIMGroupMemberChange
}

type SCIMGroupMemberChange struct {
	IDs     []int64
	Replace bool
	Remove  bool
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
	DeleteGroup(context.Context, Tx, int64, int64, uint64) error
	SetGroupMembers(context.Context, Tx, int64, []int64) error
	GroupMembers(context.Context, Tx, int64) ([]int64, error)
	RemoveUserFromGroups(context.Context, Tx, int64, int64) error
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
	actor, err := uc.currentIAMActor(ctx, actor)
	if err != nil {
		return err
	}
	if !isPlatformAdmin(actor) {
		return ErrPermissionDenied
	}
	if err := uc.requireAdminMFA(ctx, actor); err != nil {
		return err
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
	if member.Role == OrgRoleOwner {
		org := &OrganizationUsecase{Services: uc.Services}
		if err := org.ensureAnotherOwner(ctx, tx, orgID); err != nil {
			return err
		}
	}
	if err := uc.Organizations.RemoveMember(ctx, tx, orgID, userID, member.Revision); err != nil {
		return err
	}
	if err := revokeOrgMemberAssignments(ctx, uc.Services, tx, orgID, userID, 0); err != nil {
		return ErrDependency
	}
	return nil
}

func (uc *SCIMUsecase) localUser(ctx context.Context, tx Tx, orgID, userID int64) (*User, *OrganizationMember, *SCIMIdentity, error) {
	identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindUser, userID)
	if err != nil {
		return nil, nil, nil, scimLookupError(err)
	}
	user, err := uc.Users.Get(ctx, tx, userID)
	if err != nil {
		return nil, nil, nil, scimLookupError(err)
	}
	member, err := uc.Organizations.GetMember(ctx, tx, orgID, userID)
	if err != nil {
		return nil, nil, nil, scimLookupError(err)
	}
	return user, member, identity, nil
}

func scimLookupError(err error) error {
	if IsNotFound(err) {
		return ErrResourceNotFound
	}
	return ErrDependency
}

func (uc *SCIMUsecase) userView(ctx context.Context, tx Tx, orgID, userID int64) (*SCIMUser, error) {
	user, member, identity, err := uc.localUser(ctx, tx, orgID, userID)
	if err != nil {
		return nil, err
	}
	return &SCIMUser{
		ID: user.ID, ExternalID: identity.ExternalID, UserName: user.Username,
		DisplayName: user.DisplayName, Email: user.Email,
		Active:   member.Status == OrgMemberActive && user.Status == UserStatusEnabled,
		Revision: identity.Revision,
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
		if errors.Is(err, ErrResourceNotFound) {
			continue
		}
		if err != nil {
			return nil, err
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
	in.UserName = strings.TrimSpace(in.UserName)
	if in.UserName == "" || utf8.RuneCountInString(in.UserName) > 128 {
		return nil, Validation("userName 必须为 1–128 个字符")
	}
	in.DisplayName = firstNonEmpty(in.DisplayName, in.UserName)
	if utf8.RuneCountInString(in.DisplayName) > 128 {
		return nil, Validation("displayName 不能超过 128 个字符")
	}
	in.Email = NormalizeEmail(in.Email)
	if in.Email != "" {
		if err := ValidateEmail(in.Email); err != nil {
			return nil, err
		}
	}
	externalID := strings.TrimSpace(in.ExternalID)
	if externalID == "" {
		externalID = in.UserName
	}
	if utf8.RuneCountInString(externalID) > 255 {
		return nil, Validation("externalId 不能超过 255 个字符")
	}
	var created *SCIMUser
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.SCIM.GetIdentityByExternal(ctx, tx, orgID, SCIMKindUser, externalID); err == nil {
			return ConflictCode("SCIM_UNIQUENESS", "externalId 已存在")
		} else if !IsNotFound(err) {
			return ErrDependency
		}
		now := uc.Clock.Now()
		var user *User
		if in.Email != "" {
			var err error
			user, err = uc.Users.GetByEmail(ctx, tx, in.Email)
			if err != nil && !IsNotFound(err) {
				return ErrDependency
			}
		}
		if user == nil {
			normalized := NormalizeUsername(in.UserName)
			if _, err := uc.Users.GetByUsername(ctx, tx, normalized); err == nil {
				return ConflictCode("SCIM_UNIQUENESS", "userName 已存在")
			} else if !IsNotFound(err) {
				return ErrDependency
			}
			var err error
			user, err = uc.Users.Create(ctx, tx, &User{
				Username: in.UserName, UsernameNormalized: normalized,
				DisplayName: in.DisplayName,
				Email:       in.Email, EmailNormalized: in.Email,
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
				UpdatedAt: now,
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
			if err != nil && !IsNotFound(err) {
				return ErrDependency
			}
			if err != nil || member.Status != OrgMemberActive {
				return ConflictCode("SCIM_UNIQUENESS", "该邮箱已存在且不属于本组织")
			}
		}
		if _, err := uc.SCIM.UpsertIdentity(ctx, tx, &SCIMIdentity{
			OrganizationID: orgID, Kind: SCIMKindUser, ExternalID: externalID, LocalID: user.ID,
		}); err != nil {
			return err
		}
		if in.Active != nil && !*in.Active {
			member, err := uc.Organizations.GetMember(ctx, tx, orgID, user.ID)
			if err != nil {
				return ErrDependency
			}
			if err := uc.setUserActive(ctx, tx, orgID, user.ID, false, member); err != nil {
				return err
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

func (uc *SCIMUsecase) ReplaceUser(ctx context.Context, orgID, id int64, in SCIMUserInput, expected uint64) (*SCIMUser, error) {
	if strings.TrimSpace(in.UserName) == "" {
		return nil, Validation("userName 不能为空")
	}
	in.ExpectedRevision = expected
	return uc.PatchUser(ctx, orgID, id, in)
}

func (uc *SCIMUsecase) PatchUser(ctx context.Context, orgID, id int64, in SCIMUserInput) (*SCIMUser, error) {
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if utf8.RuneCountInString(in.ExternalID) > 255 {
		return nil, Validation("externalId 不能超过 255 个字符")
	}
	var out *SCIMUser
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		user, member, identity, err := uc.localUser(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if (in.UserName != "" && NormalizeUsername(in.UserName) != user.UsernameNormalized) ||
			(in.Email != "" && NormalizeEmail(in.Email) != user.EmailNormalized) ||
			(in.DisplayName != "" && strings.TrimSpace(in.DisplayName) != user.DisplayName) {
			return ErrSCIMReadOnlyProfile
		}
		if in.ExternalID != "" {
			identity.ExternalID = in.ExternalID
		}
		if err := uc.updateUserIdentity(ctx, tx, identity, in.ExpectedRevision); err != nil {
			return err
		}
		if in.Active != nil {
			if err := uc.setUserActive(ctx, tx, orgID, id, *in.Active, member); err != nil {
				return err
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

func (uc *SCIMUsecase) updateUserIdentity(ctx context.Context, tx Tx, identity *SCIMIdentity, expected uint64) error {
	if expected != 0 && identity.Revision != expected {
		return ErrSCIMPrecondition
	}
	_, err := uc.SCIM.UpsertIdentity(ctx, tx, identity)
	if expected != 0 && errors.Is(err, ErrRevisionConflict) {
		return ErrSCIMPrecondition
	}
	return err
}

// DeleteUser deprovisions: the organization membership and the externalId
// mapping go away, but the global account is never deleted. Other tenants and
// audit history must survive one tenant's deprovisioning.
func (uc *SCIMUsecase) DeleteUser(ctx context.Context, orgID, id int64) error {
	return uc.DeleteUserIfMatch(ctx, orgID, id, 0)
}

func (uc *SCIMUsecase) DeleteUserIfMatch(ctx context.Context, orgID, id int64, expected uint64) error {
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		_, member, identity, err := uc.localUser(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if err := uc.updateUserIdentity(ctx, tx, identity, expected); err != nil {
			return err
		}
		if err := uc.setUserActive(ctx, tx, orgID, id, false, member); err != nil {
			return err
		}
		if err := uc.SCIM.RemoveUserFromGroups(ctx, tx, orgID, id); err != nil {
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
	if err != nil {
		return nil, scimLookupError(err)
	}
	identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindGroup, id)
	if err == nil {
		group.ExternalID = identity.ExternalID
	} else if !IsNotFound(err) {
		return nil, ErrDependency
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
		if err == nil {
			g.ExternalID = identity.ExternalID
		} else if !IsNotFound(err) {
			return nil, ErrDependency
		}
	}
	return groups, nil
}

func (uc *SCIMUsecase) GetGroup(ctx context.Context, orgID, id int64) (*SCIMGroup, error) {
	return uc.groupView(ctx, nil, orgID, id)
}

func (uc *SCIMUsecase) CreateGroup(ctx context.Context, orgID int64, in SCIMGroupInput) (*SCIMGroup, error) {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || utf8.RuneCountInString(in.DisplayName) > 255 {
		return nil, Validation("displayName 必须为 1–255 个字符")
	}
	externalID := strings.TrimSpace(in.ExternalID)
	if externalID == "" {
		externalID = in.DisplayName
	}
	if utf8.RuneCountInString(externalID) > 255 {
		return nil, Validation("externalId 不能超过 255 个字符")
	}
	var created *SCIMGroup
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.SCIM.GetIdentityByExternal(ctx, tx, orgID, SCIMKindGroup, externalID); err == nil {
			return ConflictCode("SCIM_UNIQUENESS", "externalId 已存在")
		} else if !IsNotFound(err) {
			return ErrDependency
		}
		group, err := uc.SCIM.CreateGroup(ctx, tx, &SCIMGroup{
			OrganizationID: orgID, DisplayName: in.DisplayName,
			Revision: 1,
		})
		if err != nil {
			return err
		}
		if _, err := uc.SCIM.UpsertIdentity(ctx, tx, &SCIMIdentity{
			OrganizationID: orgID, Kind: SCIMKindGroup, ExternalID: externalID, LocalID: group.ID,
		}); err != nil {
			return err
		}
		if err := uc.editGroupMembers(ctx, tx, orgID, group.ID, in.Members); err != nil {
			return err
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

func (uc *SCIMUsecase) PatchGroup(ctx context.Context, orgID, id int64, in SCIMGroupInput, expected uint64) (*SCIMGroup, error) {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if utf8.RuneCountInString(in.DisplayName) > 255 || utf8.RuneCountInString(in.ExternalID) > 255 {
		return nil, Validation("displayName 和 externalId 不能超过 255 个字符")
	}
	var out *SCIMGroup
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		group, err := uc.SCIM.GetGroup(ctx, tx, orgID, id)
		if err != nil {
			return scimLookupError(err)
		}
		if expected != 0 && group.Revision != expected {
			return ErrSCIMPrecondition
		}
		if in.DisplayName != "" {
			group.DisplayName = in.DisplayName
		}
		if _, err := uc.SCIM.UpdateGroup(ctx, tx, group, group.Revision); err != nil {
			if expected != 0 && errors.Is(err, ErrRevisionConflict) {
				return ErrSCIMPrecondition
			}
			return err
		}
		if in.ExternalID != "" {
			identity, err := uc.SCIM.GetIdentityByLocal(ctx, tx, orgID, SCIMKindGroup, id)
			if err != nil {
				return scimLookupError(err)
			}
			identity.ExternalID = in.ExternalID
			if _, err := uc.SCIM.UpsertIdentity(ctx, tx, identity); err != nil {
				return err
			}
		}
		if err := uc.editGroupMembers(ctx, tx, orgID, id, in.Members); err != nil {
			return err
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

func (uc *SCIMUsecase) DeleteGroup(ctx context.Context, orgID, id int64, expected uint64) error {
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		group, err := uc.SCIM.GetGroup(ctx, tx, orgID, id)
		if err != nil {
			return scimLookupError(err)
		}
		if expected != 0 && group.Revision != expected {
			return ErrSCIMPrecondition
		}
		if err := uc.SCIM.DeleteGroup(ctx, tx, orgID, id, group.Revision); err != nil {
			if expected != 0 && errors.Is(err, ErrRevisionConflict) {
				return ErrSCIMPrecondition
			}
			return err
		}
		if err := uc.SCIM.SetGroupMembers(ctx, tx, id, nil); err != nil {
			return ErrDependency
		}
		if err := uc.SCIM.DeleteIdentity(ctx, tx, orgID, SCIMKindGroup, id); err != nil {
			return ErrDependency
		}
		return uc.scimAudit(ctx, tx, orgID, "scim.group.deleted", itoa(id), "deprovision")
	})
}

func (uc *SCIMUsecase) editGroupMembers(ctx context.Context, tx Tx, orgID, id int64, changes []SCIMGroupMemberChange) error {
	if len(changes) == 0 {
		return nil
	}
	current, err := uc.SCIM.GroupMembers(ctx, tx, id)
	if err != nil {
		return ErrDependency
	}
	set := make(map[int64]struct{}, len(current))
	for _, uid := range current {
		set[uid] = struct{}{}
	}
	for _, change := range changes {
		if change.Replace {
			clear(set)
		}
		if change.Remove {
			for _, uid := range change.IDs {
				delete(set, uid)
			}
			continue
		}
		if err := uc.validGroupMembers(ctx, tx, orgID, change.IDs); err != nil {
			return err
		}
		for _, uid := range change.IDs {
			set[uid] = struct{}{}
		}
	}
	next := make([]int64, 0, len(set))
	for uid := range set {
		next = append(next, uid)
	}
	if err := uc.SCIM.SetGroupMembers(ctx, tx, id, next); err != nil {
		return ErrDependency
	}
	return nil
}

// validGroupMembers refuses ids that are not provisioned users of THIS tenant.
// Without it, a SCIM client could put an arbitrary platform user id into a
// group and make the group enumeration disclose foreign accounts.
func (uc *SCIMUsecase) validGroupMembers(ctx context.Context, tx Tx, orgID int64, ids []int64) error {
	for _, uid := range ids {
		if _, _, _, err := uc.localUser(ctx, tx, orgID, uid); err != nil {
			if !errors.Is(err, ErrResourceNotFound) {
				return err
			}
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
