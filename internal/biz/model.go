package biz

import (
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// ProvidersDisabledAll is the explicit "no external provider" entry in
// AuthSettings.Providers. An empty list keeps the legacy meaning of "every
// configured provider is enabled"; this sentinel makes "disable all"
// distinguishable without adding a new settings column.
const ProvidersDisabledAll = "none"

const (
	UserStatusEnabled  = "enabled"
	UserStatusDisabled = "disabled"
	UserStatusArchived = "archived"

	ApplicationCode = "user-center"

	OriginDefault   = "default"
	OriginBootstrap = "bootstrap"
	OriginExplicit  = "explicit"
	OriginLegacy    = "legacy_candidate"

	RoleStatusActive   = "active"
	RoleStatusDisabled = "disabled"
	RoleStatusArchived = "archived"

	PermissionStatusActive   = "active"
	PermissionStatusDisabled = "disabled"
	PermissionStatusArchived = "archived"

	BindingBound   = "bound"
	BindingUnbound = "unbound"

	ExportPending = "pending"
	ExportReady   = "ready"
	ExportFailed  = "failed"
)

type User struct {
	ID                 int64
	Username           string
	UsernameNormalized string
	DisplayName        string
	Email              string
	EmailNormalized    string
	EmailVerified      bool
	Status             string
	Revision           uint64
	IdentityVersion    uint64
	MFAEnabled         bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	ArchivedAt         *time.Time
	AnonymizedAt       *time.Time
	Roles              []RoleRef
}

type RoleRef struct {
	ID   int64
	Code string
	Name string
}

type Credential struct {
	UserID             int64
	PasswordHash       string
	Algorithm          string
	PasswordVersion    uint64
	MustChangePassword bool
	Revision           uint64
	UpdatedAt          time.Time
}

type ExternalIdentity struct {
	ID              int64
	UserID          int64
	Provider        string
	ProviderSubject string
	Issuer          string
	Display         string
	CreatedAt       time.Time
}

type MFAState struct {
	UserID         int64
	Secret         string
	KeyVersion     int
	PendingSecret  string
	PendingSession string
	PendingUntil   time.Time
	RecoveryHashes []string
	LastStep       int64
	Failures       int
	LockedUntil    time.Time
	Revision       uint64
}

func (m MFAState) Enabled() bool { return m.Secret != "" }

type Session struct {
	ID              string
	UserID          int64
	ApplicationCode string
	TokenHash       string
	UserAgent       string
	IPMasked        string
	IssuedAt        time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	IdleExpiresAt   time.Time
	RevokedAt       *time.Time
	IdentityVersion uint64
	Revision        uint64
	ActiveRoleIDs   []int64
}

func (s Session) Valid(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

type SecurityEvent struct {
	ID               string
	UserID           int64
	SessionID        string
	Kind             string
	Result           string
	IPMasked         string
	UserAgentSummary string
	RequestID        string
	OccurredAt       time.Time
}

type Role struct {
	ID                   int64
	Code                 string
	Name                 string
	Description          string
	Builtin              bool
	Status               string
	MaxMembers           *int64
	Revision             uint64
	CreationDelegationID int64
	Inherits             []int64
	Grants               []Grant
	// Context is the authorization domain the role belongs to. The zero value
	// is the platform context.
	Context authorization.Context
}

type Grant struct {
	Operation string
	Effect    authorization.Effect
	Scope     authorization.Scope
}

type Assignment struct {
	ID         int64
	UserID     int64
	RoleID     int64
	Boundary   authorization.Scope
	StartsAt   time.Time
	ExpiresAt  *time.Time
	Revoked    bool
	Origin     string
	Revision   uint64
	AssignedBy int64
	CreatedAt  time.Time
	// Context is the tenant the assignment was issued in; it never applies to
	// another context.
	Context authorization.Context
}

func (a Assignment) Active(now time.Time) bool {
	if a.Revoked || now.Before(a.StartsAt) {
		return false
	}
	return a.ExpiresAt == nil || now.Before(*a.ExpiresAt)
}

type Resource struct {
	ID      int64
	Code    string
	Name    string
	Owner   string
	Enabled bool
}

type Permission struct {
	ID              int64
	ResourceID      int64
	Code            string
	Name            string
	Category        string
	RiskLevel       string
	Status          string
	Binding         string
	SupportedScopes []string
	ContextTypes    []string
	Protected       bool
	Description     string
	Sort            int32
	Revision        uint64
}

func (p Permission) ScopeKinds() []authorization.ScopeKind {
	out := make([]authorization.ScopeKind, 0, len(p.SupportedScopes))
	for _, s := range p.SupportedScopes {
		out = append(out, authorization.ScopeKind(s))
	}
	return out
}

type DelegationCeiling struct {
	Operation string
	Scope     authorization.Scope
}

type Delegation struct {
	ID              int64
	ManagerRoleID   int64
	TargetRoleID    int64
	TargetKind      string
	Actions         []string
	TargetUserScope authorization.Scope
	GrantCeiling    []DelegationCeiling
	CanRedelegate   bool
	StartsAt        time.Time
	ExpiresAt       *time.Time
	RevokedAt       *time.Time
	Revision        uint64
	CreatedBy       int64
	CreatedAt       time.Time
}

func (d Delegation) Active(now time.Time) bool {
	if d.RevokedAt != nil || now.Before(d.StartsAt) {
		return false
	}
	return d.ExpiresAt == nil || now.Before(*d.ExpiresAt)
}

type Constraint struct {
	ID       int64
	Kind     string
	Name     string
	RoleIDs  []int64
	MaxCount int64
	Enabled  bool
	Revision uint64
}

type MenuItem struct {
	ID          int64
	ParentID    int64
	RouteKey    string
	Name        string
	IconKey     string
	Sort        int32
	Enabled     bool
	RequiredAll []string
	RequiredAny []string
	Revision    uint64
}

type AuditEvent struct {
	EventID        string
	ActorUserID    int64
	ActorServiceID string
	ActorSessionID string
	Action         string
	Target         string
	Before         string
	After          string
	Diff           string
	Result         string
	Reason         string
	RequestID      string
	Versions       string
	OccurredAt     time.Time
	// OrganizationID scopes the event to one tenant; 0 is platform level.
	OrganizationID int64
}

type ExportJob struct {
	ID              int64
	Kind            string
	ActorUserID     int64
	ActorSessionID  string
	ScopeSnapshot   string
	RequestedFields []string
	Status          string
	ArtifactName    string
	Error           string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	// OrganizationID scopes tenant exports; 0 is a platform export.
	OrganizationID int64
}

type Event struct {
	EventID           string
	AggregateType     string
	AggregateID       int64
	AggregateRevision uint64
	EventType         string
	SchemaVersion     int
	Payload           string
	OccurredAt        time.Time
}

type OutboxDelivery struct {
	EventID      string
	SubscriberID string
	Attempts     int
	NextRetryAt  time.Time
	Status       string
	LastError    string
}

type IntegrationClient struct {
	ID                 int64
	ClientID           string
	Code               string
	ServiceOwner       string
	Status             string
	CredentialHash     string
	CredentialVersion  int
	AllowedMethods     []string
	EventSubscriptions []string
	CallbackURL        string
	ExpiresAt          *time.Time
	Revision           uint64
	CreatedAt          time.Time
}

type Delivery struct {
	EventID           string
	EventType         string
	SubscriberID      string
	Status            string
	Attempts          int
	NextRetryAt       time.Time
	LastError         string
	Payload           string
	AggregateType     string
	AggregateID       int64
	AggregateRevision uint64
	SchemaVersion     int
	OccurredAt        time.Time
	CallbackURL       string
}

type AuthSettings struct {
	RegistrationEnabled       bool
	EmailVerificationRequired bool
	PasswordMinLength         int
	SessionTTLMinutes         int
	IdleTimeoutMinutes        int
	MFARequiredForAdmins      bool
	AllowedEmailDomains       []string
	Providers                 []string
	Revision                  uint64
	UpdatedAt                 time.Time
}

type EmailSettings struct {
	Driver       string
	From         string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	PasswordSet  bool
	Revision     uint64
}

type OIDCClient struct {
	ID           int64
	ClientID     string
	Name         string
	ServiceOwner string
	Status       string
	SecretHash   string
	RedirectURIs []string
	// PostLogoutRedirectURIs is the exact-match whitelist for end_session.
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Public                 bool
	RequirePKCE            bool
	AccessTTL              int
	RefreshTTL             int
	Revision               uint64
	CreatedAt              time.Time
}

// OIDCConsent is the scope set a user already approved for one client.
type OIDCConsent struct {
	ClientID  string
	UserID    int64
	Scopes    []string
	GrantedAt time.Time
	UpdatedAt time.Time
	Revision  uint64
}

// OIDCConsentRequest is the parked authorize request awaiting a decision.
type OIDCConsentRequest struct {
	HandleHash          string
	ClientID            string
	UserID              int64
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	IdentityVersion     uint64
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

type OIDCCode struct {
	CodeHash            string
	ClientID            string
	UserID              int64
	IdentityVersion     uint64
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

type OIDCRefreshToken struct {
	TokenHash       string
	FamilyID        string
	ClientID        string
	UserID          int64
	IdentityVersion uint64
	Scope           string
	AuthTime        time.Time
	ExpiresAt       time.Time
}

const (
	OrgStatusActive   = "active"
	OrgStatusArchived = "archived"
	OrgRoleOwner      = "owner"
	OrgRoleAdmin      = "admin"
	OrgRoleMember     = "member"
	OrgMemberActive   = "active"
	OrgMemberRemoved  = "removed"
)

// Organization-scoped IAM. Membership roles are the coarse projection; the
// built-in roles below are materialized per organization so grants, custom
// roles and assignments stay inside one tenant.
const (
	OrgRoleCodeOwner  = "org_owner"
	OrgRoleCodeAdmin  = "org_admin"
	OrgRoleCodeMember = "org_member"

	PermOrgMemberRead       = "organization.member.read"
	PermOrgMemberManage     = "organization.member.manage"
	PermOrgDepartmentRead   = "organization.department.read"
	PermOrgDepartmentManage = "organization.department.manage"
	PermOrgRoleRead         = "organization.iam.role.read"
	PermOrgRoleManage       = "organization.iam.role.manage"
	PermOrgAssignmentRead   = "organization.iam.assignment.read"
	PermOrgAssignmentManage = "organization.iam.assignment.manage"
	PermOrgAuditRead        = "organization.audit.read"
	PermOrgSettingsUpdate   = "organization.settings.update"
	PermOrgArchive          = "organization.archive"
	PermOrgAdminRead        = "organization.admin.read"
	PermOrgAdminUpdate      = "organization.admin.update"
)

func OrgRoleCode(membershipRole string) string {
	switch membershipRole {
	case OrgRoleOwner:
		return OrgRoleCodeOwner
	case OrgRoleAdmin:
		return OrgRoleCodeAdmin
	default:
		return OrgRoleCodeMember
	}
}

func OrgRoleCodes() []string {
	return []string{OrgRoleCodeOwner, OrgRoleCodeAdmin, OrgRoleCodeMember}
}

type Organization struct {
	ID          int64
	Code        string
	Name        string
	Status      string
	Revision    uint64
	CreatedBy   int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
	Role        string
	MemberCount int64
}

type OrganizationMember struct {
	ID             int64
	OrganizationID int64
	UserID         int64
	Username       string
	DisplayName    string
	Email          string
	Role           string
	DepartmentID   *int64
	Status         string
	Revision       uint64
	InvitedBy      int64
	JoinedAt       time.Time
}

type Department struct {
	ID             int64
	OrganizationID int64
	ParentID       int64
	Code           string
	Name           string
	Status         string
	Revision       uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const (
	OrgInvitationPending  = "pending"
	OrgInvitationAccepted = "accepted"
	OrgInvitationRevoked  = "revoked"
	OrgInvitationExpired  = "expired"
)

// OrganizationInvitation is an e-mail invitation to join a tenant. The raw
// token only ever exists in the invitation message; the row stores its hash.
type OrganizationInvitation struct {
	ID                int64
	OrganizationID    int64
	Email             string
	EmailNormalized   string
	Role              string
	DepartmentID      *int64
	TokenHash         string
	Status            string
	InvitedBy         int64
	InvitedByUsername string
	AcceptedBy        int64
	ExpiresAt         time.Time
	AcceptedAt        *time.Time
	Revision          uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (i OrganizationInvitation) Pending(now time.Time) bool {
	return i.Status == OrgInvitationPending && now.Before(i.ExpiresAt)
}

// OrganizationSettings is the platform-level organization policy. Quota is off
// by default: enabling it is an operator decision, not a silent restriction.
// LegalHold exempts an archived account from the retention cleanup job.
type LegalHold struct {
	UserID     int64
	Reason     string
	CreatedAt  time.Time
	ReleasedAt *time.Time
}

// WebAuthnCredential is a registered platform/passkey authenticator. The
// public key is the raw COSE_Key CBOR blob; no attestation chain is retained.
type WebAuthnCredential struct {
	ID           int64
	UserID       int64
	CredentialID string
	Name         string
	PublicKey    []byte
	SignCount    uint32
	AAGUID       string
	Transports   []string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	Revision     uint64
}

type OrganizationSettings struct {
	QuotaEnabled    bool
	MaxOwnedPerUser int
	CountArchived   bool
	Revision        uint64
	UpdatedAt       time.Time
}
