package biz

import (
	"context"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Tx is an opaque transaction handle owned by the data layer. Passing nil
// means "use the default connection".
type Tx any

type TxManager interface {
	InTx(context.Context, func(context.Context, Tx) error) error
}

type UserRepo interface {
	Create(context.Context, Tx, *User) (*User, error)
	Get(context.Context, Tx, int64) (*User, error)
	GetByUsername(context.Context, Tx, string) (*User, error)
	GetByEmail(context.Context, Tx, string) (*User, error)
	Update(context.Context, Tx, *User, uint64) (*User, error)
	BumpIdentityVersion(context.Context, Tx, int64) (uint64, error)
	List(context.Context, Tx, UserFilter) ([]*User, int64, error)
	CountByStatus(context.Context, Tx, authorization.Scope) (map[string]int64, error)
	CountMFA(context.Context, Tx, authorization.Scope) (int64, error)
	Overview(context.Context, Tx, UserFilter, time.Time, time.Time) (*Overview, error)
	RolesForUser(context.Context, Tx, int64) ([]RoleRef, error)
	CountsByRole(context.Context, Tx, int64) (int64, error)
}

type UserFilter struct {
	Keyword     string
	Status      string
	RoleID      int64
	MFA         *bool
	Scope       authorization.Scope
	ActorID     int64
	Offset      int
	Limit       int
	Fields      []string
	ExcludedIDs []int64
	SearchEmail bool
}

type CredentialRepo interface {
	Get(context.Context, Tx, int64) (*Credential, error)
	Create(context.Context, Tx, *Credential) error
	UpdatePassword(context.Context, Tx, int64, string, string, uint64, bool) (uint64, error)
	BumpPasswordVersion(context.Context, Tx, int64) (uint64, error)
}

type ExternalIdentityRepo interface {
	ListByUser(context.Context, Tx, int64) ([]*ExternalIdentity, error)
	GetByID(context.Context, Tx, int64) (*ExternalIdentity, error)
	FindBySubject(context.Context, Tx, string, string, string) (*ExternalIdentity, error)
	Create(context.Context, Tx, *ExternalIdentity) (*ExternalIdentity, error)
	Delete(context.Context, Tx, int64, int64) error
	CountByUser(context.Context, Tx, int64) (int64, error)
}

type MFARepo interface {
	Get(context.Context, Tx, int64) (*MFAState, error)
	Save(context.Context, Tx, *MFAState) error
	Delete(context.Context, Tx, int64) error
}

type SessionRepo interface {
	Create(context.Context, Tx, *Session) error
	GetByTokenHash(context.Context, Tx, string) (*Session, error)
	Get(context.Context, Tx, string) (*Session, error)
	ListByUser(context.Context, Tx, int64) ([]*Session, error)
	Touch(context.Context, Tx, string, time.Time, time.Time) error
	Revoke(context.Context, Tx, string, *time.Time) error
	RevokeAllForUser(context.Context, Tx, int64, *time.Time) error
	CountActive(context.Context, Tx) (int64, error)
	ListActiveRoleIDs(context.Context, Tx, string) ([]int64, error)
	SetActiveRoleIDs(context.Context, Tx, string, []int64, uint64) error
	SetIdentityVersion(context.Context, Tx, string, uint64) error
}

type SecurityEventRepo interface {
	Append(context.Context, Tx, *SecurityEvent) error
	ListByUser(context.Context, Tx, int64, int, string) ([]*SecurityEvent, string, error)
	CountRecent(context.Context, Tx, string, time.Time) (int64, error)
}

type FlowCompletionRepo interface {
	Complete(context.Context, Tx, string, string, int64, string) error
}

type ChallengeStore interface {
	Put(context.Context, Challenge) error
	// Verify checks the code and increments the attempt counter without
	// consuming the challenge. Consumption happens after the DB commit via
	// Delete, keeping the DB unique completion record authoritative.
	Verify(context.Context, string, string, string) (Challenge, error)
	Get(context.Context, string, string) (Challenge, error)
	Delete(context.Context, string) error
}

type Challenge struct {
	ID        string
	Purpose   string
	CodeHash  string
	UserID    int64
	Email     string
	Payload   string
	Attempts  int
	ExpiresAt time.Time
}

type RateLimiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type StepUpStore interface {
	Put(context.Context, string, time.Time) error
	Get(context.Context, string) (time.Time, error)
	Delete(context.Context, string) error
}

type MailSender interface {
	Send(context.Context, string, string, string) error
}

type AuditRepo interface {
	Append(context.Context, Tx, *AuditEvent) error
	List(context.Context, Tx, AuditFilter) ([]*AuditEvent, int64, error)
	Get(context.Context, Tx, string) (*AuditEvent, error)
}

type AuditFilter struct {
	Action      string
	ActorUserID int64
	Target      string
	From        *time.Time
	To          *time.Time
	Offset      int
	Limit       int
}

type PolicyRepo interface {
	PolicyRevision(context.Context, Tx) (uint64, error)
	BumpPolicyRevision(context.Context, Tx) (uint64, error)
	UserRevision(context.Context, Tx, int64) (uint64, error)
}

type IAMRepo interface {
	ListResources(context.Context, Tx) ([]*Resource, error)
	ListPermissions(context.Context, Tx, PermissionFilter) ([]*Permission, error)
	GetPermission(context.Context, Tx, int64) (*Permission, error)
	GetPermissionByCode(context.Context, Tx, string) (*Permission, error)
	CreatePermission(context.Context, Tx, *Permission) (*Permission, error)
	UpdatePermission(context.Context, Tx, *Permission, uint64) (*Permission, error)
	ListRoles(context.Context, Tx, RoleFilter) ([]*Role, error)
	GetRole(context.Context, Tx, int64) (*Role, error)
	GetRoleByCode(context.Context, Tx, string) (*Role, error)
	CreateRole(context.Context, Tx, *Role) (*Role, error)
	UpdateRole(context.Context, Tx, *Role, uint64) (*Role, error)
	PutRoleGrants(context.Context, Tx, int64, []Grant, uint64) (uint64, error)
	PutRoleInheritance(context.Context, Tx, int64, []int64, uint64) (uint64, error)
	ListAssignmentsForUser(context.Context, Tx, int64) ([]*Assignment, error)
	GetAssignment(context.Context, Tx, int64) (*Assignment, error)
	CreateAssignment(context.Context, Tx, *Assignment) (*Assignment, error)
	RevokeAssignment(context.Context, Tx, int64, uint64, int64) error
	ListAssignmentsForRole(context.Context, Tx, int64) ([]*Assignment, error)
	ListRoleMembers(context.Context, Tx, int64) ([]RoleMember, error)
	CountActiveAssignmentsForRole(context.Context, Tx, int64) (int64, error)
	ListAllRolesWithGrants(context.Context, Tx) ([]*Role, error)
	ListAssignments(context.Context, Tx, AssignmentFilter) ([]*AssignmentItem, int64, error)
	ListConstraints(context.Context, Tx) ([]*Constraint, error)
	ListDelegations(context.Context, Tx, DelegationFilter) ([]*Delegation, error)
	GetDelegation(context.Context, Tx, int64) (*Delegation, error)
	CreateDelegation(context.Context, Tx, *Delegation) (*Delegation, error)
	UpdateDelegation(context.Context, Tx, *Delegation, uint64) (*Delegation, error)
	RevokeDelegation(context.Context, Tx, int64, uint64, int64) error
	GetConstraint(context.Context, Tx, int64) (*Constraint, error)
	CreateConstraint(context.Context, Tx, *Constraint) (*Constraint, error)
	UpdateConstraint(context.Context, Tx, *Constraint, uint64) (*Constraint, error)
	DeleteConstraint(context.Context, Tx, int64) error
	ListMenus(context.Context, Tx) ([]*MenuItem, error)
	GetMenu(context.Context, Tx, int64) (*MenuItem, error)
	CreateMenu(context.Context, Tx, *MenuItem) (*MenuItem, error)
	UpdateMenu(context.Context, Tx, *MenuItem, uint64) (*MenuItem, error)
}

type PermissionFilter struct {
	Category string
	Status   string
	Keyword  string
}

type DelegationFilter struct {
	ManagerRoleID int64
	TargetRoleID  int64
	Status        string
}

type RoleFilter struct {
	Status  string
	Keyword string
}

type AssignmentFilter struct {
	UserID int64
	RoleID int64
	Status string
	Offset int
	Limit  int
}

type AssignmentItem struct {
	Assignment  *Assignment
	Username    string
	DisplayName string
	RoleCode    string
	RoleName    string
}

type OutboxRepo interface {
	Append(context.Context, Tx, *Event) error
	PendingEventsForClient(context.Context, Tx, *IntegrationClient, int) ([]*Event, error)
	EnsureDelivery(context.Context, Tx, string, string, time.Time) error
	DueDeliveries(context.Context, Tx, time.Time, int) ([]*Delivery, error)
	ListDeliveries(context.Context, Tx, string, int, int) ([]*Delivery, int64, error)
	RetryDelivery(context.Context, Tx, string, string) error
	MarkDelivered(context.Context, string, string, time.Time) error
	MarkRetry(context.Context, string, string, time.Time, string) error
}

type IntegrationClientRepo interface {
	List(context.Context, Tx) ([]*IntegrationClient, error)
	Get(context.Context, Tx, int64) (*IntegrationClient, error)
	GetByClientID(context.Context, Tx, string) (*IntegrationClient, error)
	Create(context.Context, Tx, *IntegrationClient) (*IntegrationClient, error)
	Update(context.Context, Tx, *IntegrationClient, uint64) (*IntegrationClient, error)
	RotateCredential(context.Context, Tx, int64, string, int) (*IntegrationClient, error)
	Disable(context.Context, Tx, int64) error
}

type SettingsRepo interface {
	GetAuth(context.Context, Tx) (*AuthSettings, error)
	SaveAuth(context.Context, Tx, *AuthSettings, uint64) (*AuthSettings, error)
	GetEmail(context.Context, Tx) (*EmailSettings, string, error)
	SaveEmail(context.Context, Tx, *EmailSettings, string, uint64) (*EmailSettings, error)
}

type ExportRepo interface {
	Create(context.Context, Tx, *ExportJob) (*ExportJob, error)
	Get(context.Context, int64) (*ExportJob, error)
	ListByActor(context.Context, int64, int, string) ([]*ExportJob, string, error)
}

type Clock interface{ Now() time.Time }
type IDGenerator interface{ NewID() string }
type SecretBox interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type OIDCClientRepo interface {
	ListOIDCClients(context.Context, Tx) ([]*OIDCClient, error)
	GetOIDCClient(context.Context, Tx, int64) (*OIDCClient, error)
	GetOIDCClientByClientID(context.Context, Tx, string) (*OIDCClient, error)
	CreateOIDCClient(context.Context, Tx, *OIDCClient) (*OIDCClient, error)
	UpdateOIDCClient(context.Context, Tx, *OIDCClient, uint64) (*OIDCClient, error)
	RotateOIDCClientSecret(context.Context, Tx, int64, string) (*OIDCClient, error)
	DisableOIDCClient(context.Context, Tx, int64) error
}

type OIDCCodeRepo interface {
	CreateOIDCCode(context.Context, Tx, *OIDCCode) error
	ConsumeOIDCCode(context.Context, Tx, string, string, string, time.Time) (*OIDCCode, error)
	CreateOIDCRefreshToken(context.Context, Tx, *OIDCRefreshToken) error
	ConsumeOIDCRefreshToken(context.Context, Tx, string, string, time.Time) (*OIDCRefreshToken, error)
}

// OIDCSigner owns the RSA key used for ID/access tokens.
type OIDCSigner interface {
	KeyID() string
	Sign(map[string]any) (string, error)
	Verify(string) (map[string]any, error)
	PublicJWK() map[string]any
}
