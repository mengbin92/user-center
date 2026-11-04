package data

import "time"

type userPO struct {
	ID                 int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Username           string     `gorm:"column:username;size:128;not null"`
	UsernameNormalized string     `gorm:"column:username_normalized;size:128;not null;uniqueIndex"`
	DisplayName        string     `gorm:"column:display_name;size:128;not null"`
	Email              *string    `gorm:"column:email;size:254"`
	EmailNormalized    *string    `gorm:"column:email_normalized;size:254;uniqueIndex"`
	EmailVerifiedAt    *time.Time `gorm:"column:email_verified_at"`
	Status             string     `gorm:"column:status;size:16;not null;index"`
	Revision           uint64     `gorm:"column:revision;not null;default:1"`
	IdentityVersion    uint64     `gorm:"column:identity_version;not null;default:1"`
	CreatedAt          time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt          time.Time  `gorm:"column:updated_at;not null"`
	ArchivedAt         *time.Time `gorm:"column:archived_at"`
}

func (userPO) TableName() string { return "users" }

type credentialPO struct {
	UserID             int64     `gorm:"column:user_id;primaryKey"`
	PasswordHash       string    `gorm:"column:password_hash;size:255"`
	Algorithm          string    `gorm:"column:algorithm;size:32;not null"`
	PasswordVersion    uint64    `gorm:"column:password_version;not null;default:1"`
	MustChangePassword bool      `gorm:"column:must_change_password;not null;default:false"`
	Revision           uint64    `gorm:"column:revision;not null;default:1"`
	UpdatedAt          time.Time `gorm:"column:updated_at;not null"`
}

func (credentialPO) TableName() string { return "user_credentials" }

type mfaPO struct {
	UserID         int64      `gorm:"column:user_id;primaryKey"`
	Secret         string     `gorm:"column:secret_ciphertext;size:512"`
	KeyVersion     int        `gorm:"column:key_version;not null;default:1"`
	PendingSecret  string     `gorm:"column:pending_secret;size:512"`
	PendingSession string     `gorm:"column:pending_session;size:64"`
	PendingUntil   *time.Time `gorm:"column:pending_until"`
	RecoveryHashes string     `gorm:"column:recovery_hashes;type:text"`
	LastStep       int64      `gorm:"column:last_step;not null;default:0"`
	Failures       int        `gorm:"column:failures;not null;default:0"`
	LockedUntil    *time.Time `gorm:"column:locked_until"`
	Revision       uint64     `gorm:"column:revision;not null;default:1"`
}

func (mfaPO) TableName() string { return "identity_mfa" }

type externalIdentityPO struct {
	ID              int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID          int64     `gorm:"column:user_id;not null;index"`
	Provider        string    `gorm:"column:provider;size:32;not null"`
	ProviderSubject string    `gorm:"column:provider_subject;size:191;not null"`
	Issuer          string    `gorm:"column:issuer;size:191;not null;default:''"`
	Display         string    `gorm:"column:display;size:191"`
	CreatedAt       time.Time `gorm:"column:created_at;not null"`
	UpdatedAt       time.Time `gorm:"column:updated_at;not null"`
}

func (externalIdentityPO) TableName() string { return "user_oauth_identities" }

type sessionPO struct {
	ID              string     `gorm:"column:id;size:64;primaryKey"`
	UserID          int64      `gorm:"column:user_id;not null;index"`
	ApplicationCode string     `gorm:"column:application_code;size:64;not null"`
	TokenHash       string     `gorm:"column:credential_hash;size:64;not null;uniqueIndex"`
	UserAgent       string     `gorm:"column:user_agent;size:255"`
	IPMasked        string     `gorm:"column:ip_masked;size:64"`
	IssuedAt        time.Time  `gorm:"column:issued_at;not null"`
	LastSeenAt      time.Time  `gorm:"column:last_seen_at;not null"`
	ExpiresAt       time.Time  `gorm:"column:expires_at;not null;index"`
	IdleExpiresAt   time.Time  `gorm:"column:idle_expires_at;not null"`
	RevokedAt       *time.Time `gorm:"column:revoked_at"`
	IdentityVersion uint64     `gorm:"column:identity_version;not null"`
	Revision        uint64     `gorm:"column:revision;not null;default:1"`
}

func (sessionPO) TableName() string { return "iam_sessions" }

type sessionRolePO struct {
	SessionID string    `gorm:"column:session_id;size:64;primaryKey"`
	RoleID    int64     `gorm:"column:role_id;primaryKey"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (sessionRolePO) TableName() string { return "iam_session_roles" }

type securityEventPO struct {
	ID               string    `gorm:"column:event_id;size:64;primaryKey"`
	UserID           int64     `gorm:"column:user_id;index"`
	SessionID        string    `gorm:"column:session_id;size:64"`
	Kind             string    `gorm:"column:kind;size:32;not null"`
	Result           string    `gorm:"column:result;size:16;not null"`
	IPMasked         string    `gorm:"column:ip_masked;size:64"`
	UserAgentSummary string    `gorm:"column:user_agent_summary;size:255"`
	RequestID        string    `gorm:"column:request_id;size:64"`
	OccurredAt       time.Time `gorm:"column:occurred_at;not null;index"`
}

func (securityEventPO) TableName() string { return "security_events" }

type flowCompletionPO struct {
	ChallengeID string    `gorm:"column:challenge_id;size:64;primaryKey"`
	Purpose     string    `gorm:"column:purpose;size:32;primaryKey"`
	UserID      int64     `gorm:"column:user_id;not null"`
	ResultRef   string    `gorm:"column:result_ref;size:128"`
	CompletedAt time.Time `gorm:"column:completed_at;not null"`
}

func (flowCompletionPO) TableName() string { return "auth_flow_completions" }

type policyStatePO struct {
	ID                int64  `gorm:"column:id;primaryKey"`
	PolicyRevision    uint64 `gorm:"column:policy_revision;not null"`
	CatalogRevision   uint64 `gorm:"column:catalog_revision;not null"`
	AuthorizationMode string `gorm:"column:authorization_mode;size:16;not null"`
	CutoverState      string `gorm:"column:cutover_state;size:16;not null"`
	CutoverBatchID    string `gorm:"column:cutover_batch_id;size:64"`
}

func (policyStatePO) TableName() string { return "iam_policy_state" }

type resourcePO struct {
	ID      int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Code    string `gorm:"column:code;size:128;not null;uniqueIndex"`
	Name    string `gorm:"column:name;size:128;not null"`
	Owner   string `gorm:"column:owner;size:64;not null"`
	Enabled bool   `gorm:"column:enabled;not null;default:true"`
}

func (resourcePO) TableName() string { return "iam_resources" }

type permissionPO struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ResourceID      int64  `gorm:"column:resource_id;not null;index"`
	Code            string `gorm:"column:code;size:128;not null;uniqueIndex"`
	Name            string `gorm:"column:name;size:128;not null"`
	Category        string `gorm:"column:category;size:64"`
	RiskLevel       string `gorm:"column:risk_level;size:16;not null"`
	Status          string `gorm:"column:status;size:16;not null"`
	Binding         string `gorm:"column:binding;size:16;not null"`
	SupportedScopes string `gorm:"column:supported_scopes;type:text"`
	ContextTypes    string `gorm:"column:context_types;type:text"`
	Protected       bool   `gorm:"column:protected;not null;default:false"`
	Description     string `gorm:"column:description;size:512"`
	Sort            int32  `gorm:"column:sort;not null;default:0"`
	Revision        uint64 `gorm:"column:revision;not null;default:1"`
}

func (permissionPO) TableName() string { return "iam_permissions" }

type rolePO struct {
	ID                   int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Code                 string `gorm:"column:code;size:64;not null;uniqueIndex:uk_iam_roles_context_code,priority:3"`
	Name                 string `gorm:"column:name;size:128;not null"`
	Description          string `gorm:"column:description;size:512"`
	Builtin              bool   `gorm:"column:builtin;not null;default:false"`
	Status               string `gorm:"column:status;size:16;not null"`
	MaxMembers           *int64 `gorm:"column:max_members"`
	Revision             uint64 `gorm:"column:revision;not null;default:1"`
	CreationDelegationID int64  `gorm:"column:creation_delegation_id;not null;default:0"`
	// ContextType/ContextID scope the role to the platform or one organization.
	// Rows written before V2.3 are platform policy by definition.
	ContextType string `gorm:"column:context_type;size:16;not null;default:platform;uniqueIndex:uk_iam_roles_context_code,priority:1;index:idx_iam_roles_context,priority:1"`
	ContextID   int64  `gorm:"column:context_id;not null;default:0;uniqueIndex:uk_iam_roles_context_code,priority:2;index:idx_iam_roles_context,priority:2"`
}

func (rolePO) TableName() string { return "iam_roles" }

type roleGrantPO struct {
	RoleID    int64  `gorm:"column:role_id;primaryKey"`
	Operation string `gorm:"column:operation;size:128;primaryKey"`
	Effect    string `gorm:"column:effect;size:16;not null"`
	Scope     string `gorm:"column:scope;type:text;not null"`
}

func (roleGrantPO) TableName() string { return "iam_role_permissions" }

type roleInheritancePO struct {
	RoleID     int64 `gorm:"column:role_id;primaryKey"`
	InheritsID int64 `gorm:"column:inherits_role_id;primaryKey"`
}

func (roleInheritancePO) TableName() string { return "iam_role_inheritance" }

type assignmentPO struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     int64      `gorm:"column:user_id;not null;index"`
	RoleID     int64      `gorm:"column:role_id;not null;index"`
	Boundary   string     `gorm:"column:boundary;type:text;not null"`
	StartsAt   time.Time  `gorm:"column:starts_at;not null"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
	Status     string     `gorm:"column:status;size:16;not null"`
	Origin     string     `gorm:"column:origin;size:32;not null"`
	Revision   uint64     `gorm:"column:revision;not null;default:1"`
	AssignedBy int64      `gorm:"column:assigned_by;not null;default:0"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	// The assignment is only valid inside its own context.
	ContextType string `gorm:"column:context_type;size:16;not null;default:platform;index:idx_iam_user_roles_context,priority:1"`
	ContextID   int64  `gorm:"column:context_id;not null;default:0;index:idx_iam_user_roles_context,priority:2"`
}

func (assignmentPO) TableName() string { return "iam_user_roles" }

type delegationPO struct {
	ID              int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ManagerRoleID   int64      `gorm:"column:manager_role_id;not null;index"`
	TargetRoleID    int64      `gorm:"column:target_role_id;not null;index"`
	TargetKind      string     `gorm:"column:target_kind;size:32;not null"`
	Actions         string     `gorm:"column:actions;type:text;not null"`
	TargetUserScope string     `gorm:"column:target_user_scope;type:text;not null"`
	GrantCeiling    string     `gorm:"column:grant_ceiling;type:text;not null"`
	CanRedelegate   bool       `gorm:"column:can_redelegate;not null;default:false"`
	StartsAt        time.Time  `gorm:"column:starts_at;not null"`
	ExpiresAt       *time.Time `gorm:"column:expires_at"`
	RevokedAt       *time.Time `gorm:"column:revoked_at"`
	Revision        uint64     `gorm:"column:revision;not null;default:1"`
	CreatedBy       int64      `gorm:"column:created_by;not null;default:0"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
}

func (delegationPO) TableName() string { return "iam_delegations" }

type constraintPO struct {
	ID       int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Kind     string `gorm:"column:kind;size:32;not null"`
	Name     string `gorm:"column:name;size:128;not null"`
	RoleIDs  string `gorm:"column:role_ids;type:text;not null"`
	MaxCount int64  `gorm:"column:max_count;not null;default:0"`
	Enabled  bool   `gorm:"column:enabled;not null;default:true"`
	Revision uint64 `gorm:"column:revision;not null;default:1"`
}

func (constraintPO) TableName() string { return "iam_role_constraints" }

type menuPO struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ParentID    int64  `gorm:"column:parent_id;not null;default:0"`
	RouteKey    string `gorm:"column:route_key;size:128;not null;uniqueIndex"`
	Name        string `gorm:"column:name;size:128;not null"`
	IconKey     string `gorm:"column:icon_key;size:64"`
	Sort        int32  `gorm:"column:sort;not null;default:0"`
	Enabled     bool   `gorm:"column:enabled;not null;default:true"`
	RequiredAll string `gorm:"column:required_all;type:text"`
	RequiredAny string `gorm:"column:required_any;type:text"`
	Revision    uint64 `gorm:"column:revision;not null;default:1"`
}

func (menuPO) TableName() string { return "iam_menu_items" }

type auditEventPO struct {
	EventID        string    `gorm:"column:event_id;size:64;primaryKey"`
	ActorUserID    int64     `gorm:"column:actor_user_id;index"`
	ActorServiceID string    `gorm:"column:actor_service_id;size:64"`
	ActorSessionID string    `gorm:"column:actor_session_id;size:64"`
	Action         string    `gorm:"column:action;size:128;not null;index"`
	Target         string    `gorm:"column:target;size:191;index"`
	BeforeData     string    `gorm:"column:before_data;type:text"`
	AfterData      string    `gorm:"column:after_data;type:text"`
	Diff           string    `gorm:"column:diff;type:text"`
	Result         string    `gorm:"column:result;size:16;not null"`
	Reason         string    `gorm:"column:reason;size:512"`
	RequestID      string    `gorm:"column:request_id;size:64"`
	Versions       string    `gorm:"column:authorization_versions;type:text"`
	OccurredAt     time.Time `gorm:"column:occurred_at;not null;index"`
	// OrganizationID scopes tenant audit: 0 means a platform-level event.
	OrganizationID int64 `gorm:"column:organization_id;not null;default:0;index:idx_iam_audit_org,priority:1"`
}

func (auditEventPO) TableName() string { return "iam_audit_events" }

type authSettingsPO struct {
	Key       string    `gorm:"column:name;size:64;primaryKey"`
	Value     string    `gorm:"column:value;type:text;not null"`
	Revision  uint64    `gorm:"column:revision;not null;default:1"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (authSettingsPO) TableName() string { return "auth_settings" }

type emailSettingsPO struct {
	Key       string    `gorm:"column:name;size:64;primaryKey"`
	Value     string    `gorm:"column:value;type:text;not null"`
	Secret    string    `gorm:"column:secret;type:text"`
	Revision  uint64    `gorm:"column:revision;not null;default:1"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (emailSettingsPO) TableName() string { return "auth_email_settings" }

type exportJobPO struct {
	ID              int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Kind            string    `gorm:"column:kind;size:32;not null"`
	ActorUserID     int64     `gorm:"column:actor_user_id;not null;index"`
	ActorSessionID  string    `gorm:"column:actor_session_id;size:64"`
	ScopeSnapshot   string    `gorm:"column:scope_snapshot;size:255"`
	RequestedFields string    `gorm:"column:requested_fields;type:text"`
	Status          string    `gorm:"column:status;size:16;not null"`
	ArtifactName    string    `gorm:"column:artifact_name;size:255"`
	Error           string    `gorm:"column:error;size:512"`
	CreatedAt       time.Time `gorm:"column:created_at;not null"`
	ExpiresAt       time.Time `gorm:"column:expires_at;not null"`
	// OrganizationID scopes tenant exports; 0 is a platform export.
	OrganizationID int64 `gorm:"column:organization_id;not null;default:0;index:idx_export_jobs_org"`
}

func (exportJobPO) TableName() string { return "export_jobs" }

type outboxEventPO struct {
	EventID           string    `gorm:"column:event_id;size:64;primaryKey"`
	AggregateType     string    `gorm:"column:aggregate_type;size:64;not null"`
	AggregateID       int64     `gorm:"column:aggregate_id;not null"`
	AggregateRevision uint64    `gorm:"column:aggregate_revision;not null"`
	EventType         string    `gorm:"column:event_type;size:64;not null"`
	SchemaVersion     int       `gorm:"column:schema_version;not null"`
	Payload           string    `gorm:"column:payload;type:text;not null"`
	CreatedAt         time.Time `gorm:"column:created_at;not null"`
}

func (outboxEventPO) TableName() string { return "event_outbox" }

type integrationClientPO struct {
	ID                 int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ClientID           string     `gorm:"column:client_id;size:64;not null;uniqueIndex"`
	Code               string     `gorm:"column:code;size:64;not null;uniqueIndex"`
	ServiceOwner       string     `gorm:"column:service_owner;size:64;not null"`
	Status             string     `gorm:"column:status;size:16;not null"`
	CredentialHash     string     `gorm:"column:credential_hash;size:64;not null"`
	CredentialVersion  int        `gorm:"column:credential_version;not null;default:1"`
	AllowedMethods     string     `gorm:"column:allowed_methods;type:text"`
	EventSubscriptions string     `gorm:"column:event_subscriptions;type:text"`
	CallbackURL        string     `gorm:"column:callback_url;size:512"`
	ExpiresAt          *time.Time `gorm:"column:expires_at"`
	Revision           uint64     `gorm:"column:revision;not null;default:1"`
	CreatedAt          time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt          time.Time  `gorm:"column:updated_at;not null"`
}

func (integrationClientPO) TableName() string { return "integration_clients" }

type oidcClientPO struct {
	ID           int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ClientID     string `gorm:"column:client_id;size:64;not null;uniqueIndex"`
	Name         string `gorm:"column:name;size:128;not null"`
	ServiceOwner string `gorm:"column:service_owner;size:64;not null"`
	Status       string `gorm:"column:status;size:16;not null"`
	SecretHash   string `gorm:"column:secret_hash;size:64"`
	RedirectURIs string `gorm:"column:redirect_uris;type:text;not null"`
	Scopes       string `gorm:"column:scopes;type:text;not null"`
	// PostLogoutRedirectURIs is the RP-initiated logout whitelist.
	PostLogoutRedirectURIs string    `gorm:"column:post_logout_redirect_uris;type:text"`
	Public                 bool      `gorm:"column:public;not null;default:false"`
	RequirePKCE            bool      `gorm:"column:require_pkce;not null"`
	AccessTTL              int       `gorm:"column:access_token_ttl_seconds;not null;default:900"`
	RefreshTTL             int       `gorm:"column:refresh_token_ttl_seconds;not null;default:86400"`
	Revision               uint64    `gorm:"column:revision;not null;default:1"`
	CreatedAt              time.Time `gorm:"column:created_at;not null"`
	UpdatedAt              time.Time `gorm:"column:updated_at;not null"`
}

func (oidcClientPO) TableName() string { return "oidc_clients" }

// oidcConsentPO records the scopes a user granted a client. The pair is unique:
// a user has at most one consent per client, and scope growth re-prompts.
type oidcConsentPO struct {
	ClientID  string    `gorm:"column:client_id;size:64;primaryKey"`
	UserID    int64     `gorm:"column:user_id;primaryKey;index:idx_oidc_consent_user"`
	Scopes    string    `gorm:"column:scopes;type:text;not null"`
	GrantedAt time.Time `gorm:"column:granted_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	Revision  uint64    `gorm:"column:revision;not null;default:1"`
}

func (oidcConsentPO) TableName() string { return "oidc_consents" }

// oidcConsentRequestPO is the one-time authorize request parked while the user
// decides. Only the hash of the handle is stored.
type oidcConsentRequestPO struct {
	HandleHash          string     `gorm:"column:handle_hash;size:64;primaryKey"`
	ClientID            string     `gorm:"column:client_id;size:64;not null"`
	UserID              int64      `gorm:"column:user_id;not null"`
	RedirectURI         string     `gorm:"column:redirect_uri;size:512;not null"`
	Scope               string     `gorm:"column:scope;size:512;not null"`
	State               string     `gorm:"column:state;size:512"`
	Nonce               string     `gorm:"column:nonce;size:255"`
	CodeChallenge       string     `gorm:"column:code_challenge;size:128"`
	CodeChallengeMethod string     `gorm:"column:code_challenge_method;size:8"`
	AuthTime            time.Time  `gorm:"column:auth_time;not null"`
	IdentityVersion     uint64     `gorm:"column:identity_version;not null"`
	ExpiresAt           time.Time  `gorm:"column:expires_at;not null;index:idx_oidc_consent_request_expiry"`
	ConsumedAt          *time.Time `gorm:"column:consumed_at"`
	CreatedAt           time.Time  `gorm:"column:created_at;not null"`
}

func (oidcConsentRequestPO) TableName() string { return "oidc_consent_requests" }

type oidcCodePO struct {
	CodeHash            string     `gorm:"column:code_hash;size:64;primaryKey"`
	ClientID            string     `gorm:"column:client_id;size:64;not null;index"`
	UserID              int64      `gorm:"column:user_id;not null"`
	IdentityVersion     uint64     `gorm:"column:identity_version;not null;default:0"`
	RedirectURI         string     `gorm:"column:redirect_uri;size:512;not null"`
	Scope               string     `gorm:"column:scope;size:512;not null"`
	Nonce               string     `gorm:"column:nonce;size:255"`
	CodeChallenge       string     `gorm:"column:code_challenge;size:128"`
	CodeChallengeMethod string     `gorm:"column:code_challenge_method;size:8"`
	AuthTime            time.Time  `gorm:"column:auth_time;not null"`
	ExpiresAt           time.Time  `gorm:"column:expires_at;not null;index:idx_oidc_code_expiry"`
	ConsumedAt          *time.Time `gorm:"column:consumed_at"`
	CreatedAt           time.Time  `gorm:"column:created_at;not null"`
}

func (oidcCodePO) TableName() string { return "oidc_authorization_codes" }

type oidcRefreshPO struct {
	TokenHash       string     `gorm:"column:token_hash;size:64;primaryKey"`
	FamilyID        string     `gorm:"column:family_id;size:64;not null;default:'';index:idx_oidc_refresh_family,priority:2"`
	ClientID        string     `gorm:"column:client_id;size:64;not null;index:idx_oidc_refresh_family,priority:1"`
	UserID          int64      `gorm:"column:user_id;not null"`
	IdentityVersion uint64     `gorm:"column:identity_version;not null;default:0"`
	Scope           string     `gorm:"column:scope;size:512;not null"`
	AuthTime        time.Time  `gorm:"column:auth_time;not null"`
	ExpiresAt       time.Time  `gorm:"column:expires_at;not null;index:idx_oidc_refresh_expiry"`
	RevokedAt       *time.Time `gorm:"column:revoked_at"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
}

func (oidcRefreshPO) TableName() string { return "oidc_refresh_tokens" }

type organizationPO struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Code       string     `gorm:"column:code;size:64;not null;uniqueIndex"`
	Name       string     `gorm:"column:name;size:128;not null"`
	Status     string     `gorm:"column:status;size:16;not null"`
	Revision   uint64     `gorm:"column:revision;not null;default:1"`
	CreatedBy  int64      `gorm:"column:created_by;not null;default:0"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;not null"`
	ArchivedAt *time.Time `gorm:"column:archived_at"`
}

func (organizationPO) TableName() string { return "organizations" }

type organizationMemberPO struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID int64     `gorm:"column:organization_id;not null;index"`
	UserID         int64     `gorm:"column:user_id;not null;index"`
	Role           string    `gorm:"column:role;size:16;not null"`
	DepartmentID   *int64    `gorm:"column:department_id"`
	Status         string    `gorm:"column:status;size:16;not null"`
	Revision       uint64    `gorm:"column:revision;not null;default:1"`
	InvitedBy      int64     `gorm:"column:invited_by;not null;default:0"`
	JoinedAt       time.Time `gorm:"column:joined_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (organizationMemberPO) TableName() string { return "organization_members" }

type organizationDepartmentPO struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID int64     `gorm:"column:organization_id;not null;index"`
	ParentID       int64     `gorm:"column:parent_id;not null;default:0"`
	Code           string    `gorm:"column:code;size:64;not null"`
	Name           string    `gorm:"column:name;size:128;not null"`
	Status         string    `gorm:"column:status;size:16;not null"`
	Revision       uint64    `gorm:"column:revision;not null;default:1"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (organizationDepartmentPO) TableName() string { return "organization_departments" }

// organizationInvitationPO holds a pending invitation. Only the hash of the
// token is stored; the raw token exists solely in the invitation e-mail.
type organizationInvitationPO struct {
	ID              int64      `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID  int64      `gorm:"column:organization_id;not null;index:idx_org_invitation_org,priority:1"`
	Email           string     `gorm:"column:email;size:254;not null"`
	EmailNormalized string     `gorm:"column:email_normalized;size:254;not null;index:idx_org_invitation_email"`
	Role            string     `gorm:"column:role;size:16;not null"`
	DepartmentID    *int64     `gorm:"column:department_id"`
	TokenHash       string     `gorm:"column:token_hash;size:64;not null;uniqueIndex"`
	Status          string     `gorm:"column:status;size:16;not null;index:idx_org_invitation_org,priority:2"`
	InvitedBy       int64      `gorm:"column:invited_by;not null;default:0"`
	AcceptedBy      int64      `gorm:"column:accepted_by;not null;default:0"`
	ExpiresAt       time.Time  `gorm:"column:expires_at;not null"`
	AcceptedAt      *time.Time `gorm:"column:accepted_at"`
	Revision        uint64     `gorm:"column:revision;not null;default:1"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;not null"`
}

func (organizationInvitationPO) TableName() string { return "organization_invitations" }

type legacyImportBatchPO struct {
	BatchID          string     `gorm:"column:batch_id;size:64;primaryKey"`
	SourceCommit     string     `gorm:"column:source_commit;size:64"`
	SnapshotPosition string     `gorm:"column:snapshot_position;size:128"`
	Counts           string     `gorm:"column:counts;type:text"`
	Fingerprint      string     `gorm:"column:fingerprint;size:128"`
	State            string     `gorm:"column:state;size:24;not null"`
	Error            string     `gorm:"column:error;size:512"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null"`
	CompletedAt      *time.Time `gorm:"column:completed_at"`
}

func (legacyImportBatchPO) TableName() string { return "legacy_import_batches" }

type deliveryPO struct {
	EventID      string    `gorm:"column:event_id;size:64;primaryKey"`
	SubscriberID string    `gorm:"column:subscriber_id;size:64;primaryKey"`
	Status       string    `gorm:"column:status;size:24;not null"`
	Attempts     int       `gorm:"column:attempts;not null;default:0"`
	NextRetryAt  time.Time `gorm:"column:next_retry_at;not null"`
	LastError    string    `gorm:"column:last_error;size:512"`
}

func (deliveryPO) TableName() string { return "event_deliveries" }
