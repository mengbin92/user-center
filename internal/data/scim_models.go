package data

import "time"

// SCIM provisioning tables. SQLite (dev/tests) builds these through
// AutoMigrate; MySQL uses 015_scim.sql. The column set has to stay identical.
type scimTokenPO struct {
	ID                int64      `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID    int64      `gorm:"column:organization_id;not null;index:idx_scim_tokens_org,priority:1"`
	Name              string     `gorm:"column:name;size:128;not null"`
	TokenHash         string     `gorm:"column:token_hash;size:64;not null;uniqueIndex"`
	Status            string     `gorm:"column:status;size:16;not null;index:idx_scim_tokens_org,priority:2"`
	CredentialVersion int        `gorm:"column:credential_version;not null;default:1"`
	Revision          uint64     `gorm:"column:revision;not null;default:1"`
	CreatedBy         int64      `gorm:"column:created_by;not null"`
	CreatedAt         time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;not null"`
	LastUsedAt        *time.Time `gorm:"column:last_used_at"`
	DisabledAt        *time.Time `gorm:"column:disabled_at"`
}

func (scimTokenPO) TableName() string { return "scim_tokens" }

type scimIdentityPO struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID int64     `gorm:"column:organization_id;not null;uniqueIndex:uk_scim_identity,priority:1;uniqueIndex:uk_scim_identity_local,priority:1"`
	Kind           string    `gorm:"column:kind;size:16;not null;uniqueIndex:uk_scim_identity,priority:2;uniqueIndex:uk_scim_identity_local,priority:2"`
	ExternalID     string    `gorm:"column:external_id;size:255;not null;uniqueIndex:uk_scim_identity,priority:3"`
	LocalID        int64     `gorm:"column:local_id;not null;uniqueIndex:uk_scim_identity_local,priority:3"`
	Revision       uint64    `gorm:"column:revision;not null;default:1"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (scimIdentityPO) TableName() string { return "scim_identities" }

type scimGroupPO struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID int64     `gorm:"column:organization_id;not null;uniqueIndex:uk_scim_group_name,priority:1"`
	DisplayName    string    `gorm:"column:display_name;size:255;not null;uniqueIndex:uk_scim_group_name,priority:2"`
	Revision       uint64    `gorm:"column:revision;not null;default:1"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (scimGroupPO) TableName() string { return "scim_groups" }

type scimGroupMemberPO struct {
	GroupID int64 `gorm:"column:group_id;primaryKey"`
	UserID  int64 `gorm:"column:user_id;primaryKey"`
}

func (scimGroupMemberPO) TableName() string { return "scim_group_members" }
