package data

import "time"

// tenantSchemaPO is the platform-side registry of prepared tenant schemas. It
// is what cross-tenant queries iterate: without it, the platform would have to
// guess which databases exist.
type tenantSchemaPO struct {
	OrganizationID int64     `gorm:"column:organization_id;primaryKey"`
	SchemaName     string    `gorm:"column:schema_name;size:128;not null"`
	Status         string    `gorm:"column:status;size:16;not null"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (tenantSchemaPO) TableName() string { return "tenant_schemas" }
