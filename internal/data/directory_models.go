package data

import "time"

type directorySourcePO struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	OrganizationID int64      `gorm:"column:organization_id;not null;uniqueIndex:uk_directory_source_name,priority:1"`
	Kind           string     `gorm:"column:kind;size:32;not null"`
	Name           string     `gorm:"column:name;size:128;not null;uniqueIndex:uk_directory_source_name,priority:2"`
	ConfigJSON     string     `gorm:"column:config_json;type:text;not null"`
	SecretEnc      string     `gorm:"column:secret_enc;type:text;not null"`
	Status         string     `gorm:"column:status;size:16;not null;index:idx_directory_sources_due,priority:1"`
	CursorValue    string     `gorm:"column:cursor_value;size:512;not null"`
	Revision       uint64     `gorm:"column:revision;not null;default:1"`
	CreatedBy      int64      `gorm:"column:created_by;not null"`
	CreatedAt      time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;not null"`
	LastRunAt      *time.Time `gorm:"column:last_run_at;index:idx_directory_sources_due,priority:2"`
}

func (directorySourcePO) TableName() string { return "directory_sources" }

type directoryRunPO struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	SourceID       int64      `gorm:"column:source_id;not null;index:idx_directory_runs_source,priority:1"`
	OrganizationID int64      `gorm:"column:organization_id;not null"`
	Mode           string     `gorm:"column:mode;size:16;not null"`
	Status         string     `gorm:"column:status;size:16;not null"`
	StartedAt      time.Time  `gorm:"column:started_at;not null"`
	FinishedAt     *time.Time `gorm:"column:finished_at"`
	Fetched        int        `gorm:"column:fetched;not null"`
	CreatedCount   int        `gorm:"column:created_count;not null"`
	UpdatedCount   int        `gorm:"column:updated_count;not null"`
	DisabledCount  int        `gorm:"column:disabled_count;not null"`
	UnchangedCount int        `gorm:"column:unchanged_count;not null"`
	FailedCount    int        `gorm:"column:failed_count;not null"`
	CursorBefore   string     `gorm:"column:cursor_before;size:512;not null"`
	CursorAfter    string     `gorm:"column:cursor_after;size:512;not null"`
	ReportJSON     string     `gorm:"column:report_json;type:text"`
	ErrorText      string     `gorm:"column:error_text;type:text"`
}

func (directoryRunPO) TableName() string { return "directory_sync_runs" }

type directoryObjectPO struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	SourceID       int64     `gorm:"column:source_id;not null;uniqueIndex:uk_directory_object,priority:1;index:idx_directory_object_local,priority:1"`
	OrganizationID int64     `gorm:"column:organization_id;not null"`
	ExternalID     string    `gorm:"column:external_id;size:255;not null;uniqueIndex:uk_directory_object,priority:2"`
	LocalID        int64     `gorm:"column:local_id;not null;index:idx_directory_object_local,priority:2"`
	LastSeenAt     time.Time `gorm:"column:last_seen_at;not null"`
	Revision       uint64    `gorm:"column:revision;not null;default:1"`
}

func (directoryObjectPO) TableName() string { return "directory_objects" }
