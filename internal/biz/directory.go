package biz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mengbin92/user-center/platform/tenant"
)

// Enterprise directory synchronization.
//
// A source is bound to exactly one organization, and every object it creates
// is provisioned through the same SCIM usecase an IdP uses. That keeps one
// account-creation path (and one set of tenant checks) for both inbound
// channels instead of a second, subtly different implementation.

const (
	DirectoryKindLDAP     = "ldap"
	DirectoryKindJSONFeed = "jsonfeed"
	DirectoryStatusActive = "active"
	DirectoryStatusPaused = "paused"
	DirectoryModeFull     = "full"
	DirectoryModeDelta    = "delta"
	DirectoryModeDryRun   = "dry_run"
)

type DirectorySource struct {
	ID             int64
	OrganizationID int64
	Kind           string
	Name           string
	Config         DirectoryConfig
	SecretEnc      string
	Status         string
	Cursor         string
	Revision       uint64
	CreatedBy      int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastRunAt      *time.Time
}

type DirectoryObject struct {
	ID             int64
	SourceID       int64
	OrganizationID int64
	ExternalID     string
	LocalID        int64
	LastSeenAt     time.Time
	Revision       uint64
}

type SyncOutcome struct {
	ExternalID string `json:"externalId"`
	Action     string `json:"action"`
	Detail     string `json:"detail,omitempty"`
}

type DirectoryRun struct {
	ID             int64
	SourceID       int64
	OrganizationID int64
	Mode           string
	Status         string
	StartedAt      time.Time
	FinishedAt     *time.Time
	Fetched        int
	Created        int
	Updated        int
	Disabled       int
	Unchanged      int
	Failed         int
	CursorBefore   string
	CursorAfter    string
	Report         []SyncOutcome
	ErrorText      string
}

type DirectoryRepo interface {
	CreateSource(context.Context, Tx, *DirectorySource) (*DirectorySource, error)
	GetSource(context.Context, Tx, int64) (*DirectorySource, error)
	ListSources(context.Context, Tx, int64) ([]*DirectorySource, error)
	DueSources(context.Context, Tx, time.Time, int) ([]*DirectorySource, error)
	UpdateSource(context.Context, Tx, *DirectorySource, uint64) (*DirectorySource, error)
	UpdateCursor(context.Context, Tx, int64, string, time.Time) error

	CreateRun(context.Context, Tx, *DirectoryRun) (*DirectoryRun, error)
	FinishRun(context.Context, Tx, *DirectoryRun) error
	ListRuns(context.Context, Tx, int64, int) ([]*DirectoryRun, error)

	GetObject(context.Context, Tx, int64, string) (*DirectoryObject, error)
	UpsertObject(context.Context, Tx, *DirectoryObject) error
	ListObjects(context.Context, Tx, int64) ([]*DirectoryObject, error)
	DeleteObject(context.Context, Tx, int64, string) error
}

type DirectoryUsecase struct {
	*Services
	Repo       DirectoryRepo
	Connectors map[string]DirectoryConnector
	SCIM       *SCIMUsecase
	workerMu   sync.Mutex
}

func NewDirectoryUsecase(s *Services, repo DirectoryRepo, connectors map[string]DirectoryConnector, scim *SCIMUsecase) *DirectoryUsecase {
	return &DirectoryUsecase{Services: s, Repo: repo, Connectors: connectors, SCIM: scim}
}

func (uc *DirectoryUsecase) directoryGuard(ctx context.Context, actor ActorContext, write bool) error {
	if !isPlatformAdmin(actor) {
		return ErrPermissionDenied
	}
	if write {
		return uc.RequireStepUp(ctx, actor)
	}
	return nil
}

func (uc *DirectoryUsecase) directoryReason(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	return nil
}

func (uc *DirectoryUsecase) Sources(ctx context.Context, actor ActorContext, orgID int64) ([]*DirectorySource, error) {
	if err := uc.directoryGuard(ctx, actor, false); err != nil {
		return nil, err
	}
	items, err := uc.Repo.ListSources(ctx, nil, orgID)
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *DirectoryUsecase) Runs(ctx context.Context, actor ActorContext, sourceID int64, limit int) ([]*DirectoryRun, error) {
	if err := uc.directoryGuard(ctx, actor, false); err != nil {
		return nil, err
	}
	if _, err := uc.Repo.GetSource(ctx, nil, sourceID); err != nil {
		return nil, ErrResourceNotFound
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	items, err := uc.Repo.ListRuns(ctx, nil, sourceID, limit)
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *DirectoryUsecase) CreateSource(ctx context.Context, actor ActorContext, orgID int64, kind, name string, cfg DirectoryConfig, secret, reason string) (*DirectorySource, error) {
	if err := uc.directoryGuard(ctx, actor, true); err != nil {
		return nil, err
	}
	if err := uc.directoryReason(reason); err != nil {
		return nil, err
	}
	connector, ok := uc.Connectors[kind]
	if !ok {
		return nil, Validation("不支持的目录类型: " + kind)
	}
	_ = connector
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return nil, Validation("name 必须为 1–128 个字符")
	}
	cfg.Normalize()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if _, err := validateDirectoryURL(cfg.URL, directorySchemes(kind)...); err != nil {
		return nil, err
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil || org.Status != OrgStatusActive {
		return nil, Validation("组织不存在或已归档")
	}
	enc, err := uc.Secrets.Encrypt(secret)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	var created *DirectorySource
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Repo.CreateSource(ctx, tx, &DirectorySource{
			OrganizationID: orgID, Kind: kind, Name: name, Config: cfg,
			SecretEnc: enc,
			Status:    DirectoryStatusActive, Revision: 1, CreatedBy: actor.User.ID,
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return ErrDependency
		}
		created = row
		return uc.audit(ctx, tx, actor, "directory.source.created", itoa(row.ID), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func directorySchemes(kind string) []string {
	if kind == DirectoryKindLDAP {
		return []string{"ldap", "ldaps"}
	}
	return []string{"http", "https"}
}

func (uc *DirectoryUsecase) UpdateSource(ctx context.Context, actor ActorContext, id int64, cfg *DirectoryConfig, status string, expected uint64, reason string) (*DirectorySource, error) {
	if err := uc.directoryGuard(ctx, actor, true); err != nil {
		return nil, err
	}
	if err := uc.directoryReason(reason); err != nil {
		return nil, err
	}
	if status != "" && status != DirectoryStatusActive && status != DirectoryStatusPaused {
		return nil, Validation("status 只能是 active / paused")
	}
	var out *DirectorySource
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		current, err := uc.Repo.GetSource(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || current.Revision != expected {
			return ConflictRevision(current.Revision)
		}
		if cfg != nil {
			cfg.Normalize()
			if err := cfg.validate(); err != nil {
				return err
			}
			if _, err := validateDirectoryURL(cfg.URL, directorySchemes(current.Kind)...); err != nil {
				return err
			}
			current.Config = *cfg
		}
		if status != "" {
			current.Status = status
		}
		current.UpdatedAt = uc.Clock.Now()
		row, err := uc.Repo.UpdateSource(ctx, tx, current, expected)
		if err != nil {
			return err
		}
		out = row
		return uc.audit(ctx, tx, actor, "directory.source.updated", itoa(id), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (uc *DirectoryUsecase) RotateSecret(ctx context.Context, actor ActorContext, id int64, secret string, expected uint64, reason string) (*DirectorySource, error) {
	if err := uc.directoryGuard(ctx, actor, true); err != nil {
		return nil, err
	}
	if err := uc.directoryReason(reason); err != nil {
		return nil, err
	}
	enc, err := uc.Secrets.Encrypt(secret)
	if err != nil {
		return nil, ErrDependency
	}
	var out *DirectorySource
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		current, err := uc.Repo.GetSource(ctx, tx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || current.Revision != expected {
			return ConflictRevision(current.Revision)
		}
		current.SecretEnc = enc
		current.UpdatedAt = uc.Clock.Now()
		row, err := uc.Repo.UpdateSource(ctx, tx, current, expected)
		if err != nil {
			return err
		}
		out = row
		return uc.audit(ctx, tx, actor, "directory.source.secret_rotated", itoa(id), "{}", "{}", "{}", reason, "success")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (uc *DirectoryUsecase) TriggerSync(ctx context.Context, actor ActorContext, sourceID int64, mode, reason string) (*DirectoryRun, error) {
	if err := uc.directoryGuard(ctx, actor, true); err != nil {
		return nil, err
	}
	if err := uc.directoryReason(reason); err != nil {
		return nil, err
	}
	if mode != DirectoryModeFull && mode != DirectoryModeDelta && mode != DirectoryModeDryRun {
		return nil, Validation("mode 只能是 full / delta / dry_run")
	}
	source, err := uc.Repo.GetSource(ctx, nil, sourceID)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	// Runs and object mappings are tenant-owned; bind the context before the
	// engine starts so they land in this organization's schema.
	ctx = tenant.With(ctx, source.OrganizationID)
	if err := uc.audit(ctx, nil, actor, "directory.sync.triggered", itoa(sourceID), "{}", "{}", "{}", reason, "success"); err != nil {
		return nil, err
	}
	return uc.syncOnce(ctx, source, mode)
}

// ---------------------------------------------------------------------------
// Sync engine

func (uc *DirectoryUsecase) syncOnce(ctx context.Context, source *DirectorySource, mode string) (*DirectoryRun, error) {
	connector, ok := uc.Connectors[source.Kind]
	if !ok {
		return nil, Validation("目录类型没有可用连接器: " + source.Kind)
	}
	run := &DirectoryRun{
		SourceID: source.ID, OrganizationID: source.OrganizationID, Mode: mode,
		Status: "running", StartedAt: uc.Clock.Now(), CursorBefore: source.Cursor,
	}
	created, err := uc.Repo.CreateRun(ctx, nil, run)
	if err != nil {
		return nil, ErrDependency
	}
	run = created

	defer func() {
		now := uc.Clock.Now()
		run.FinishedAt = &now
		if run.Status == "running" {
			run.Status = "succeeded"
		}
		if run.Failed > 0 {
			run.Status = "partial"
		}
		_ = uc.Repo.FinishRun(context.Background(), nil, run)
	}()

	secret, err := uc.Secrets.Decrypt(source.SecretEnc)
	if err != nil {
		run.Status, run.ErrorText = "failed", "credential decryption failed"
		return run, nil
	}
	cursor := source.Cursor
	if mode == DirectoryModeFull {
		cursor = ""
	}
	snapshot, err := connector.Fetch(ctx, source.Config, secret, cursor)
	if err != nil {
		run.Status, run.ErrorText = "failed", err.Error()
		return run, nil
	}
	run.Fetched = len(snapshot.Records)

	seen := map[string]bool{}
	for _, record := range snapshot.Records {
		mapped := directoryExternalID(source.ID, record.ExternalID)
		seen[mapped] = true
		if mode == DirectoryModeDryRun {
			// Counters describe writes that actually happened. A preview only
			// reports what WOULD happen, so created_count stays zero.
			action := "would_create"
			if _, err := uc.Repo.GetObject(ctx, nil, source.ID, mapped); err == nil {
				action = "would_update"
			}
			run.Report = append(run.Report, SyncOutcome{ExternalID: record.ExternalID, Action: action})
			continue
		}
		obj, objErr := uc.Repo.GetObject(ctx, nil, source.ID, mapped)
		input := SCIMUserInput{
			ExternalID: mapped, UserName: record.UserName,
			DisplayName: record.DisplayName, Email: record.Email,
			Active: boolPtr(record.Active),
		}
		if objErr != nil {
			user, err := uc.SCIM.CreateUser(ctx, source.OrganizationID, input)
			if err != nil {
				run.Failed++
				run.Report = append(run.Report, SyncOutcome{ExternalID: record.ExternalID, Action: "failed", Detail: err.Error()})
				continue
			}
			if err := uc.Repo.UpsertObject(ctx, nil, &DirectoryObject{
				SourceID: source.ID, OrganizationID: source.OrganizationID,
				ExternalID: mapped, LocalID: user.ID, LastSeenAt: run.StartedAt,
			}); err != nil {
				run.Failed++
				continue
			}
			run.Created++
			run.Report = append(run.Report, SyncOutcome{ExternalID: record.ExternalID, Action: "created"})
			continue
		}
		if source.Config.Conflict == "local_wins" {
			_ = uc.Repo.UpsertObject(ctx, nil, &DirectoryObject{
				SourceID: source.ID, OrganizationID: source.OrganizationID,
				ExternalID: mapped, LocalID: obj.LocalID, LastSeenAt: run.StartedAt,
			})
			run.Unchanged++
			continue
		}
		// PatchUser keeps the local id authoritative; externalId is only used
		// on creation so an IdP rename cannot rebind an existing row.
		input.ExternalID = ""
		if _, err := uc.SCIM.PatchUser(ctx, source.OrganizationID, obj.LocalID, input); err != nil {
			run.Failed++
			run.Report = append(run.Report, SyncOutcome{ExternalID: record.ExternalID, Action: "failed", Detail: err.Error()})
			continue
		}
		_ = uc.Repo.UpsertObject(ctx, nil, &DirectoryObject{
			SourceID: source.ID, OrganizationID: source.OrganizationID,
			ExternalID: mapped, LocalID: obj.LocalID, LastSeenAt: run.StartedAt,
		})
		run.Updated++
		if !record.Active {
			run.Disabled++
		}
	}

	// Reconciliation: explicit deletions (delta) or absence from a full
	// snapshot. local_wins never removes anything on its own.
	tombstones := map[string]bool{}
	for _, raw := range snapshot.Deleted {
		tombstones[directoryExternalID(source.ID, raw)] = true
	}
	if snapshot.Full && source.Config.Deletion != "keep" {
		objects, err := uc.Repo.ListObjects(ctx, nil, source.ID)
		if err != nil {
			run.Status, run.ErrorText = "failed", "reconciliation read failed"
			return run, nil
		}
		for _, obj := range objects {
			if !seen[obj.ExternalID] {
				tombstones[obj.ExternalID] = true
			}
		}
	}
	for mapped := range tombstones {
		obj, err := uc.Repo.GetObject(ctx, nil, source.ID, mapped)
		if err != nil {
			continue
		}
		if mode == DirectoryModeDryRun {
			run.Report = append(run.Report, SyncOutcome{ExternalID: mapped, Action: "would_deprovision"})
			continue
		}
		var err2 error
		switch source.Config.Deletion {
		case "delete":
			err2 = uc.SCIM.DeleteUser(ctx, source.OrganizationID, obj.LocalID)
			if err2 == nil {
				_ = uc.Repo.DeleteObject(ctx, nil, source.ID, mapped)
			}
		default: // disable
			inactive := false
			_, err2 = uc.SCIM.PatchUser(ctx, source.OrganizationID, obj.LocalID, SCIMUserInput{Active: &inactive})
		}
		if err2 != nil {
			run.Failed++
			run.Report = append(run.Report, SyncOutcome{ExternalID: mapped, Action: "failed", Detail: err2.Error()})
			continue
		}
		run.Disabled++
		run.Report = append(run.Report, SyncOutcome{ExternalID: mapped, Action: "deprovisioned"})
	}

	if mode != DirectoryModeDryRun {
		// A dry run must not advance the watermark: doing so would make the
		// next real run skip every object the preview just reported on.
		run.CursorAfter = snapshot.Cursor
		if err := uc.Repo.UpdateCursor(ctx, nil, source.ID, snapshot.Cursor, run.StartedAt); err != nil {
			run.Status, run.ErrorText = "partial", "cursor update failed"
		}
	}
	return run, nil
}

func directoryExternalID(sourceID int64, external string) string {
	return fmt.Sprintf("dir:%d:%s", sourceID, external)
}

func boolPtr(v bool) *bool { return &v }

// Dispatch runs due sources once. It is serial on purpose: a directory pull
// can be slow, and overlapping runs of the same source would fight over the
// cursor. Failures are recorded on the run row, never returned to the ticker.
func (uc *DirectoryUsecase) Dispatch(ctx context.Context) {
	if !uc.workerMu.TryLock() {
		return
	}
	defer uc.workerMu.Unlock()
	sources, err := uc.Repo.DueSources(ctx, nil, uc.Clock.Now(), 20)
	if err != nil {
		return
	}
	for _, source := range sources {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, _ = uc.syncOnce(tenant.With(ctx, source.OrganizationID), source, DirectoryModeDelta)
	}
}

func (uc *DirectoryUsecase) StartWorker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uc.Dispatch(ctx)
		}
	}
}
