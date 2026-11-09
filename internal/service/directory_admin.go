package service

import (
	"context"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// DirectoryAdminService is the browser-facing governance surface. The
// connector secret is write-only: it is encrypted in biz before it reaches the
// repository and never appears in a reply message.
type DirectoryAdminService struct {
	usercv1.UnimplementedDirectoryAdminServiceServer
	uc *biz.DirectoryUsecase
}

func NewDirectoryAdminService(uc *biz.DirectoryUsecase) *DirectoryAdminService {
	return &DirectoryAdminService{uc: uc}
}

func directorySourceProto(s *biz.DirectorySource) *usercv1.DirectorySource {
	if s == nil {
		return nil
	}
	cfg, _ := jsonx.Marshal(s.Config)
	return &usercv1.DirectorySource{
		Id: id(s.ID), OrganizationId: id(s.OrganizationID), Kind: s.Kind, Name: s.Name,
		ConfigJson: string(cfg), Status: s.Status, Cursor: s.Cursor,
		Revision: rev(s.Revision), CreatedAt: ts(s.CreatedAt), UpdatedAt: ts(s.UpdatedAt),
		LastRunAt: tptr(s.LastRunAt),
	}
}

func directoryRunProto(r *biz.DirectoryRun) *usercv1.DirectorySyncRun {
	if r == nil {
		return nil
	}
	report, _ := jsonx.Marshal(r.Report)
	return &usercv1.DirectorySyncRun{
		Id: id(r.ID), SourceId: id(r.SourceID), OrganizationId: id(r.OrganizationID),
		Mode: r.Mode, Status: r.Status, StartedAt: ts(r.StartedAt), FinishedAt: tptr(r.FinishedAt),
		Fetched: int32(r.Fetched), CreatedCount: int32(r.Created), UpdatedCount: int32(r.Updated),
		DisabledCount: int32(r.Disabled), UnchangedCount: int32(r.Unchanged), FailedCount: int32(r.Failed),
		CursorBefore: r.CursorBefore, CursorAfter: r.CursorAfter,
		ReportJson: string(report), ErrorText: r.ErrorText,
	}
}

func directoryConfig(raw string) (biz.DirectoryConfig, error) {
	var cfg biz.DirectoryConfig
	if err := jsonx.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, biz.Validation("config_json 不是合法 JSON")
	}
	return cfg, nil
}

func (s *DirectoryAdminService) ListDirectorySources(ctx context.Context, req *usercv1.ListDirectorySourcesRequest) (*usercv1.DirectorySourcesReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	items, err := s.uc.Sources(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.DirectorySourcesReply{}
	for _, item := range items {
		out.Items = append(out.Items, directorySourceProto(item))
	}
	return out, nil
}

func (s *DirectoryAdminService) CreateDirectorySource(ctx context.Context, req *usercv1.CreateDirectorySourceRequest) (*usercv1.DirectorySource, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	cfg, err := directoryConfig(req.GetConfigJson())
	if err != nil {
		return nil, err
	}
	source, err := s.uc.CreateSource(ctx, actor, orgID, req.GetKind(), req.GetName(), cfg, req.GetSecret(), reason)
	if err != nil {
		return nil, err
	}
	return directorySourceProto(source), nil
}

func (s *DirectoryAdminService) UpdateDirectorySource(ctx context.Context, req *usercv1.UpdateDirectorySourceRequest) (*usercv1.DirectorySource, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	sourceID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	var cfg *biz.DirectoryConfig
	if raw := req.GetConfigJson(); raw != "" {
		parsed, err := directoryConfig(raw)
		if err != nil {
			return nil, err
		}
		cfg = &parsed
	}
	source, err := s.uc.UpdateSource(ctx, actor, sourceID, cfg, req.GetStatus(), expected, reason)
	if err != nil {
		return nil, err
	}
	return directorySourceProto(source), nil
}

func (s *DirectoryAdminService) RotateDirectorySourceSecret(ctx context.Context, req *usercv1.RotateDirectorySourceSecretRequest) (*usercv1.DirectorySource, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	sourceID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	source, err := s.uc.RotateSecret(ctx, actor, sourceID, req.GetSecret(), expected, reason)
	if err != nil {
		return nil, err
	}
	return directorySourceProto(source), nil
}

func (s *DirectoryAdminService) TriggerDirectorySync(ctx context.Context, req *usercv1.TriggerDirectorySyncRequest) (*usercv1.DirectorySyncRun, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	sourceID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	mode := req.GetMode()
	if mode == "" {
		mode = biz.DirectoryModeDelta
	}
	run, err := s.uc.TriggerSync(ctx, actor, sourceID, mode, reason)
	if err != nil {
		return nil, err
	}
	return directoryRunProto(run), nil
}

func (s *DirectoryAdminService) ListDirectorySyncRuns(ctx context.Context, req *usercv1.ListDirectorySyncRunsRequest) (*usercv1.DirectorySyncRunsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	sourceID, err := parseIDField(req.GetSourceId(), "source_id")
	if err != nil {
		return nil, err
	}
	items, err := s.uc.Runs(ctx, actor, sourceID, 20)
	if err != nil {
		return nil, err
	}
	out := &usercv1.DirectorySyncRunsReply{}
	for _, item := range items {
		out.Items = append(out.Items, directoryRunProto(item))
	}
	return out, nil
}
