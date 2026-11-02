package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

type AdminUserService struct {
	usercv1.UnimplementedAdminUserServiceServer
	users    *biz.UserUsecase
	sessions *biz.SessionUsecase
}

func NewAdminUserService(users *biz.UserUsecase, sessions *biz.SessionUsecase) *AdminUserService {
	return &AdminUserService{users: users, sessions: sessions}
}

func (s *AdminUserService) GetOverview(ctx context.Context, _ *usercv1.GetOverviewRequest) (*usercv1.OverviewReply, error) {
	actor := requestMeta(ctx)
	o, err := s.users.OverviewView(ctx, actor)
	if err != nil {
		return nil, err
	}
	return &usercv1.OverviewReply{
		TotalUsers: o.Total, EnabledUsers: o.Enabled, DisabledUsers: o.Disabled,
		ArchivedUsers: o.Archived, MfaUsers: o.MFA, ActiveSessions: o.ActiveSessions,
		Logins_24H: o.Logins24h, FailedLogins_24H: o.Failed24h,
	}, nil
}

func (s *AdminUserService) ListUsers(ctx context.Context, req *usercv1.ListUsersRequest) (*usercv1.UsersReply, error) {
	actor := requestMeta(ctx)
	offset, err := biz.DecodePageToken(req.GetPageToken(), bizFingerprint(req.GetKeyword(), req.GetStatus(), req.GetRoleId(), req.GetMfaEnabled()))
	if err != nil {
		return nil, err
	}
	var roleID int64
	if req.GetRoleId() != "" {
		roleID, err = parseIDField(req.GetRoleId(), "role_id")
		if err != nil {
			return nil, err
		}
	}
	var mfa *bool
	switch req.GetMfaEnabled() {
	case "", "any":
	case "true":
		v := true
		mfa = &v
	case "false":
		v := false
		mfa = &v
	default:
		return nil, biz.Validation("mfa_enabled 只能是 any/true/false")
	}
	limit := pageSize(req.GetPageSize())
	items, total, err := s.users.ListUsers(ctx, actor, biz.UserFilter{
		Keyword: req.GetKeyword(), Status: req.GetStatus(), RoleID: roleID, MFA: mfa,
		Offset: offset, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := &usercv1.UsersReply{Meta: &usercv1.ListMeta{TotalSize: rev(uint64(total))}}
	for _, item := range items {
		out.Items = append(out.Items, userProto(item.User))
	}
	if offset+len(items) < int(total) {
		out.Meta.NextPageToken = biz.EncodePageToken(offset+len(items), bizFingerprint(req.GetKeyword(), req.GetStatus(), req.GetRoleId(), req.GetMfaEnabled()))
	}
	return out, nil
}

func bizFingerprint(parts ...any) string {
	// Kept in the service layer to bind tokens to the exact user filter.
	return fingerprintOf(parts...)
}

func (s *AdminUserService) CreateUser(ctx context.Context, req *usercv1.CreateUserRequest) (*usercv1.User, error) {
	actor := requestMeta(ctx)
	var roleIDs []int64
	for _, raw := range req.GetRoleIds() {
		roleID, err := parseIDField(raw, "role_id")
		if err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, roleID)
	}
	u, err := s.users.CreateUser(ctx, actor, biz.CreateUserInput{
		Username: req.GetUsername(), Email: req.GetEmail(), DisplayName: req.GetDisplayName(),
		RoleIDs: roleIDs, SendActivation: req.GetSendActivation(),
		InitialPassword: req.GetInitialPassword(), Reason: reasonOr(req.GetReason(), "administrator create"),
	})
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *AdminUserService) GetUser(ctx context.Context, req *usercv1.GetUserRequest) (*usercv1.User, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetUser(ctx, actor, userID)
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *AdminUserService) UpdateUser(ctx context.Context, req *usercv1.UpdateUserRequest) (*usercv1.User, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	var policy uint64
	if req.GetExpectedPolicyRevision() != "" {
		policy, err = parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return nil, err
		}
	}
	u, err := s.users.UpdateUser(ctx, actor, userID, biz.UpdateUserInput{
		DisplayName: req.GetDisplayName(), UpdateMask: req.GetUpdateMask(),
		ExpectedRevision: expected, ExpectedPolicy: policy,
		Reason: reasonOr(req.GetReason(), "administrator update"),
	})
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *AdminUserService) SetUserStatus(ctx context.Context, req *usercv1.SetUserStatusRequest) (*usercv1.User, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	u, err := s.users.SetStatus(ctx, actor, userID, req.GetStatus(), expected, reasonOr(req.GetReason(), "administrator status change"))
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *AdminUserService) ArchiveUser(ctx context.Context, req *usercv1.ArchiveUserRequest) (*usercv1.User, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	u, err := s.users.Archive(ctx, actor, userID, expected, reasonOr(req.GetReason(), "administrator archive"))
	if err != nil {
		return nil, err
	}
	return userProto(u), nil
}

func (s *AdminUserService) CreatePasswordResetRequest(ctx context.Context, req *usercv1.CreatePasswordResetTaskRequest) (*usercv1.PasswordResetTaskReply, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	expires, err := s.users.CreatePasswordResetTask(ctx, actor, userID, reasonOr(req.GetReason(), "administrator password reset"))
	if err != nil {
		return nil, err
	}
	return &usercv1.PasswordResetTaskReply{Queued: true, ExpiresAt: ts(expires)}, nil
}

func (s *AdminUserService) ResetMFA(ctx context.Context, req *usercv1.ResetMFARequest) (*emptypb.Empty, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	if err := s.users.ResetMFA(ctx, actor, userID, reasonOr(req.GetReason(), "administrator MFA reset")); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *AdminUserService) ListUserSessions(ctx context.Context, req *usercv1.ListUserSessionsRequest) (*usercv1.SessionsReply, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	rows, err := s.users.UserSessions(ctx, actor, userID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.SessionsReply{}
	for _, row := range rows {
		out.Items = append(out.Items, sessionProto(row, actor.Session.ID))
	}
	return out, nil
}

func (s *AdminUserService) RevokeUserSessions(ctx context.Context, req *usercv1.RevokeUserSessionsRequest) (*emptypb.Empty, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	if err := s.users.RevokeUserSessions(ctx, actor, userID, req.GetSessionIds(), req.GetRevokeAll(), reasonOr(req.GetReason(), "administrator revoke sessions")); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *AdminUserService) GetUserEffectivePermissions(ctx context.Context, req *usercv1.GetUserEffectivePermissionsRequest) (*usercv1.EffectivePermissionsReply, error) {
	actor := requestMeta(ctx)
	userID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	grants, policy, err := s.users.EffectivePermissions(ctx, actor, userID)
	if err != nil {
		return nil, err
	}
	user, err := s.users.GetUser(ctx, actor, userID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.EffectivePermissionsReply{PolicyRevision: rev(policy), UserRevision: rev(user.Revision)}
	for _, g := range grants {
		out.Permissions = append(out.Permissions, &usercv1.EffectivePermission{
			Operation: g.Operation, Effect: g.Effect, Scope: g.Scope,
			RoleId: id(g.RoleID), RoleCode: g.RoleCode,
		})
	}
	return out, nil
}

func (s *AdminUserService) ExportUsers(ctx context.Context, req *usercv1.ExportUsersRequest) (*usercv1.ExportJob, error) {
	actor := requestMeta(ctx)
	job, err := s.users.ExportUsers(ctx, actor, req.GetKeyword(), req.GetStatus(), req.GetFields(), reasonOr(req.GetReason(), "administrator export users"))
	if err != nil {
		return nil, err
	}
	return exportProto(job), nil
}

func (s *AdminUserService) GetExport(ctx context.Context, req *usercv1.GetExportRequest) (*usercv1.ExportJob, error) {
	actor := requestMeta(ctx)
	jobID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	job, err := s.users.GetExport(ctx, actor, jobID)
	if err != nil {
		return nil, err
	}
	return exportProto(job), nil
}

func (s *AdminUserService) ListExports(ctx context.Context, req *usercv1.ListExportsRequest) (*usercv1.ExportsReply, error) {
	actor := requestMeta(ctx)
	items, next, err := s.users.ListExports(ctx, actor, pageSize(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &usercv1.ExportsReply{Meta: &usercv1.ListMeta{NextPageToken: next}}
	for _, job := range items {
		out.Items = append(out.Items, exportProto(job))
	}
	return out, nil
}

func exportProto(job *biz.ExportJob) *usercv1.ExportJob {
	return &usercv1.ExportJob{
		Id: id(job.ID), Kind: job.Kind, Status: job.Status,
		RequestedFields: join(job.RequestedFields), ArtifactName: job.ArtifactName,
		ExpiresAt: ts(job.ExpiresAt), CreatedAt: ts(job.CreatedAt), Error: job.Error,
	}
}
