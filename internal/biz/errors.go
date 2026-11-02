package biz

import (
	"errors"

	kerrors "github.com/go-kratos/kratos/v3/errors"
)

var (
	ErrUnauthenticated    = kerrors.Unauthorized("UNAUTHENTICATED", "登录状态无效或已过期")
	ErrSessionRevoked     = kerrors.Unauthorized("SESSION_REVOKED", "会话已失效，请重新登录")
	ErrPermissionDenied   = kerrors.Forbidden("PERMISSION_DENIED", "无权执行该操作")
	ErrProtectedAccount   = kerrors.Forbidden("PROTECTED_ACCOUNT", "该账号受保护，不能执行此操作")
	ErrStepUpRequired     = kerrors.Forbidden("STEP_UP_REQUIRED", "该操作需要近期安全验证")
	ErrMFAEnrollmentReq   = kerrors.Forbidden("MFA_ENROLLMENT_REQUIRED", "管理员必须先启用多因素认证")
	ErrUserNotFound       = kerrors.NotFound("USER_NOT_FOUND", "用户不存在")
	ErrResourceNotFound   = kerrors.NotFound("RESOURCE_NOT_FOUND", "资源不存在")
	ErrRevisionConflict   = kerrors.Conflict("REVISION_CONFLICT", "数据已被更新，请刷新后重试")
	ErrUsernameExists     = kerrors.Conflict("USERNAME_EXISTS", "用户名已存在")
	ErrRoleConstraint     = kerrors.Conflict("ROLE_CONSTRAINT_VIOLATION", "角色约束冲突")
	ErrPolicyConflict     = kerrors.Conflict("POLICY_CONFLICT", "授权策略已被更新，请刷新后重试")
	ErrChallengeInvalid   = kerrors.BadRequest("CHALLENGE_INVALID", "验证码无效或已过期")
	ErrValidation         = kerrors.BadRequest("VALIDATION_FAILED", "请求参数不合法")
	ErrInvalidCredentials = kerrors.Unauthorized("INVALID_CREDENTIALS", "用户名或密码错误")
	ErrRateLimited        = kerrors.New(429, "RATE_LIMITED", "请求过于频繁，请稍后再试")
	ErrMFALocked          = kerrors.New(429, "MFA_LOCKED", "验证失败次数过多，请稍后再试")
	ErrMFADisabled        = kerrors.BadRequest("VALIDATION_FAILED", "尚未启用多因素认证")
	ErrMFAInvalid         = kerrors.BadRequest("CHALLENGE_INVALID", "验证码无效或已使用")
	ErrDependency         = kerrors.ServiceUnavailable("DEPENDENCY_UNAVAILABLE", "依赖服务暂不可用")
	ErrAuthorizationDown  = kerrors.ServiceUnavailable("AUTHORIZATION_UNAVAILABLE", "授权服务暂不可用")
	ErrLastLoginMethod    = kerrors.Conflict("LAST_LOGIN_METHOD", "至少需要保留一种可用登录方式")
	ErrRootProtected      = kerrors.Forbidden("ROOT_PROTECTED", "不能移除最后一个最高治理账号")
	ErrMFARequired        = kerrors.New(401, "MFA_REQUIRED", "需要完成多因素验证")
	ErrNotImplemented     = errors.New("not implemented")
)

func Validation(msg string) error {
	return kerrors.BadRequest("VALIDATION_FAILED", msg)
}

func ConflictRevision(current uint64) error {
	err := kerrors.Conflict("REVISION_CONFLICT", "数据已被更新，请刷新后重试")
	return err.WithMetadata(map[string]string{"current_revision": uitoa(current), "conflict_type": "target"})
}

func ConflictPolicy(current uint64) error {
	err := kerrors.Conflict("POLICY_CONFLICT", "授权策略已被更新，请刷新后重试")
	return err.WithMetadata(map[string]string{"current_policy_revision": uitoa(current), "conflict_type": "policy"})
}
