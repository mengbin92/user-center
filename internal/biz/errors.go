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
	ErrPasswordChange     = kerrors.Forbidden("PASSWORD_CHANGE_REQUIRED", "首次登录必须先修改初始密码")
	ErrDelegationRequired = kerrors.Forbidden("DELEGATION_REQUIRED", "缺少覆盖该操作的委派授权")
	ErrOAuthNotBound      = kerrors.Conflict("OAUTH_NOT_BOUND", "该第三方账号尚未绑定用户中心账号")
	ErrOAuthState         = kerrors.BadRequest("OAUTH_STATE_INVALID", "第三方登录状态无效或已过期")
	ErrOAuthUnavailable   = kerrors.ServiceUnavailable("OAUTH_UNAVAILABLE", "第三方登录暂不可用")
	ErrOAuthBound         = kerrors.Conflict("OAUTH_ALREADY_BOUND", "该第三方账号已绑定其他用户")
)

func Validation(msg string) error {
	return kerrors.BadRequest("VALIDATION_FAILED", msg)
}

// PasswordPolicyError marks a rejection that a user can act on by choosing a
// different password. It is deliberately distinct from VALIDATION_FAILED so the
// web form can attach the reason to the password field instead of showing a
// generic "request invalid".
func PasswordPolicyError(msg string) error {
	return kerrors.BadRequest("PASSWORD_POLICY_VIOLATION", msg)
}

func ConflictCode(reason, msg string) error {
	return kerrors.Conflict(reason, msg)
}

func ConflictRevision(current uint64) error {
	err := kerrors.Conflict("REVISION_CONFLICT", "数据已被更新，请刷新后重试")
	return err.WithMetadata(map[string]string{"current_revision": uitoa(current), "conflict_type": "target"})
}

func ConflictPolicy(current uint64) error {
	err := kerrors.Conflict("POLICY_CONFLICT", "授权策略已被更新，请刷新后重试")
	return err.WithMetadata(map[string]string{"current_policy_revision": uitoa(current), "conflict_type": "policy"})
}

var (
	ErrOIDCInvalidGrant      = kerrors.BadRequest("INVALID_GRANT", "授权码、刷新令牌或 PKCE 校验失败")
	ErrOIDCClientNotFound    = kerrors.NotFound("OIDC_CLIENT_NOT_FOUND", "OIDC 客户端不存在")
	ErrOrganisationLastOwner = kerrors.Conflict("ORGANIZATION_LAST_OWNER", "组织必须至少保留一名 owner")
	ErrOrgRoleExists         = kerrors.Conflict("ORGANIZATION_ROLE_EXISTS", "组织内已存在同名角色")
)
