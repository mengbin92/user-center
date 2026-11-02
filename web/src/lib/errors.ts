import type { ApiErrorBody } from './types'

export const ERROR_REASON = {
  validation: 'VALIDATION_FAILED',
  challengeInvalid: 'CHALLENGE_INVALID',
  unauthenticated: 'UNAUTHENTICATED',
  sessionRevoked: 'SESSION_REVOKED',
  permissionDenied: 'PERMISSION_DENIED',
  protectedAccount: 'PROTECTED_ACCOUNT',
  stepUpRequired: 'STEP_UP_REQUIRED',
  mfaEnrollmentRequired: 'MFA_ENROLLMENT_REQUIRED',
  userNotFound: 'USER_NOT_FOUND',
  resourceNotFound: 'RESOURCE_NOT_FOUND',
  revisionConflict: 'REVISION_CONFLICT',
  usernameExists: 'USERNAME_EXISTS',
  roleConstraintViolation: 'ROLE_CONSTRAINT_VIOLATION',
  rateLimited: 'RATE_LIMITED',
  mfaLocked: 'MFA_LOCKED',
  dependencyUnavailable: 'DEPENDENCY_UNAVAILABLE',
  authorizationUnavailable: 'AUTHORIZATION_UNAVAILABLE',
  mfaRequired: 'MFA_REQUIRED',
  invalidCredentials: 'INVALID_CREDENTIALS',
  lastLoginMethod: 'LAST_LOGIN_METHOD',
  rootProtected: 'ROOT_PROTECTED',
  policyConflict: 'POLICY_CONFLICT',
  passwordChangeRequired: 'PASSWORD_CHANGE_REQUIRED',
  delegationRequired: 'DELEGATION_REQUIRED',
  oauthNotBound: 'OAUTH_NOT_BOUND',
  oauthStateInvalid: 'OAUTH_STATE_INVALID',
  oauthUnavailable: 'OAUTH_UNAVAILABLE',
  integrationAuthFailed: 'INTEGRATION_AUTH_FAILED',
} as const

/**
 * Stable Chinese copy for security-significant reasons. Kept client-side so
 * the UI stays readable even when an upstream error drops the server message.
 */
const REASON_MESSAGES: Record<string, string> = {
  [ERROR_REASON.passwordChangeRequired]:
    '当前账号必须先修改初始密码，完成前无法访问管理功能或执行高风险操作。',
  [ERROR_REASON.mfaEnrollmentRequired]:
    '管理员账号必须先启用多因素认证，完成绑定前部分操作会被拒绝。',
  [ERROR_REASON.delegationRequired]:
    '该操作需要有效的角色委派授权，请联系管理员配置委派范围。',
  [ERROR_REASON.oauthNotBound]:
    '该第三方账号尚未绑定用户中心账号，请先登录后在安全中心完成绑定。',
  [ERROR_REASON.oauthStateInvalid]:
    '第三方授权状态已失效或已使用，请重新发起登录。',
  [ERROR_REASON.oauthUnavailable]:
    '第三方身份提供方暂不可用，请稍后重试或使用密码登录。',
  [ERROR_REASON.integrationAuthFailed]:
    '接入服务凭据无效或已停用，请重新轮换凭据后再试。',
}

export function reasonMessage(reason?: string | null): string | undefined {
  if (!reason) return undefined
  return REASON_MESSAGES[reason]
}

export class ApiError extends Error {
  readonly status: number
  readonly reason: string
  readonly metadata: Record<string, string>
  readonly requestId?: string

  constructor(options: {
    status: number
    reason?: string
    message?: string
    metadata?: Record<string, string>
    requestId?: string
  }) {
    super(options.message || '请求失败')
    this.name = 'ApiError'
    this.status = options.status
    this.reason = options.reason || 'UNKNOWN'
    this.metadata = options.metadata ?? {}
    this.requestId = options.requestId
  }

  get isUnauthorized(): boolean {
    return this.status === 401
  }

  get isForbidden(): boolean {
    return this.status === 403
  }

  get isStepUpRequired(): boolean {
    return this.reason === ERROR_REASON.stepUpRequired
  }

  get isPasswordChangeRequired(): boolean {
    return this.reason === ERROR_REASON.passwordChangeRequired
  }

  get isCsrfFailure(): boolean {
    return this.isForbidden && this.message.includes('CSRF')
  }

  get currentRevision(): string | undefined {
    return this.metadata.current_revision
  }

  get currentPolicyRevision(): string | undefined {
    return this.metadata.current_policy_revision
  }

  get conflictType(): string | undefined {
    return this.metadata.conflict_type
  }

  get isRevisionConflict(): boolean {
    return (
      this.reason === ERROR_REASON.revisionConflict ||
      this.reason === ERROR_REASON.policyConflict
    )
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError
}

export function errorMessage(error: unknown): string {
  if (isApiError(error)) return reasonMessage(error.reason) ?? error.message
  if (error instanceof Error) return error.message
  return '未知错误'
}

export function parseErrorBody(body: unknown): ApiErrorBody {
  if (body && typeof body === 'object') {
    const record = body as Record<string, unknown>
    return {
      code: typeof record.code === 'number' ? record.code : undefined,
      reason: typeof record.reason === 'string' ? record.reason : undefined,
      message: typeof record.message === 'string' ? record.message : undefined,
      metadata:
        record.metadata && typeof record.metadata === 'object'
          ? (record.metadata as Record<string, string>)
          : undefined,
    }
  }
  return {}
}
