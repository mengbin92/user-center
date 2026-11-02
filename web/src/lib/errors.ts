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
} as const

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
  if (isApiError(error)) return error.message
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
