import { oidcAuthorizationPath } from './paths'

const PROVIDER_LABELS: Record<string, string> = {
  github: 'GitHub',
  google: 'Google',
  mock: 'Mock 开发登录',
}

const OAUTH_ERROR_MESSAGES: Record<string, string> = {
  not_bound:
    '该第三方账号尚未绑定用户中心账号。请先使用密码登录，再到安全中心完成绑定。',
  state_invalid: '第三方授权状态已失效或已使用，请重新发起登录。',
  oauth_failed: '第三方身份提供方验证失败，请稍后重试。',
  OAUTH_NOT_BOUND:
    '该第三方账号尚未绑定用户中心账号。请先使用密码登录，再到安全中心完成绑定。',
  OAUTH_STATE_INVALID: '第三方授权状态已失效或已使用，请重新发起登录。',
  OAUTH_UNAVAILABLE: '第三方身份提供方暂不可用，请稍后重试或使用密码登录。',
  oauth_unavailable: '第三方身份提供方暂不可用，请稍后重试或使用密码登录。',
}

export type OAuthMode = 'login' | 'bind' | 'verify'

export function providerLabel(provider: string): string {
  return PROVIDER_LABELS[provider] ?? provider
}

/**
 * The provider start endpoint answers with a 302 to the identity provider.
 * It must be reached with a full-page navigation so the browser follows the
 * redirect and sends the HttpOnly session cookie for bind mode.
 */
export function providerStartPath(
  provider: string,
  mode: OAuthMode = 'login',
  next?: string | null,
): string {
  const path = `/api/v1/auth/providers/${encodeURIComponent(provider)}/start`
  if (mode !== 'login') return `${path}?mode=${mode}`
  const continuation = oidcAuthorizationPath(next ?? null)
  return continuation ? `${path}?next=${encodeURIComponent(continuation)}` : path
}

export function oauthErrorMessage(raw?: string | null): string {
  if (!raw) return ''
  const known = OAUTH_ERROR_MESSAGES[raw]
  if (known) return known
  let decoded = raw
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    decoded = raw
  }
  return decoded.replaceAll('_', ' ')
}
