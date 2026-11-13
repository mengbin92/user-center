import { ArrowLeft, Fingerprint, KeyRound, Loader2, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, Navigate, useSearchParams } from 'react-router'

import { Button } from '../../components/button'
import { FullPageLoading } from '../../app/guards'
import { InlineAlert } from '../../components/card'
import { Checkbox, Field, Input } from '../../components/input'
import { useToast } from '../../components/toast'
import { AuthShell } from './auth-shell'
import { ProviderButtons } from './provider-buttons'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage, isApiError } from '../../lib/errors'
import { formatDateTime } from '../../lib/format'
import { oauthErrorMessage } from '../../lib/oauth'
import { oidcAuthorizationPath, safeNext } from '../../lib/paths'
import { getLoginAssertion, passkeySupported } from '../../lib/webauthn'
import type { WebAuthnChallenge } from '../../lib/types'

function describeAuthError(error: unknown): string {
  if (isApiError(error)) {
    if (error.reason === 'INVALID_CREDENTIALS') return '用户名或密码错误'
    if (error.reason === 'RATE_LIMITED') {
      return `${error.message}，请稍后再试`
    }
    if (error.reason === 'MFA_LOCKED') {
      return `${error.message}，请等待锁定时间结束后重试`
    }
    if (error.reason === 'CHALLENGE_INVALID') {
      return '验证码无效或已过期，请重新登录'
    }
    if (error.reason === 'MFA_ENROLLMENT_REQUIRED') {
      return '管理员账号必须先启用多因素认证'
    }
    if (error.status === 0) return error.message
    return error.message
  }
  return errorMessage(error)
}

function describePasskeyError(error: unknown): string {
  if (
    typeof DOMException !== 'undefined' &&
    error instanceof DOMException &&
    (error.name === 'NotAllowedError' || error.name === 'AbortError')
  ) {
    return '未找到可用的通行密钥，或操作已取消。可改用密码登录。'
  }
  if (isApiError(error) && error.reason === 'CHALLENGE_INVALID') {
    return '通行密钥验证失败，请重试或改用密码登录。'
  }
  return describeAuthError(error)
}

export function LoginPage() {
  const { status, hasAdmin, signIn } = useAuth()
  const toast = useToast()
  const [searchParams] = useSearchParams()
  const next = safeNext(searchParams.get('next'))
  const oauthErrorParam = searchParams.get('oauth_error')
  const oauthMfaChallenge = searchParams.get('mfa_challenge')

  const [postLoginPath, setPostLoginPath] = useState<string | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [remember, setRemember] = useState(false)
  const [phase, setPhase] = useState<'password' | 'mfa'>(oauthMfaChallenge ? 'mfa' : 'password')
  const [challengeId, setChallengeId] = useState(oauthMfaChallenge ?? '')
  const [challengeExpiresAt, setChallengeExpiresAt] = useState('')
  const [code, setCode] = useState('')
  const [webAuthn, setWebAuthn] = useState<WebAuthnChallenge | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const destination = postLoginPath ?? next ?? (hasAdmin ? '/admin' : '/account')
  const oidcNext = oidcAuthorizationPath(destination)

  useEffect(() => {
    if (status === 'authenticated' && !oauthErrorParam && oidcNext) {
      window.location.replace(oidcNext)
    }
  }, [status, oauthErrorParam, oidcNext])

  const contextQuery = useQuery({
    queryKey: ['auth', 'context'],
    queryFn: () => api.auth.context(),
    retry: false,
    staleTime: 60_000,
  })

  if (status === 'authenticated') {
    // The backend redirects OAuth start failures to /login even for an
    // authenticated bind request; forward them to the account security page.
    if (oauthErrorParam) {
      return (
        <Navigate
          to={`/account/security?oauth_error=${encodeURIComponent(oauthErrorParam)}`}
          replace
        />
      )
    }
    if (oidcNext) return <FullPageLoading label="正在继续应用授权…" />
    return (
      <Navigate
        to={destination}
        replace
      />
    )
  }

  // The per-user session cap reclaims older sessions on every issuance path
  // (password, TOTP, passkey). All three branches share one announcement so a
  // passkey login cannot quietly log the user out of another device.
  const announceRecycledSessions = (reply: { recycled_sessions?: number }) => {
    if (!reply.recycled_sessions) return
    toast.info(
      '已退出其他设备',
      `同时在线会话已达上限，已自动退出 ${reply.recycled_sessions} 个最久未使用的会话。`,
    )
  }

  const submitPassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const reply = await api.auth.login({ username, password, remember })
      if (reply.status === 'mfa_required') {
        if (!reply.challenge_id) {
          setError('服务端未返回 MFA challenge，请重新登录')
          return
        }
        setChallengeId(reply.challenge_id)
        setChallengeExpiresAt(reply.challenge_expires_at ?? '')
        setWebAuthn(reply.webauthn ?? null)
        setCode('')
        setPhase('mfa')
        return
      }
      announceRecycledSessions(reply)
      if (reply.password_change_required) {
        setPostLoginPath(`/account/security?password_change_required=1${oidcNext ? `&next=${encodeURIComponent(oidcNext)}` : ''}`)
      }
      await signIn()
    } catch (loginError) {
      setError(describeAuthError(loginError))
    } finally {
      setBusy(false)
    }
  }

  const submitMfa = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    if (!code.trim()) {
      setError('请输入动态验证码')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const reply = await api.auth.completeMfa({
        challenge_id: challengeId,
        code: code.trim(),
      })
      announceRecycledSessions(reply)
      if (reply.password_change_required) {
        setPostLoginPath(`/account/security?password_change_required=1${oidcNext ? `&next=${encodeURIComponent(oidcNext)}` : ''}`)
      }
      await signIn()
    } catch (mfaError) {
      setError(describeAuthError(mfaError))
    } finally {
      setBusy(false)
    }
  }

  const submitPasskey = async () => {
    if (busy || !webAuthn?.challenge || !challengeId) return
    setBusy(true)
    setError(null)
    try {
      const assertion = await getLoginAssertion(
        webAuthn.challenge,
        webAuthn.rp_id ?? '',
        webAuthn.allow_credential_ids ?? [],
        challengeId,
      )
      const reply = await api.auth.completeMfa(assertion)
      announceRecycledSessions(reply)
      if (reply.password_change_required) {
        setPostLoginPath(`/account/security?password_change_required=1${oidcNext ? `&next=${encodeURIComponent(oidcNext)}` : ''}`)
      }
      await signIn()
    } catch (passkeyError) {
      setError(describeAuthError(passkeyError))
    } finally {
      setBusy(false)
    }
  }

  const submitPasskeyLogin = async () => {
    if (busy) return
    const identifier = username.trim()
    if (!identifier) {
      setError('请先输入用户名或邮箱，再使用通行密钥登录')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const challenge = await api.auth.beginPasskeyLogin({ username: identifier })
      const assertion = await getLoginAssertion(
        challenge.challenge ?? '',
        challenge.rp_id ?? '',
        challenge.allow_credential_ids ?? [],
        challenge.challenge_id ?? '',
      )
      const reply = await api.auth.completePasskeyLogin({ ...assertion, remember })
      if (reply.status === 'mfa_required') {
        if (!reply.challenge_id) {
          setError('服务端未返回 MFA challenge，请重新登录')
          return
        }
        setChallengeId(reply.challenge_id)
        setChallengeExpiresAt(reply.challenge_expires_at ?? '')
        // The passkey was the first factor; the remaining factor is TOTP or a
        // recovery code, so the MFA screen must not offer the passkey again.
        setWebAuthn(null)
        setCode('')
        setPhase('mfa')
        return
      }
      announceRecycledSessions(reply)
      if (reply.password_change_required) {
        setPostLoginPath(`/account/security?password_change_required=1${oidcNext ? `&next=${encodeURIComponent(oidcNext)}` : ''}`)
      }
      await signIn()
    } catch (passkeyError) {
      setError(describePasskeyError(passkeyError))
    } finally {
      setBusy(false)
    }
  }

  const resetMfa = () => {
    setPhase('password')
    setChallengeId('')
    setChallengeExpiresAt('')
    setCode('')
    setWebAuthn(null)
    setError(null)
  }

  return (
    <AuthShell
      title={phase === 'password' ? '登录用户中心' : '完成两步验证'}
      subtitle={
        phase === 'password'
          ? '使用用户名或邮箱登录，会话保存在 HttpOnly Cookie 中'
          : '输入身份验证器中的 6 位动态码，或使用一枚恢复码'
      }
      footer={
        <>
          还没有账号？
          {contextQuery.data?.registration_enabled === false ? (
            <span className="text-slate-400">注册暂未开放</span>
          ) : (
            <Link to="/register" className="font-medium text-indigo-700 hover:underline">
              立即注册
            </Link>
          )}
        </>
      }
    >
      {phase === 'password' ? (
        <form className="space-y-3.5" onSubmit={submitPassword}>
          <Field label="用户名或邮箱" htmlFor="login-username" required>
            <Input
              id="login-username"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="请输入用户名或邮箱"
              required
              autoFocus
            />
          </Field>
          <Field
            label="密码"
            htmlFor="login-password"
            required
            hint={
              contextQuery.data?.password_min_length
                ? `密码最少 ${contextQuery.data.password_min_length} 位`
                : undefined
            }
          >
            <Input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="请输入密码"
              required
            />
          </Field>
          <div className="flex items-center justify-between">
            <Checkbox
              checked={remember}
              onChange={(event) => setRemember(event.target.checked)}
              label="在此设备保持登录"
            />
            <Link
              to="/forgot-password"
              className="text-[11px] font-medium text-indigo-700 hover:underline"
            >
              忘记密码？
            </Link>
          </div>

          {oauthErrorParam ? (
            <InlineAlert tone="danger" title="第三方登录失败">
              {oauthErrorMessage(oauthErrorParam)}
            </InlineAlert>
          ) : null}

          {error ? (
            <InlineAlert tone="danger" title="登录失败">
              {error}
            </InlineAlert>
          ) : null}

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            loading={busy}
            icon={<KeyRound className="h-4 w-4" />}
          >
            登录
          </Button>

          {passkeySupported() ? (
            <div className="space-y-1.5">
              <Button
                type="button"
                variant="secondary"
                className="w-full"
                disabled={busy}
                onClick={() => void submitPasskeyLogin()}
                icon={<Fingerprint className="h-4 w-4" />}
              >
                使用通行密钥
              </Button>
              <p className="text-center text-[10px] text-slate-400">
                用已绑定的 Passkey 免密码登录；未绑定时请先用密码登录，再到安全中心添加。
              </p>
            </div>
          ) : null}

          {contextQuery.data?.providers?.length ? (
            <div className="space-y-2 border-t border-slate-100 pt-3">
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-wide text-slate-400">
                <span className="h-px flex-1 bg-slate-100" />
                第三方身份提供方
                <span className="h-px flex-1 bg-slate-100" />
              </div>
              <ProviderButtons providers={contextQuery.data.providers} next={next} />
              <p className="text-center text-[10px] text-slate-400">
                将跳转到身份提供方完成授权，回调由服务端校验状态。
              </p>
            </div>
          ) : null}
        </form>
      ) : (
        <form className="space-y-3.5" onSubmit={submitMfa}>
          <div className="flex items-start gap-2 rounded-md border border-indigo-100 bg-indigo-50 px-3 py-2 text-xs text-indigo-800">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <div className="font-medium">账号已开启多因素认证</div>
              {challengeExpiresAt ? (
                <div className="opacity-80">
                  验证窗口有效期至 {formatDateTime(challengeExpiresAt)}
                </div>
              ) : null}
            </div>
          </div>

          <Field
            label="动态验证码或恢复码"
            htmlFor="login-mfa-code"
            required
            hint="身份验证器 6 位数字；恢复码不区分大小写"
          >
            <Input
              id="login-mfa-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="000000"
              autoComplete="one-time-code"
              inputMode="numeric"
              autoFocus
              required
            />
          </Field>

          {error ? (
            <InlineAlert tone="danger" title="验证失败">
              {error}
            </InlineAlert>
          ) : null}

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            loading={busy}
          >
            验证并登录
          </Button>
          {webAuthn ? (
            <Button
              type="button"
              variant="outline"
              className="w-full"
              disabled={busy}
              icon={<KeyRound className="h-4 w-4" />}
              onClick={() => void submitPasskey()}
            >
              使用 Passkey / 安全密钥
            </Button>
          ) : null}
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={resetMfa}
            disabled={busy}
            icon={<ArrowLeft className="h-3.5 w-3.5" />}
          >
            返回密码登录
          </Button>
          <div className="flex items-center justify-center gap-1 text-[10px] text-slate-400">
            <Loader2 className="h-3 w-3" />
            连续验证失败会触发临时锁定
          </div>
        </form>
      )}
    </AuthShell>
  )
}
