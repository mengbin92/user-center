import { ArrowLeft, CheckCircle2, Mail, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'

import { Button } from '../../components/button'
import { InlineAlert } from '../../components/card'
import { Checkbox, Field, Input } from '../../components/input'
import { AuthShell } from './auth-shell'
import { api } from '../../lib/api'
import { passwordValidationError } from '../../lib/password'
import { errorMessage, isApiError } from '../../lib/errors'
import { formatDateTime } from '../../lib/format'
import type { RegisterReply } from '../../lib/types'

function describeRegisterError(error: unknown): string {
  if (isApiError(error)) {
    if (error.reason === 'USERNAME_EXISTS') return '用户名已被占用'
    if (error.reason === 'CHALLENGE_INVALID') return '验证码无效或已过期'
    if (error.reason === 'RATE_LIMITED') return `${error.message}，请稍后再试`
    return error.message
  }
  return errorMessage(error)
}

export function RegisterPage() {
  const contextQuery = useQuery({
    queryKey: ['auth', 'context'],
    queryFn: () => api.auth.context(),
    retry: false,
    staleTime: 60_000,
  })
  const context = contextQuery.data
  const minLength = context?.password_min_length ?? 10
  const verificationRequired = context?.email_verification_required ?? true

  const [step, setStep] = useState<'email' | 'details' | 'done'>('email')
  const [email, setEmail] = useState('')
  const [challengeId, setChallengeId] = useState('')
  const [challengeExpiresAt, setChallengeExpiresAt] = useState('')
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [accepted, setAccepted] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [registered, setRegistered] = useState<RegisterReply | null>(null)

  useEffect(() => {
    if (context && !context.email_verification_required) {
      setStep((current) => (current === 'email' ? 'details' : current))
    }
  }, [context])

  const requestCode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    if (!email.trim()) {
      setError('请输入邮箱')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const reply = await api.auth.createRegistrationChallenge({
        email: email.trim(),
      })
      setChallengeId(reply.challenge_id ?? '')
      setChallengeExpiresAt(reply.expires_at ?? '')
      setStep('details')
    } catch (requestError) {
      setError(describeRegisterError(requestError))
    } finally {
      setBusy(false)
    }
  }

  const resendCode = async () => {
    if (busy || !email.trim()) return
    setBusy(true)
    setError(null)
    try {
      const reply = await api.auth.createRegistrationChallenge({
        email: email.trim(),
      })
      setChallengeId(reply.challenge_id ?? '')
      setChallengeExpiresAt(reply.expires_at ?? '')
    } catch (requestError) {
      setError(describeRegisterError(requestError))
    } finally {
      setBusy(false)
    }
  }

  const submitRegistration = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    const passwordError = passwordValidationError(password, minLength)
    if (passwordError) {
      setError(passwordError)
      return
    }
    if (password !== confirmPassword) {
      setError('两次输入的密码不一致')
      return
    }
    if (!accepted) {
      setError('请阅读并同意服务条款与隐私政策')
      return
    }
    if (verificationRequired && (!challengeId || !code.trim())) {
      setError('请先获取并填写邮箱验证码')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const reply = await api.auth.register({
        username: username.trim(),
        email: email.trim(),
        password,
        code: code.trim(),
        challenge_id: challengeId,
        terms_version: 'v1',
      })
      setRegistered(reply)
      setStep('done')
    } catch (registerError) {
      setError(describeRegisterError(registerError))
    } finally {
      setBusy(false)
    }
  }

  if (context?.registration_enabled === false) {
    return (
      <AuthShell title="注册暂未开放" subtitle="管理员尚未开放自助注册">
        <div className="space-y-3 text-center">
          <InlineAlert tone="info" title="当前只允许受邀或管理员创建账号">
            如需账号，请联系组织管理员通过管理控制台创建。
          </InlineAlert>
          <Link
            to="/login"
            className="inline-flex rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500"
          >
            返回登录
          </Link>
        </div>
      </AuthShell>
    )
  }

  return (
    <AuthShell
      title={step === 'done' ? '注册成功' : '创建账号'}
      subtitle={
        step === 'done'
          ? '账号已创建，现在可以登录'
          : verificationRequired
            ? '先验证邮箱，再设置账号信息'
            : '填写账号信息完成注册'
      }
      footer={
        <>
          已有账号？
          <Link to="/login" className="font-medium text-indigo-700 hover:underline">
            返回登录
          </Link>
        </>
      }
    >
      {step === 'email' ? (
        <form className="space-y-3.5" onSubmit={requestCode}>
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-indigo-600 text-[10px] font-semibold text-white">
              1
            </span>
            验证邮箱
            <span className="h-px flex-1 bg-slate-200" />
            <span className="text-slate-400">2 设置账号</span>
          </div>
          <Field
            label="邮箱"
            htmlFor="register-email"
            required
            hint={
              <>
                验证码会发送到该邮箱。开发环境使用 console 邮件驱动时，验证码会打印在后端日志中。
              </>
            }
          >
            <Input
              id="register-email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.com"
              required
              autoFocus
            />
          </Field>
          {error ? (
            <InlineAlert tone="danger" title="发送失败">
              {error}
            </InlineAlert>
          ) : null}
          <Button
            type="submit"
            variant="primary"
            className="w-full"
            loading={busy}
            icon={<Mail className="h-4 w-4" />}
          >
            发送验证码
          </Button>
        </form>
      ) : step === 'details' ? (
        <form className="space-y-3.5" onSubmit={submitRegistration}>
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            邮箱验证
            <span className="h-px flex-1 bg-slate-200" />
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-indigo-600 text-[10px] font-semibold text-white">
              2
            </span>
            设置账号
          </div>

          <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs">
            <div className="text-slate-500">注册邮箱</div>
            <div className="font-medium text-slate-800">{email}</div>
            {challengeExpiresAt ? (
              <div className="mt-0.5 text-[10px] text-slate-400">
                验证码有效期至 {formatDateTime(challengeExpiresAt)}
              </div>
            ) : null}
          </div>

          {verificationRequired ? (
            <Field label="邮箱验证码" htmlFor="register-code" required>
              <div className="flex gap-2">
                <Input
                  id="register-code"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  placeholder="6 位验证码"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
                <Button
                  variant="secondary"
                  size="md"
                  onClick={() => void resendCode()}
                  disabled={busy}
                  className="shrink-0"
                >
                  重新发送
                </Button>
              </div>
            </Field>
          ) : null}

          <Field label="用户名" htmlFor="register-username" required>
            <Input
              id="register-username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="登录用户名"
              required
            />
          </Field>

          <Field
            label="密码"
            htmlFor="register-password"
            required
            hint={`至少 ${minLength} 位，建议包含大小写字母、数字与符号`}
          >
            <Input
              id="register-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={minLength}
              required
            />
          </Field>
          <Field label="确认密码" htmlFor="register-confirm" required>
            <Input
              id="register-confirm"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
            />
          </Field>

          <Checkbox
            checked={accepted}
            onChange={(event) => setAccepted(event.target.checked)}
            label={
              <span>
                我已阅读并同意
                <Link to="/terms" className="mx-1 text-indigo-700 hover:underline">
                  服务条款
                </Link>
                与
                <Link to="/privacy" className="mx-1 text-indigo-700 hover:underline">
                  隐私政策
                </Link>
              </span>
            }
          />

          {error ? (
            <InlineAlert tone="danger" title="注册失败">
              {error}
            </InlineAlert>
          ) : null}

          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            创建账号
          </Button>
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={() => {
              setStep('email')
              setError(null)
            }}
            disabled={busy}
            icon={<ArrowLeft className="h-3.5 w-3.5" />}
          >
            更换邮箱
          </Button>
        </form>
      ) : (
        <div className="space-y-3 text-center">
          <span className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-emerald-50 text-emerald-600">
            <ShieldCheck className="h-6 w-6" />
          </span>
          <div>
            <div className="text-sm font-semibold text-slate-900">
              {registered?.user?.username ?? username}，欢迎加入
            </div>
            <p className="mt-1 text-xs text-slate-500">
              账号已创建。请使用新账号登录，并根据需要启用多因素认证。
            </p>
          </div>
          <Link
            to="/login"
            className="inline-flex w-full items-center justify-center rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
          >
            前往登录
          </Link>
        </div>
      )}
    </AuthShell>
  )
}
