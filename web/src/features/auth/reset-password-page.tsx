import { KeyRound, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router'

import { Button } from '../../components/button'
import { InlineAlert } from '../../components/card'
import { Field, Input } from '../../components/input'
import { AuthShell } from './auth-shell'
import { api } from '../../lib/api'
import { passwordValidationError } from '../../lib/password'
import { errorMessage, isApiError } from '../../lib/errors'

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const initialChallenge = searchParams.get('challenge') ?? ''
  const initialCode = searchParams.get('code') ?? ''
  const [challengeId, setChallengeId] = useState(initialChallenge)
  const [code, setCode] = useState(initialCode)
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const contextQuery = useQuery({
    queryKey: ['auth', 'context'],
    queryFn: () => api.auth.context(),
    retry: false,
    staleTime: 60_000,
  })
  const minLength = contextQuery.data?.password_min_length ?? 10
  const hasLinkParams = Boolean(initialChallenge && initialCode)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
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
    if (!challengeId.trim() || !code.trim()) {
      setError('重置链接不完整，请重新申请')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await api.auth.resetPassword({
        challenge_id: challengeId.trim(),
        code: code.trim(),
        new_password: password,
      })
      setDone(true)
    } catch (resetError) {
      if (isApiError(resetError) && resetError.reason === 'CHALLENGE_INVALID') {
        setError('重置链接无效或已过期，请重新申请')
      } else if (isApiError(resetError) && resetError.status === 429) {
        setError(`${resetError.message}，请稍后再试`)
      } else {
        setError(errorMessage(resetError))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell
      title={done ? '密码已重置' : '设置新密码'}
      subtitle={
        done
          ? '所有其他会话已失效，请使用新密码登录'
          : '重置链接只能使用一次，请设置一个未使用过的新密码'
      }
      footer={
        <Link to="/login" className="font-medium text-indigo-700 hover:underline">
          返回登录
        </Link>
      }
    >
      {done ? (
        <div className="space-y-3 text-center">
          <span className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-emerald-50 text-emerald-600">
            <ShieldCheck className="h-6 w-6" />
          </span>
          <p className="text-xs text-slate-500">
            密码已更新，出于安全考虑，其他设备上的会话已被撤销。
          </p>
          <Link
            to="/login"
            className="inline-flex w-full items-center justify-center rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
          >
            使用新密码登录
          </Link>
        </div>
      ) : (
        <form className="space-y-3.5" onSubmit={submit}>
          {!hasLinkParams ? (
            <InlineAlert tone="warning" title="未检测到完整的重置链接">
              请从邮件中的链接打开本页面，或在下方手动填写 challenge 与验证码。
            </InlineAlert>
          ) : null}

          <Field label="challenge_id" htmlFor="reset-challenge" required>
            <Input
              id="reset-challenge"
              value={challengeId}
              onChange={(event) => setChallengeId(event.target.value)}
              placeholder="重置 challenge"
              className="font-mono text-[11px]"
              required
            />
          </Field>
          <Field label="验证码" htmlFor="reset-code" required>
            <Input
              id="reset-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="邮件中的验证码"
              className="font-mono text-[11px]"
              required
            />
          </Field>
          <Field
            label="新密码"
            htmlFor="reset-password"
            required
            hint={`至少 ${minLength} 位，不能与当前密码相同`}
          >
            <Input
              id="reset-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={minLength}
              required
              autoFocus
            />
          </Field>
          <Field label="确认新密码" htmlFor="reset-confirm" required>
            <Input
              id="reset-confirm"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
            />
          </Field>

          {error ? (
            <InlineAlert tone="danger" title="重置失败">
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
            重置密码
          </Button>
          <Link
            to="/forgot-password"
            className="block text-center text-[11px] font-medium text-indigo-700 hover:underline"
          >
            重新申请重置链接
          </Link>
        </form>
      )}
    </AuthShell>
  )
}
