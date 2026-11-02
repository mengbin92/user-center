import { MailCheck } from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router'

import { Button } from '../../components/button'
import { InlineAlert } from '../../components/card'
import { Field, Input } from '../../components/input'
import { AuthShell } from './auth-shell'
import { api } from '../../lib/api'
import { errorMessage, isApiError } from '../../lib/errors'

export function ForgotPasswordPage() {
  const [identifier, setIdentifier] = useState('')
  const [sent, setSent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await api.auth.createPasswordResetChallenge({
        identifier: identifier.trim(),
      })
      setSent(true)
    } catch (requestError) {
      if (isApiError(requestError) && requestError.status === 429) {
        setError(`${requestError.message}，请稍后再试`)
      } else {
        setError(errorMessage(requestError))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell
      title="找回密码"
      subtitle="输入用户名或邮箱，我们会发送重置链接"
      footer={
        <>
          想起密码了？
          <Link to="/login" className="font-medium text-indigo-700 hover:underline">
            返回登录
          </Link>
        </>
      }
    >
      {sent ? (
        <div className="space-y-3 text-center">
          <span className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-emerald-50 text-emerald-600">
            <MailCheck className="h-6 w-6" />
          </span>
          <div>
            <div className="text-sm font-semibold text-slate-900">
              重置邮件已发送
            </div>
            <p className="mt-1 text-xs text-slate-500">
              如果该账号存在且可接收邮件，你会在几分钟内收到重置链接。链接 30 分钟内有效。
            </p>
          </div>
          <InlineAlert tone="info" title="没有收到邮件？">
            请检查垃圾邮件。开发环境使用 console 邮件驱动时，重置链接会打印在后端日志中。
          </InlineAlert>
          <div className="flex flex-col gap-2">
            <Button variant="secondary" onClick={() => setSent(false)}>
              重新输入账号
            </Button>
            <Link
              to="/login"
              className="text-xs font-medium text-indigo-700 hover:underline"
            >
              返回登录
            </Link>
          </div>
        </div>
      ) : (
        <form className="space-y-3.5" onSubmit={submit}>
          <Field
            label="用户名或邮箱"
            htmlFor="forgot-identifier"
            required
            hint="出于安全考虑，无论账号是否存在，响应都保持一致。"
          >
            <Input
              id="forgot-identifier"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              placeholder="用户名或注册邮箱"
              autoComplete="username"
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
            icon={<MailCheck className="h-4 w-4" />}
          >
            发送重置链接
          </Button>
        </form>
      )}
    </AuthShell>
  )
}
