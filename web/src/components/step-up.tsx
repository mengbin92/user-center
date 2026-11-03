import { ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'

import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { errorMessage } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { Button } from './button'
import { Dialog } from './dialog'
import { Field, Input } from './input'
import { InlineAlert } from './card'
import { useToast } from './toast'

type StepUpContextValue = {
  requestStepUp: () => Promise<boolean>
}

const StepUpContext = createContext<StepUpContextValue | null>(null)

export function StepUpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const resolver = useRef<((verified: boolean) => void) | null>(null)
  const challengeVersion = useRef(0)
  const toast = useToast()
  const { sessionGeneration, getSessionGeneration } = useAuth()

  const security = useQuery({
    queryKey: ['me', 'security'],
    queryFn: () => api.me.security(),
    enabled: open,
    staleTime: 0,
    retry: false,
  })

  const passwordAvailable = security.data?.password_available !== false

  const requestStepUp = useCallback(() => {
    return new Promise<boolean>((resolve) => {
      challengeVersion.current += 1
      resolver.current?.(false)
      setPassword('')
      setCode('')
      setError(null)
      resolver.current = resolve
      setOpen(true)
    })
  }, [])

  const finish = useCallback((verified: boolean) => {
    challengeVersion.current += 1
    resolver.current?.(verified)
    resolver.current = null
    setOpen(false)
    setPassword('')
    setCode('')
    setBusy(false)
  }, [])

  useEffect(() => {
    finish(false)
    return () => {
      resolver.current?.(false)
      resolver.current = null
    }
  }, [sessionGeneration, finish])

  const submit = async () => {
    if (busy) return
    if (!security.data) {
      setError('请先等待读取账号安全状态')
      return
    }
    if (passwordAvailable && !password.trim()) {
      setError('请输入当前密码')
      return
    }
    if (!code.trim()) {
      setError('请输入动态验证码或恢复码')
      return
    }
    const generation = getSessionGeneration()
    const challenge = challengeVersion.current
    setBusy(true)
    setError(null)
    try {
      const reply = await api.me.verifySecurity({
        current_password: passwordAvailable ? password : '',
        code: code.trim(),
      })
      if (generation !== getSessionGeneration() || challenge !== challengeVersion.current) return
      if (!reply.verified) {
        setError('安全验证未通过，请重试')
        return
      }
      toast.success(
        '安全验证通过',
        `有效时间至 ${formatDateTime(reply.expires_at)}，现在可以执行高风险操作。`,
      )
      finish(true)
    } catch (verifyError) {
      if (generation !== getSessionGeneration() || challenge !== challengeVersion.current) return
      setError(errorMessage(verifyError))
    } finally {
      if (challenge === challengeVersion.current) setBusy(false)
    }
  }

  return (
    <StepUpContext.Provider value={{ requestStepUp }}>
      {children}
      <Dialog
        open={open}
        dismissible={!busy}
        onClose={() => finish(false)}
        title="需要近期安全验证"
        description="该操作属于高风险变更。验证通过后本次操作会自动重试一次。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => finish(false)}
              disabled={busy}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void submit()}
              loading={busy}
              icon={<ShieldCheck className="h-3.5 w-3.5" />}
            >
              验证并继续
            </Button>
          </>
        }
      >
        {security.data?.mfa_enabled === false ? (
          <InlineAlert tone="warning" title="当前账号尚未启用多因素认证">
            高风险操作要求验证动态验证码。请先前往
            <Link
              to="/account/security"
              className="mx-1 font-medium text-indigo-700 underline"
              onClick={() => finish(false)}
            >
              安全中心
            </Link>
            启用 MFA，再重新执行此操作。
          </InlineAlert>
        ) : (
          <InlineAlert tone="info" title={passwordAvailable ? "使用当前密码 + MFA 验证" : "使用第三方身份 + MFA 验证"}>
            支持输入身份验证器 6 位动态码，或使用一枚未使用的恢复码。
          </InlineAlert>
        )}
        {!passwordAvailable ? <InlineAlert tone="info" title="使用已绑定的第三方身份验证">请先前往 <Link to="/account/security" onClick={() => finish(false)} className="font-medium underline">安全中心重新验证绑定身份</Link>，返回后输入动态码完成近期验证。</InlineAlert> : null}
        {passwordAvailable ? <Field label="当前密码" htmlFor="step-up-password" required>
          <Input
            id="step-up-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="输入当前登录密码"
          />
        </Field> : null}
        <Field
          label="动态验证码 / 恢复码"
          htmlFor="step-up-code"
          required
          hint="TOTP 6 位数字，或形如 XXXXX-XXXXX 的恢复码"
        >
          <Input
            id="step-up-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="例如 123456"
          />
        </Field>
        {error ? (
          <p className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
            {error}
          </p>
        ) : null}
      </Dialog>
    </StepUpContext.Provider>
  )
}

export function useStepUp(): StepUpContextValue {
  const context = useContext(StepUpContext)
  if (!context) throw new Error('useStepUp 必须在 StepUpProvider 内使用')
  return context
}
