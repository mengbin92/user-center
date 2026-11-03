import {
  ArrowLeft,
  CircleCheck,
  Loader2,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'

import { InlineAlert } from '../../components/card'
import { AuthShell } from './auth-shell'
import { useAuth } from '../../lib/auth'
import { oauthErrorMessage, providerLabel } from '../../lib/oauth'

export function AuthCallbackPage() {
  const { provider = '' } = useParams()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { status, hasAdmin, signIn } = useAuth()

  const resultStatus = searchParams.get('status')
  const oauthError = searchParams.get('oauth_error')
  const bound = searchParams.get('bound')
  const [settled, setSettled] = useState(false)
  const attemptedSession = useRef(false)

  const needsSession =
    resultStatus === 'success' || Boolean(bound) || Boolean(oauthError)

  useEffect(() => {
    if (!needsSession) {
      setSettled(true)
      return
    }
    if (status === 'loading') return
    if (status === 'authenticated') {
      setSettled(true)
      return
    }
    if (status === 'anonymous' && !attemptedSession.current) {
      attemptedSession.current = true
      let active = true
      void signIn().finally(() => {
        if (active) setSettled(true)
      })
      return () => {
        active = false
      }
    }
    setSettled(true)
  }, [needsSession, status, signIn])

  const target = oauthError
    ? null
    : bound
      ? `/account/security?bound=${encodeURIComponent(bound)}`
      : resultStatus === 'success'
        ? hasAdmin
          ? '/admin'
          : '/account'
        : null

  useEffect(() => {
    if (!settled || !target || status !== 'authenticated') return
    const timer = window.setTimeout(() => {
      navigate(target, { replace: true })
    }, 1500)
    return () => window.clearTimeout(timer)
  }, [settled, target, status, navigate])

  let body: ReactNode
  if (oauthError) {
    body = (
      <>
        <InlineAlert tone="danger" icon={ShieldAlert} title="第三方登录失败">
          {oauthErrorMessage(oauthError)}
        </InlineAlert>
        <Link
          to={status === 'authenticated' ? '/account/security' : '/login'}
          className="flex w-full items-center justify-center gap-1 rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          {status === 'authenticated' ? '返回安全中心' : '返回登录'}
        </Link>
      </>
    )
  } else if (!settled) {
    body = (
      <div className="flex flex-col items-center gap-2 py-6 text-center">
        <Loader2 className="h-5 w-5 animate-spin text-indigo-500" />
        <div className="text-sm font-medium text-slate-800">
          正在确认登录状态…
        </div>
        <p className="text-xs text-slate-500">
          服务端已处理身份提供方回调，正在读取当前会话。
        </p>
      </div>
    )
  } else if (resultStatus === 'success') {
    body = (
      <>
        {status === 'authenticated' ? (
          <div className="flex flex-col items-center gap-2 py-3 text-center">
            <span className="grid h-12 w-12 place-items-center rounded-full bg-emerald-50 text-emerald-600">
              <CircleCheck className="h-6 w-6" />
            </span>
            <div className="text-sm font-semibold text-slate-900">
              第三方登录成功
            </div>
            <p className="text-xs text-slate-500">
              已将 {providerLabel(provider)} 身份与账号会话关联，即将进入
              {hasAdmin ? '管理控制台' : '账号中心'}。
            </p>
          </div>
        ) : (
          <InlineAlert
            tone="warning"
            icon={TriangleAlert}
            title="登录状态未建立"
          >
            身份提供方回调已返回，但当前浏览器没有有效会话。请重新登录。
          </InlineAlert>
        )}
        <Link
          to={status === 'authenticated' ? target ?? '/account' : '/login'}
          className="flex w-full items-center justify-center gap-1 rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
        >
          {status === 'authenticated'
            ? hasAdmin
              ? '进入管理控制台'
              : '进入账号中心'
            : '返回登录'}
        </Link>
      </>
    )
  } else if (bound) {
    body = (
      <>
        <InlineAlert tone="success" icon={CircleCheck} title="绑定成功">
          已将 {providerLabel(bound)} 身份绑定到当前账号，即将返回安全中心。
        </InlineAlert>
        <Link
          to={`/account/security?bound=${encodeURIComponent(bound)}`}
          className="flex w-full items-center justify-center gap-1 rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
        >
          返回安全中心
        </Link>
      </>
    )
  } else {
    body = (
      <>
        <InlineAlert tone="warning" icon={TriangleAlert} title="回调缺少结果参数">
          未识别到 status、bound 或 oauth_error 参数。请重新发起第三方登录或绑定。
        </InlineAlert>
        <Link
          to="/login"
          className="flex w-full items-center justify-center gap-1 rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          返回登录
        </Link>
      </>
    )
  }

  return (
    <AuthShell
      title="第三方身份回调"
      subtitle={`身份提供方：${providerLabel(provider || '未知')}`}
      footer={
        <Link to="/login" className="font-medium text-indigo-700 hover:underline">
          返回密码登录
        </Link>
      }
    >
      <div className="space-y-3">{body}</div>
    </AuthShell>
  )
}
