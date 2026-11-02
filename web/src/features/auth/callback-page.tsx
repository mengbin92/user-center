import { ArrowLeft, PlugZap } from 'lucide-react'
import { Link, useParams, useSearchParams } from 'react-router'

import { InlineAlert } from '../../components/card'
import { AuthShell } from './auth-shell'

export function AuthCallbackPage() {
  const { provider = '' } = useParams()
  const [searchParams] = useSearchParams()
  const hasCode = Boolean(searchParams.get('code'))
  const hasState = Boolean(searchParams.get('state'))
  const error = searchParams.get('error')

  return (
    <AuthShell
      title="第三方登录回调"
      subtitle={`身份提供方：${provider || '未知'}`}
      footer={
        <Link to="/login" className="font-medium text-indigo-700 hover:underline">
          返回密码登录
        </Link>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-col items-center gap-2 py-2 text-center">
          <span className="grid h-12 w-12 place-items-center rounded-full bg-amber-50 text-amber-600">
            <PlugZap className="h-6 w-6" />
          </span>
          <div className="text-sm font-semibold text-slate-900">
            回调入口已就绪，尚未启用
          </div>
          <p className="max-w-sm text-xs text-slate-500">
            本页是第三方登录的占位安全入口。当前 API 契约未提供 OAuth
            回调交换端点，因此不会在此处理凭据。请联系管理员完成身份提供方接入。
          </p>
        </div>

        <dl className="grid grid-cols-2 gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs">
          <div>
            <dt className="text-slate-500">provider</dt>
            <dd className="font-mono text-slate-800">{provider || '—'}</dd>
          </div>
          <div>
            <dt className="text-slate-500">回调参数</dt>
            <dd className="font-mono text-slate-800">
              {hasCode ? 'code 已返回' : '无 code'} /{' '}
              {hasState ? 'state 已返回' : '无 state'}
            </dd>
          </div>
        </dl>

        {error ? (
          <InlineAlert tone="danger" title="身份提供方返回错误">
            {error}
          </InlineAlert>
        ) : (
          <InlineAlert tone="info" title="安全提示">
            不要在浏览器中粘贴或保存授权码。所有令牌交换必须由后端完成。
          </InlineAlert>
        )}

        <Link
          to="/login"
          className="flex w-full items-center justify-center gap-1 rounded-md bg-indigo-600 px-3 py-2 text-xs font-medium text-white hover:bg-indigo-500"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          返回登录
        </Link>
      </div>
    </AuthShell>
  )
}
