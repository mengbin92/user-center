import { Check, ExternalLink, ShieldCheck, X } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, InlineAlert } from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'

const SCOPE_LABELS: Record<string, { title: string; detail: string }> = {
  openid: { title: '确认你的身份', detail: '向应用提供不可变的账号标识（sub）。' },
  profile: { title: '基本资料', detail: '昵称与用户名。' },
  email: { title: '邮箱地址', detail: '邮箱及其验证状态。' },
  offline_access: {
    title: '离线访问',
    detail: '允许应用在你不在线时通过刷新令牌继续访问。',
  },
}

export function ConsentPage() {
  const [params] = useSearchParams()
  const handle = params.get('handle') ?? ''
  const [remember, setRemember] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const request = useQuery({
    queryKey: ['me', 'oidc-request', handle],
    queryFn: () => api.me.oidcConsentRequest(handle),
    enabled: Boolean(handle),
    retry: false,
  })

  async function decide(approve: boolean) {
    if (!handle || submitting) return
    setSubmitting(true)
    setError('')
    try {
      const reply = await api.me.decideOIDCConsent(handle, {
        handle,
        approve,
        remember: approve && remember,
      })
      const target = reply.redirect_url ?? ''
      if (!target) {
        setError('服务端未返回跳转地址，请返回应用重试。')
        return
      }
      window.location.assign(target)
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : '提交失败，请稍后重试',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-start justify-center bg-slate-100 px-4 py-12">
      <div className="w-full max-w-xl space-y-4">
        <PageTitle title="应用授权" />
        {!handle ? (
          <InlineAlert tone="warning">授权请求无效或已过期，请返回应用重新发起。</InlineAlert>
        ) : (
          <QueryBoundary query={request}>
            {(() => {
              const view = request.data
              if (!view) return null
              const scopes = view.scopes ?? []
              const granted = new Set(view.previously_granted_scopes ?? [])
              return (
                <Card>
                  <CardHeader
                    title="授权第三方应用"
                    description="请确认该应用请求的访问权限。拒绝后不会向其返回任何授权码。"
                  />
                  <CardContent className="space-y-5">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-base font-semibold text-slate-900">
                            {view.client_name || view.client_id}
                          </p>
                          <p className="mt-1 text-xs text-slate-500">
                            发起方：{view.service_owner || '—'} · 回调域名：
                            {view.redirect_host || '—'}
                          </p>
                        </div>
                        <ShieldCheck className="h-5 w-5 shrink-0 text-indigo-600" />
                      </div>
                      <p className="mt-3 text-[11px] text-slate-500">
                        请求时间：{formatDateTime(view.requested_at)} · 有效期至：
                        {formatDateTime(view.expires_at)}
                      </p>
                    </div>

                    <div className="space-y-2">
                      <p className="text-xs font-semibold text-slate-700">
                        该应用将获得
                      </p>
                      {scopes.map((scope) => {
                        const label = SCOPE_LABELS[scope] ?? {
                          title: scope,
                          detail: '应用请求的访问范围。',
                        }
                        return (
                          <div
                            key={scope}
                            className="flex items-start gap-3 rounded-md border border-slate-200 px-3 py-2"
                          >
                            <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-slate-800">
                                {label.title}
                                {granted.has(scope) && (
                                  <Badge className="ml-2" tone="neutral">
                                    已授予
                                  </Badge>
                                )}
                              </p>
                              <p className="text-xs text-slate-500">
                                {label.detail}
                              </p>
                            </div>
                          </div>
                        )
                      })}
                    </div>

                    <label className="flex items-center gap-2 text-xs text-slate-600">
                      <input
                        type="checkbox"
                        checked={remember}
                        onChange={(event) => setRemember(event.target.checked)}
                        className="h-3.5 w-3.5"
                      />
                      记住本次授权（下次不再询问，可在「应用授权」中撤销）
                    </label>

                    {error && <InlineAlert tone="danger">{error}</InlineAlert>}

                    <div className="flex flex-wrap items-center justify-end gap-2">
                      <Button
                        variant="ghost"
                        onClick={() => void decide(false)}
                        disabled={submitting}
                      >
                        <X className="h-4 w-4" />
                        拒绝
                      </Button>
                      <Button onClick={() => void decide(true)} disabled={submitting}>
                        <Check className="h-4 w-4" />
                        同意并继续
                      </Button>
                    </div>
                    <p className="flex items-center gap-1 text-[11px] text-slate-400">
                      <ExternalLink className="h-3 w-3" />
                      授权完成后将返回应用；本页不会签发授权码。
                    </p>
                  </CardContent>
                </Card>
              )
            })()}
          </QueryBoundary>
        )}
      </div>
    </div>
  )
}
