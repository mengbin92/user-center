import { KeyRound, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
} from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { AuthSettings } from '../../lib/types'

export function AdminProvidersPage() {
  const { can } = useAuth()
  const [pending, setPending] = useState<{ code: string; enable: boolean } | null>(null)
  const providers = useQuery({
    queryKey: ['admin', 'settings', 'providers'],
    queryFn: () => api.settings.providers(),
    retry: false,
  })
  const auth = useQuery({
    queryKey: ['admin', 'settings', 'auth'],
    queryFn: () => api.settings.auth(),
    retry: false,
  })

  const update = useApiMutation({
    mutationFn: ({ reason }: { reason: string }) => {
      const current = auth.data as AuthSettings | undefined
      // "none" is the explicit all-disabled sentinel; an empty list means
      // "every configured provider enabled" and must never be written by a
      // toggle, otherwise disabling the last one would silently re-enable all.
      const list = (current?.providers ?? []).filter((item) => item !== 'none')
      const code = pending?.code ?? ''
      const selection = pending?.enable
        ? Array.from(new Set([...list, code]))
        : list.filter((item) => item !== code)
      const next = selection.length === 0 ? ['none'] : selection
      return api.settings.updateAuth({
        providers: next,
        update_mask: 'providers',
        expected_revision: current?.revision ?? '1',
        reason,
      })
    },
    successMessage: '登录提供方状态已更新',
    invalidate: [
      ['admin', 'settings', 'providers'],
      ['admin', 'settings', 'auth'],
    ],
    onSuccess: () => setPending(null),
  })

  const items = providers.data?.items ?? []
  const configuredList = (auth.data?.providers ?? []).filter(
    (item) => item !== 'none',
  )
  const allDisabled = (auth.data?.providers ?? []).includes('none')
  const enabled = new Set(
    allDisabled ? [] : configuredList.length ? configuredList : items.map((i) => i.code ?? ''),
  )

  return (
    <div className="space-y-4">
      <PageTitle title="身份提供方" />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            外部身份提供方
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            凭据仅从环境变量读取，本页面不回显任何密钥；启停沿用认证配置接口并写入审计。清空启用项会写入显式「全部停用」标记，不会退回默认放行。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void providers.refetch()}>
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </Button>
      </div>

      <InlineAlert tone="info" title="凭据来源单一化">
        当前只支持 env 来源：<code>OAUTH_GITHUB_CLIENT_ID/SECRET</code>、
        <code>OAUTH_GOOGLE_CLIENT_ID/SECRET</code>。未配置时启用开关不可用，避免环境变量与数据库同时生效造成歧义。
      </InlineAlert>

      <Card>
        <CardHeader
          title="提供方清单"
          description={`配置版本 ${providers.data?.revision ?? '—'}`}
        />
        <CardContent className="p-0">
          <QueryBoundary query={providers} loadingLabel="读取提供方配置…">
            <Table minWidth="min-w-[820px]">
              <THead>
                <TR>
                  <TH>提供方</TH>
                  <TH>启用状态</TH>
                  <TH>凭据</TH>
                  <TH>回调地址</TH>
                  <TH>所需环境变量</TH>
                  <TH>最近变更</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((item) => {
                  const active = item.enabled && enabled.has(item.code ?? '')
                  return (
                    <TR key={item.code}>
                      <TD>
                        <span className="inline-flex items-center gap-1.5 font-medium text-slate-800">
                          <KeyRound className="h-3.5 w-3.5 text-indigo-600" />
                          {item.name || item.code}
                        </span>
                      </TD>
                      <TD>
                        <Badge tone={active ? 'success' : 'neutral'}>
                          {active ? '已启用' : '未启用'}
                        </Badge>
                      </TD>
                      <TD>
                        <div className="text-[11px] text-slate-600">
                          来源：{item.credential_source || 'env'}
                          <div className="mt-0.5">
                            {item.credential_configured ? (
                              <Badge tone="success">已配置</Badge>
                            ) : (
                              <Badge tone="warning">未配置</Badge>
                            )}
                          </div>
                        </div>
                      </TD>
                      <TD className="max-w-[220px] truncate font-mono text-[10px] text-slate-500">
                        {item.callback_url || '—'}
                      </TD>
                      <TD className="font-mono text-[10px] text-slate-500">
                        {(item.required_env ?? []).join(' · ') || '—'}
                      </TD>
                      <TD className="text-[11px] text-slate-500">
                        {formatDateTime(item.updated_at)}
                      </TD>
                      <TD className="text-right">
                        <Button
                          size="xs"
                          variant="ghost"
                          disabled={
                            !item.credential_configured ||
                            !can('settings.auth.update') ||
                            !auth.data
                          }
                          onClick={() =>
                            setPending({ code: item.code ?? '', enable: !active })
                          }
                        >
                          {active ? '停用' : '启用'}
                        </Button>
                      </TD>
                    </TR>
                  )
                })}
              </TBody>
            </Table>
          </QueryBoundary>
        </CardContent>
      </Card>

      <ReasonDialog
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        onConfirm={(reason) => void update.mutateAsync({ reason })}
        title={pending?.enable ? '启用登录提供方' : '停用登录提供方'}
        description="变更会写入审计并推进 policy revision；未配置凭据的提供方无法启用。"
        confirmLabel="确认变更"
        busy={update.isPending}
      />
    </div>
  )
}
