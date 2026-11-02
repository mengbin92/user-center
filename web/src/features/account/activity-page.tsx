import { Activity, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import { Card, CardHeader, EmptyState } from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import {
  Pagination,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'

const KIND_LABELS: Record<string, string> = {
  login: '登录',
  login_success: '登录成功',
  login_failure: '登录失败',
  logout: '退出登录',
  mfa_enable: '启用 MFA',
  mfa_disable: '关闭 MFA',
  mfa_recovery_rotate: '轮换恢复码',
  step_up: '安全验证',
  session_revoke: '撤销会话',
  password_change: '修改密码',
  email_change: '变更邮箱',
}

export function ActivityPage() {
  const [tokens, setTokens] = useState<string[]>([''])
  const pageToken = tokens[tokens.length - 1] ?? ''

  const eventsQuery = useQuery({
    queryKey: ['me', 'security-events', pageToken],
    queryFn: () =>
      api.me.securityEvents({ page_size: 20, page_token: pageToken || undefined }),
    retry: false,
  })

  const items = eventsQuery.data?.items ?? []
  const nextToken = eventsQuery.data?.meta?.next_page_token

  const goNext = () => {
    if (!nextToken) return
    setTokens((current) => [...current, nextToken])
  }

  const goPrev = () => {
    setTokens((current) => (current.length > 1 ? current.slice(0, -1) : current))
  }

  return (
    <div className="space-y-4">
      <PageTitle title="登录记录" />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            安全事件
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            最近 20 条登录、MFA、会话与敏感操作记录。IP 与设备信息已脱敏。
          </p>
        </div>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => void eventsQuery.refetch()}
          loading={eventsQuery.isFetching}
          icon={<RefreshCw className="h-3.5 w-3.5" />}
        >
          刷新
        </Button>
      </div>

      <Card>
        <CardHeader
          title="安全事件"
          description="事件由服务端安全审计写入，只读。"
          actions={<Badge tone="info">{items.length} 条</Badge>}
        />
        <QueryBoundary query={eventsQuery} loadingLabel="读取安全事件…">
          {items.length === 0 ? (
            <EmptyState
              title="暂无安全事件"
              description="登录、修改密码或启用 MFA 后，这里会出现记录。"
              icon={Activity}
            />
          ) : (
            <>
              <Table minWidth="min-w-[820px]">
                <THead>
                  <TR>
                    <TH>事件</TH>
                    <TH>结果</TH>
                    <TH>来源 IP</TH>
                    <TH>设备摘要</TH>
                    <TH>请求 ID</TH>
                    <TH>时间</TH>
                  </TR>
                </THead>
                <TBody>
                  {items.map((event) => (
                    <TR key={event.id}>
                      <TD>
                        <div className="text-xs font-medium text-slate-800">
                          {KIND_LABELS[event.kind ?? ''] ?? event.kind ?? '未知事件'}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {event.kind}
                        </div>
                      </TD>
                      <TD>
                        <StatusBadge status={event.result} />
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-600">
                        {event.ip_masked || '—'}
                      </TD>
                      <TD className="max-w-[220px] truncate text-[11px] text-slate-500">
                        {event.user_agent_summary || '—'}
                      </TD>
                      <TD className="max-w-[150px] truncate font-mono text-[10px] text-slate-400">
                        {event.request_id || '—'}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(event.occurred_at)}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                total={eventsQuery.data?.meta?.total_size ?? items.length}
                pageIndex={tokens.length}
                hasNext={Boolean(nextToken)}
                onPrev={goPrev}
                onNext={goNext}
                loading={eventsQuery.isFetching}
              />
            </>
          )}
        </QueryBoundary>
      </Card>
    </div>
  )
}
