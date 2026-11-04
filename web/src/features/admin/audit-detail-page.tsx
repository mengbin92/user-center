import { ArrowLeft, ClipboardList } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useLocation, useNavigate, useParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  EmptyState,
} from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { api } from '../../lib/api'
import { formatDateTime, prettyJson } from '../../lib/format'
import { InfoGrid } from './common'

function JsonBlock({ label, raw }: { label: string; raw?: string | null }) {
  const text = prettyJson(raw)
  const empty = !raw || text === '{}' || text === '—'
  return (
    <details className="rounded-md border border-slate-200 bg-white" open={label === 'diff' && !empty}>
      <summary className="cursor-pointer px-3 py-2 text-[11px] font-medium text-slate-600">
        {label}
        {empty ? <span className="ml-2 font-normal text-slate-400">（空）</span> : null}
      </summary>
      <div className="border-t border-slate-100 px-3 py-2">
        {empty ? (
          <p className="text-xs text-slate-400">该事件没有记录此字段。</p>
        ) : (
          <pre className="max-h-72 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-[10.5px] leading-5 text-slate-100">
            {text}
          </pre>
        )}
      </div>
    </details>
  )
}

export function AdminAuditDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const backState = location.state as { auditFilters?: unknown } | null

  const query = useQuery({
    queryKey: ['admin', 'audit', 'page', id],
    queryFn: () => api.audits.get(id),
    enabled: Boolean(id),
    retry: false,
  })

  const goBack = () =>
    navigate('/admin/audits', {
      state: backState?.auditFilters ? { auditFilters: backState.auditFilters } : undefined,
    })

  return (
    <div className="space-y-4">
      <PageTitle title="审计事件详情" />
      <div>
        <Button size="xs" variant="ghost" onClick={goBack}>
          <ArrowLeft className="h-3.5 w-3.5" />
          返回审计列表
        </Button>
      </div>

      <QueryBoundary query={query} loadingLabel="读取审计事件…">
        {query.data ? (
          <>
            <Card>
              <CardHeader
                title={query.data.action || '审计事件'}
                description="单条事件的完整上下文，包含操作者、结果、原因、请求 ID 与版本信息。"
                actions={<StatusBadge status={query.data.result} />}
              />
              <CardContent>
                <InfoGrid
                  items={[
                    { label: '事件 ID', value: query.data.id || '—', mono: true },
                    { label: '操作', value: query.data.action || '—', mono: true },
                    { label: '操作者用户', value: query.data.actor_user_id || '—', mono: true },
                    { label: '操作者服务', value: query.data.actor_service_id || '—', mono: true },
                    { label: '会话', value: query.data.actor_session_id || '—', mono: true },
                    { label: '目标', value: query.data.target || '—', mono: true },
                    { label: '结果', value: query.data.result || '—' },
                    { label: '时间', value: formatDateTime(query.data.occurred_at) },
                    { label: '请求 ID', value: query.data.request_id || '—', mono: true },
                    {
                      label: '授权版本',
                      value: query.data.authorization_versions || '—',
                      mono: true,
                    },
                  ]}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="原因" description="管理端写入时留痕的业务原因。" />
              <CardContent>
                <p className="text-xs text-slate-700">{query.data.reason || '—'}</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader
                title="变更快照"
                description="长 JSON 可折叠；diff 为空时给出降级提示。"
              />
              <CardContent className="space-y-2">
                <JsonBlock label="diff" raw={query.data.diff} />
                <JsonBlock label="before" raw={query.data.before} />
                <JsonBlock label="after" raw={query.data.after} />
              </CardContent>
            </Card>
          </>
        ) : (
          <Card>
            <EmptyState icon={ClipboardList} title="事件不存在或无权查看" description="请返回列表重新选择。" />
          </Card>
        )}
      </QueryBoundary>
    </div>
  )
}
