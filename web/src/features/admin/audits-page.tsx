import {
  ClipboardList,
  Download,
  RefreshCw,
  Search,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
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
import { useAuth } from '../../lib/auth'
import { formatDateTime, prettyJson, toRfc3339 } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import { InfoGrid } from './common'

const EXPORT_FIELDS = [
  { key: 'event_id', label: '事件 ID' },
  { key: 'occurred_at', label: '时间' },
  { key: 'actor_user_id', label: '操作者' },
  { key: 'actor_session_id', label: '会话 ID' },
  { key: 'action', label: '操作' },
  { key: 'target', label: '目标' },
  { key: 'result', label: '结果' },
  { key: 'reason', label: '原因' },
  { key: 'request_id', label: '请求 ID' },
  { key: 'before', label: 'before' },
  { key: 'after', label: 'after' },
  { key: 'diff', label: 'diff' },
]

export function AdminAuditsPage() {
  const navigate = useNavigate()
  const { can } = useAuth()
  const [action, setAction] = useState('')
  const [actorId, setActorId] = useState('')
  const [target, setTarget] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [tokens, setTokens] = useState<string[]>([''])
  const [detailId, setDetailId] = useState<string | null>(null)
  const [exportOpen, setExportOpen] = useState(false)
  const [exportFields, setExportFields] = useState<Set<string>>(
    new Set([
      'event_id',
      'occurred_at',
      'actor_user_id',
      'action',
      'target',
      'result',
      'reason',
      'request_id',
    ]),
  )

  const pageToken = tokens[tokens.length - 1] ?? ''

  const auditsQuery = useQuery({
    queryKey: [
      'admin',
      'audits',
      { action, actorId, target, from, to, pageToken },
    ],
    queryFn: () =>
      api.audits.list({
        action: action || undefined,
        actor_user_id: actorId || undefined,
        target: target || undefined,
        from: toRfc3339(from),
        to: toRfc3339(to),
        page_size: 20,
        page_token: pageToken || undefined,
      }),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const detailQuery = useQuery({
    queryKey: ['admin', 'audit', detailId],
    queryFn: () => api.audits.get(detailId ?? ''),
    enabled: Boolean(detailId),
    retry: false,
  })

  const exportAudits = useApiMutation({
    mutationFn: (reason: string) =>
      api.audits.export({
        action: action || undefined,
        actor_user_id: actorId || undefined,
        target: target || undefined,
        from: toRfc3339(from),
        to: toRfc3339(to),
        fields: [...exportFields],
        reason,
      }),
    successMessage: '审计导出任务已创建',
    successDescription: '前往导出任务列表下载 CSV。',
    onSuccess: (job) => {
      setExportOpen(false)
      navigate(`/admin/exports?highlight=${job.id ?? ''}`)
    },
  })

  const submitFilters = (event: FormEvent) => {
    event.preventDefault()
    setTokens([''])
  }

  const resetFilters = () => {
    setAction('')
    setActorId('')
    setTarget('')
    setFrom('')
    setTo('')
    setTokens([''])
  }

  const toggleField = (key: string) => {
    setExportFields((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const items = auditsQuery.data?.items ?? []
  const nextToken = auditsQuery.data?.meta?.next_page_token

  return (
    <div className="space-y-4">
      <PageTitle title="审计日志" />
      <PageHeader
        eyebrow="Audit"
        title="审计日志"
        description="不可变的授权与安全审计轨迹。before/after/diff 为 JSON 快照。"
        actions={
          can('audit.export') ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setExportOpen(true)}
              icon={<Download className="h-3.5 w-3.5" />}
            >
              导出审计
            </Button>
          ) : undefined
        }
      />

      <Card className="p-3">
        <form className="flex flex-wrap items-end gap-2" onSubmit={submitFilters}>
          <Field label="操作" htmlFor="audit-action" className="w-44">
            <Input
              id="audit-action"
              value={action}
              onChange={(event) => setAction(event.target.value)}
              placeholder="identity.user.archive"
              className="font-mono text-[11px]"
            />
          </Field>
          <Field label="操作者 ID" htmlFor="audit-actor" className="w-32">
            <Input
              id="audit-actor"
              value={actorId}
              onChange={(event) => setActorId(event.target.value)}
              inputMode="numeric"
              className="font-mono"
            />
          </Field>
          <Field label="目标" htmlFor="audit-target" className="w-36">
            <Input
              id="audit-target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              className="font-mono"
            />
          </Field>
          <Field label="开始时间" htmlFor="audit-from" className="w-44">
            <Input
              id="audit-from"
              type="datetime-local"
              value={from}
              onChange={(event) => setFrom(event.target.value)}
            />
          </Field>
          <Field label="结束时间" htmlFor="audit-to" className="w-44">
            <Input
              id="audit-to"
              type="datetime-local"
              value={to}
              onChange={(event) => setTo(event.target.value)}
            />
          </Field>
          <Button type="submit" size="sm" variant="primary" icon={<Search className="h-3.5 w-3.5" />}>
            筛选
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={resetFilters}>
            重置
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={() => void auditsQuery.refetch()}
            aria-label="刷新"
            title="刷新"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </form>
      </Card>

      <Card>
        <QueryBoundary query={auditsQuery} loadingLabel="读取审计日志…">
          {items.length === 0 ? (
            <EmptyState
              title="没有匹配的审计事件"
              description="调整筛选条件或时间范围。"
              icon={ClipboardList}
            />
          ) : (
            <>
              <Table minWidth="min-w-[980px]">
                <THead>
                  <TR>
                    <TH>时间</TH>
                    <TH>操作</TH>
                    <TH>操作者</TH>
                    <TH>目标</TH>
                    <TH>结果</TH>
                    <TH>原因</TH>
                    <TH>请求 ID</TH>
                    <TH className="text-right">详情</TH>
                  </TR>
                </THead>
                <TBody>
                  {items.map((event) => (
                    <TR key={event.id} onClick={() => setDetailId(event.id ?? null)}>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(event.occurred_at)}
                      </TD>
                      <TD className="font-mono text-[11px] font-medium text-slate-800">
                        {event.action}
                      </TD>
                      <TD className="text-[11px] text-slate-600">
                        {event.actor_user_id || event.actor_service_id || '—'}
                      </TD>
                      <TD className="max-w-[160px] truncate font-mono text-[11px] text-slate-600">
                        {event.target || '—'}
                      </TD>
                      <TD>
                        <StatusBadge status={event.result} />
                      </TD>
                      <TD className="max-w-[220px] truncate text-[11px] text-slate-500">
                        {event.reason || '—'}
                      </TD>
                      <TD className="max-w-[130px] truncate font-mono text-[10px] text-slate-400">
                        {event.request_id || '—'}
                      </TD>
                      <TD className="text-right">
                        <Button
                          size="xs"
                          variant="ghost"
                          onClick={(clickEvent) => {
                            clickEvent.stopPropagation()
                            setDetailId(event.id ?? null)
                          }}
                        >
                          查看
                        </Button>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                total={auditsQuery.data?.meta?.total_size}
                pageIndex={tokens.length}
                hasNext={Boolean(nextToken)}
                onPrev={() =>
                  setTokens((current) =>
                    current.length > 1 ? current.slice(0, -1) : current,
                  )
                }
                onNext={() => {
                  if (nextToken) setTokens((current) => [...current, nextToken])
                }}
                onRefresh={() => void auditsQuery.refetch()}
                loading={auditsQuery.isFetching}
              />
            </>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        title="审计事件详情"
        description={detailQuery.data?.action}
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <Button variant="secondary" size="sm" onClick={() => setDetailId(null)}>
            关闭
          </Button>
        }
      >
        {detailQuery.isPending ? (
          <div className="py-6 text-center text-xs text-slate-500">加载中…</div>
        ) : detailQuery.isError ? (
          <InlineAlert tone="danger">无法读取审计事件</InlineAlert>
        ) : detailQuery.data ? (
          <>
            <InfoGrid
              items={[
                { label: '事件 ID', value: detailQuery.data.id, mono: true },
                { label: '操作', value: detailQuery.data.action, mono: true },
                {
                  label: '结果',
                  value: <StatusBadge status={detailQuery.data.result} />,
                },
                {
                  label: '操作者用户',
                  value: detailQuery.data.actor_user_id || '—',
                  mono: true,
                },
                {
                  label: '操作者服务',
                  value: detailQuery.data.actor_service_id || '—',
                  mono: true,
                },
                {
                  label: '会话',
                  value: detailQuery.data.actor_session_id || '—',
                  mono: true,
                },
                {
                  label: '目标',
                  value: detailQuery.data.target || '—',
                  mono: true,
                },
                {
                  label: '时间',
                  value: formatDateTime(detailQuery.data.occurred_at),
                },
                {
                  label: '请求 ID',
                  value: detailQuery.data.request_id || '—',
                  mono: true,
                },
                {
                  label: '授权版本',
                  value: detailQuery.data.authorization_versions || '—',
                  mono: true,
                },
              ]}
            />
            <div>
              <div className="mb-1 text-[11px] font-medium text-slate-600">原因</div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-700">
                {detailQuery.data.reason || '—'}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-[11px] font-medium text-slate-600">diff</div>
              <pre className="max-h-56 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-[10.5px] leading-5 text-slate-100">
                {prettyJson(detailQuery.data.diff)}
              </pre>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <div>
                <div className="mb-1 text-[11px] font-medium text-slate-600">
                  before
                </div>
                <pre className="max-h-40 overflow-auto rounded-md bg-slate-100 p-2 font-mono text-[10.5px] text-slate-700">
                  {prettyJson(detailQuery.data.before)}
                </pre>
              </div>
              <div>
                <div className="mb-1 text-[11px] font-medium text-slate-600">
                  after
                </div>
                <pre className="max-h-40 overflow-auto rounded-md bg-slate-100 p-2 font-mono text-[10.5px] text-slate-700">
                  {prettyJson(detailQuery.data.after)}
                </pre>
              </div>
            </div>
          </>
        ) : null}
      </Dialog>

      <ReasonDialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        onConfirm={(reason) => {
          if (exportFields.size > 0) exportAudits.mutate(reason)
        }}
        title="导出审计 CSV"
        description="按操作、操作者、目标与时间筛选导出，产物 24 小时内可下载。"
        confirmLabel="创建导出任务"
        busy={exportAudits.isPending}
      >
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <div className="text-xs font-medium text-slate-700">导出字段</div>
            <Badge tone="outline">{exportFields.size} 个字段</Badge>
          </div>
          <div className="grid max-h-52 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {EXPORT_FIELDS.map((field) => (
              <label
                key={field.key}
                className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                  checked={exportFields.has(field.key)}
                  onChange={() => toggleField(field.key)}
                />
                <span className="text-slate-700">{field.label}</span>
                <span className="font-mono text-[9px] text-slate-400">
                  {field.key}
                </span>
              </label>
            ))}
          </div>
        </div>
      </ReasonDialog>
    </div>
  )
}
