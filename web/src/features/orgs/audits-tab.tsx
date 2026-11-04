import { Download, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Button } from '../../components/button'
import {
  Card,
  CardHeader,
  EmptyState,
  InlineAlert,
} from '../../components/card'
import { Field, Input } from '../../components/input'
import { ReasonDialog } from '../../components/reason-dialog'
import { QueryBoundary } from '../../components/query-state'
import {
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { saveBlob } from '../../lib/download'
import { formatDateTime, formatNumber } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'

export function OrganizationAuditsTab({
  orgId,
  active,
}: {
  orgId: string
  active: boolean
}) {
  const [action, setAction] = useState('')
  const [applied, setApplied] = useState('')
  const [exportOpen, setExportOpen] = useState(false)

  const auditsQuery = useQuery({
    queryKey: ['orgs', orgId, 'audits', applied],
    queryFn: () =>
      api.orgs.listAudits(orgId, {
        action: applied || undefined,
        page_size: 50,
      }),
    retry: false,
    enabled: active,
  })

  const exportAudits = useApiMutation({
    mutationFn: async (reason: string) => {
      const job = await api.orgs.exportAudits(orgId, {
        id: orgId,
        action: applied || undefined,
        reason,
        fields: [
          'event_id', 'occurred_at', 'actor_user_id', 'action',
          'target', 'result', 'reason', 'request_id',
        ],
      })
      const { blob, filename } = await api.orgs.downloadAuditExport(
        orgId,
        job.id ?? '',
      )
      saveBlob(blob, filename ?? `org-${orgId}-audits.csv`)
    },
    successMessage: '租户审计已导出',
    onSuccess: () => setExportOpen(false),
  })

  const items = auditsQuery.data?.items ?? []
  const total = Number(auditsQuery.data?.total ?? 0)

  return (
    <div className="space-y-4">
      <InlineAlert tone="info" title="租户审计">
        这里只显示本组织的审计事件；平台级事件与其他组织的事件不会出现在此视图中。
      </InlineAlert>

      <Card>
        <CardHeader
          title="组织审计"
          description={`共 ${formatNumber(total)} 条事件`}
          actions={
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => auditsQuery.refetch()}
                loading={auditsQuery.isFetching}
              >
                <RefreshCw className="h-3.5 w-3.5" />
                刷新
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={!active}
                onClick={() => setExportOpen(true)}
              >
                <Download className="h-3.5 w-3.5" />
                导出本组织审计
              </Button>
            </div>
          }
        />
        <div className="border-b border-slate-100 px-4 py-3">
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault()
              setApplied(action.trim())
            }}
          >
            <div className="w-64">
              <Field label="动作筛选">
                <Input
                  value={action}
                  onChange={(event) => setAction(event.target.value)}
                  placeholder="organization.member.add"
                />
              </Field>
            </div>
            <Button size="sm" type="submit" variant="secondary">
              筛选
            </Button>
            {applied ? (
              <Button
                size="sm"
                variant="ghost"
                type="button"
                onClick={() => {
                  setAction('')
                  setApplied('')
                }}
              >
                清除
              </Button>
            ) : null}
          </form>
        </div>
        <QueryBoundary query={auditsQuery} loadingLabel="读取组织审计…">
          {items.length === 0 ? (
            <EmptyState title="没有匹配的审计事件" />
          ) : (
            <Table minWidth="min-w-[720px]">
              <THead>
                <TR>
                  <TH>时间</TH>
                  <TH>动作</TH>
                  <TH>操作者</TH>
                  <TH>对象</TH>
                  <TH>原因</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((event) => (
                  <TR key={event.event_id}>
                    <TD className="whitespace-nowrap text-[12px] text-slate-500">
                      {formatDateTime(event.occurred_at)}
                    </TD>
                    <TD className="font-mono text-[11px]">{event.action}</TD>
                    <TD className="font-mono text-[11px]">
                      {event.actor_user_id}
                    </TD>
                    <TD className="font-mono text-[11px]">{event.target}</TD>
                    <TD className="text-[12px] text-slate-500">
                      {event.reason || '—'}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <ReasonDialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        onConfirm={(reason) => void exportAudits.mutateAsync(reason)}
        title="导出本组织审计"
        description="导出内容严格限定当前组织，沿用平台导出的 CSV 字段与下载校验。"
        confirmLabel="生成并下载"
        busy={exportAudits.isPending}
      />
    </div>
  )
}
