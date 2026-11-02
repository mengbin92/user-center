import {
  Download,
  FileClock,
  RefreshCw,
} from 'lucide-react'
import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  EmptyState,
  PageHeader,
} from '../../components/card'
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
import { useToast } from '../../components/toast'
import { api } from '../../lib/api'
import { saveBlob } from '../../lib/download'
import { formatDateTime, formatNumber } from '../../lib/format'
import type { ExportJob } from '../../lib/types'

export function AdminExportsPage() {
  const toast = useToast()
  const [searchParams] = useSearchParams()
  const highlight = searchParams.get('highlight') ?? ''
  const [tokens, setTokens] = useState<string[]>([''])
  const [downloading, setDownloading] = useState<string | null>(null)

  const pageToken = tokens[tokens.length - 1] ?? ''

  const exportsQuery = useQuery({
    queryKey: ['admin', 'exports', pageToken],
    queryFn: () =>
      api.admin.listExports({
        page_size: 20,
        page_token: pageToken || undefined,
      }),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const items = exportsQuery.data?.items ?? []
  const nextToken = exportsQuery.data?.meta?.next_page_token

  const download = async (job: ExportJob) => {
    if (!job.id) return
    setDownloading(job.id)
    try {
      const { blob, filename } = await api.admin.downloadExport(job.id)
      saveBlob(
        blob,
        filename || job.artifact_name || `export-${job.id}.csv`,
      )
      toast.success('下载已开始', filename ?? job.artifact_name ?? undefined)
    } catch (error) {
      toast.error(
        '下载失败',
        error instanceof Error ? error.message : '导出文件可能已过期',
      )
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div className="space-y-4">
      <PageTitle title="导出任务" />
      <PageHeader
        eyebrow="Data"
        title="导出任务"
        description="用户与审计导出的异步产物。文件 24 小时内有效，过期后需重新创建。"
        actions={
          <Button
            size="sm"
            variant="secondary"
            onClick={() => void exportsQuery.refetch()}
            loading={exportsQuery.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
        }
      />

      <Card>
        <QueryBoundary query={exportsQuery} loadingLabel="读取导出任务…">
          {items.length === 0 ? (
            <EmptyState
              title="暂无导出任务"
              description="在用户管理或审计日志中创建导出。"
              icon={FileClock}
            />
          ) : (
            <>
              <Table minWidth="min-w-[940px]">
                <THead>
                  <TR>
                    <TH>任务</TH>
                    <TH>类型</TH>
                    <TH>状态</TH>
                    <TH>字段</TH>
                    <TH>产物</TH>
                    <TH>创建时间</TH>
                    <TH>过期时间</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {items.map((job) => {
                    const ready = job.status === 'ready'
                    return (
                      <TR
                        key={job.id}
                        className={
                          job.id === highlight ? 'bg-indigo-50/60' : undefined
                        }
                      >
                        <TD>
                          <div className="font-mono text-[11px] font-medium text-slate-800">
                            #{job.id}
                          </div>
                          {job.error ? (
                            <div className="max-w-[220px] truncate text-[10px] text-rose-600">
                              {job.error}
                            </div>
                          ) : null}
                        </TD>
                        <TD>
                          <Badge tone={job.kind === 'audits' ? 'info' : 'violet'}>
                            {job.kind === 'audits' ? '审计' : '用户'}
                          </Badge>
                        </TD>
                        <TD>
                          <StatusBadge status={job.status} />
                        </TD>
                        <TD className="max-w-[240px]">
                          <div className="flex flex-wrap gap-1">
                            {(job.requested_fields ?? '')
                              .split(',')
                              .filter(Boolean)
                              .slice(0, 6)
                              .map((field) => (
                                <Badge key={field} tone="outline">
                                  {field}
                                </Badge>
                              ))}
                          </div>
                        </TD>
                        <TD className="max-w-[160px] truncate font-mono text-[10px] text-slate-500">
                          {job.artifact_name || '—'}
                        </TD>
                        <TD className="whitespace-nowrap text-[11px] text-slate-500">
                          {formatDateTime(job.created_at)}
                        </TD>
                        <TD className="whitespace-nowrap text-[11px] text-slate-500">
                          {formatDateTime(job.expires_at)}
                        </TD>
                        <TD className="text-right">
                          <Button
                            size="xs"
                            variant={ready ? 'primary' : 'ghost'}
                            disabled={!ready}
                            loading={downloading === job.id}
                            onClick={() => void download(job)}
                            icon={<Download className="h-3 w-3" />}
                          >
                            下载
                          </Button>
                        </TD>
                      </TR>
                    )
                  })}
                </TBody>
              </Table>
              <Pagination
                total={exportsQuery.data?.meta?.total_size ?? items.length}
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
                onRefresh={() => void exportsQuery.refetch()}
                loading={exportsQuery.isFetching}
              />
            </>
          )}
        </QueryBoundary>
      </Card>

      <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500">
        <span>
          当前页 <span className="tabular-nums">{formatNumber(items.length)}</span> 个任务
        </span>
        <span>下载请求使用 HttpOnly Cookie 鉴权，并校验任务归属与有效期。</span>
      </div>
    </div>
  )
}
