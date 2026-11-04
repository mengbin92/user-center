import { Archive, Building2, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Button } from '../../components/button'
import {
  Card,
  EmptyState,
  PageHeader,
} from '../../components/card'
import { Field, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import {
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime, formatNumber } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Organization } from '../../lib/types'
import {
  OrganizationRoleBadge,
  OrganizationStatusBadge,
} from '../orgs/org-shared'

export function AdminOrganizationsPage() {
  const [status, setStatus] = useState('')
  const [archiveTarget, setArchiveTarget] = useState<Organization | null>(null)

  const orgsQuery = useQuery({
    queryKey: ['admin', 'organizations', { status }],
    queryFn: () =>
      api.admin.listOrganizations({ status: status || undefined }),
    retry: false,
  })

  const archiveOrg = useApiMutation({
    mutationFn: (reason: string) => {
      const target = archiveTarget
      if (!target?.id) throw new Error('未选择组织')
      return api.admin.archiveOrganization(target.id, {
        id: target.id,
        expected_revision: target.revision ?? '0',
        reason,
      })
    },
    successMessage: '组织已归档',
    invalidate: [
      ['admin', 'organizations'],
      ['orgs', 'mine'],
    ],
    onSuccess: () => setArchiveTarget(null),
  })

  const items = orgsQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="组织管理" />
      <PageHeader
        eyebrow="Platform administration"
        title="组织管理"
        description="平台管理员可查看全部组织并按状态筛选。归档需要原因与当前 revision，会写入审计日志。"
      />

      <Card className="p-3">
        <div className="flex flex-wrap items-end gap-2">
          <Field label="组织状态" htmlFor="admin-org-status" className="w-40">
            <Select
              id="admin-org-status"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              <option value="">全部状态</option>
              <option value="active">运行中</option>
              <option value="archived">已归档</option>
            </Select>
          </Field>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => void orgsQuery.refetch()}
            loading={orgsQuery.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
          <span className="ml-auto text-[11px] text-slate-500">
            共 {formatNumber(items.length)} 个组织
          </span>
        </div>
      </Card>

      <Card>
        <QueryBoundary query={orgsQuery} loadingLabel="读取组织目录…">
          {items.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="没有匹配的组织"
              description="调整状态筛选，或确认组织是否已经创建。"
            />
          ) : (
            <Table minWidth="min-w-[980px]">
              <THead>
                <TR>
                  <TH>组织</TH>
                  <TH>状态</TH>
                  <TH>角色</TH>
                  <TH>成员数</TH>
                  <TH>revision</TH>
                  <TH>创建时间</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((org) => (
                  <TR key={org.id}>
                    <TD>
                      <div className="flex items-center gap-2">
                        <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-slate-100 text-slate-500">
                          <Building2 className="h-3.5 w-3.5" />
                        </span>
                        <div className="min-w-0">
                          <div className="max-w-[240px] truncate text-xs font-medium text-slate-800">
                            {org.name || org.code}
                          </div>
                          <div className="font-mono text-[10px] text-slate-400">
                            {org.code} · id={org.id}
                          </div>
                        </div>
                      </div>
                    </TD>
                    <TD>
                      <OrganizationStatusBadge status={org.status} />
                    </TD>
                    <TD>
                      <OrganizationRoleBadge role={org.role} />
                    </TD>
                    <TD className="text-xs tabular-nums text-slate-700">
                      {formatNumber(org.member_count)}
                    </TD>
                    <TD className="font-mono text-[11px] text-slate-500">
                      {org.revision}
                    </TD>
                    <TD className="whitespace-nowrap text-[11px] text-slate-500">
                      {formatDateTime(org.created_at)}
                    </TD>
                    <TD className="text-right">
                      {org.status === 'archived' ? (
                        <span className="text-[10px] text-slate-400">
                          已归档
                        </span>
                      ) : (
                        <Button
                          size="xs"
                          variant="danger"
                          onClick={() => setArchiveTarget(org)}
                          icon={<Archive className="h-3 w-3" />}
                        >
                          归档
                        </Button>
                      )}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <ReasonDialog
        open={archiveTarget !== null}
        onClose={() => setArchiveTarget(null)}
        onConfirm={(reason) => archiveOrg.mutate(reason)}
        title={`归档组织「${archiveTarget?.name || archiveTarget?.code || ''}」`}
        description={`将使用 revision ${archiveTarget?.revision ?? '—'} 做并发校验。归档后该组织成员与部门变更会被冻结。`}
        confirmLabel="确认归档"
        tone="danger"
        busy={archiveOrg.isPending}
        hint="归档原因会写入不可篡改的审计日志，至少 2 个字符。"
      />
    </div>
  )
}
