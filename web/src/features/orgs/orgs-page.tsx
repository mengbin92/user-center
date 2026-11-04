import { Building2, Plus, Users } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Button } from '../../components/button'
import {
  Card,
  EmptyState,
  PageHeader,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
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
import { formatNumber } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Organization } from '../../lib/types'
import {
  OrganizationRoleBadge,
  OrganizationStatusBadge,
} from './org-shared'

const ORG_CODE_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/

export function OrganizationsPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const createOpen = searchParams.get('create') === '1'

  const orgsQuery = useQuery({
    queryKey: ['orgs', 'mine'],
    queryFn: () => api.orgs.listMine(),
    retry: false,
  })

  const [code, setCode] = useState('')
  const [name, setName] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const openCreate = () => {
    setFormError(null)
    setSearchParams({ create: '1' })
  }

  const closeCreate = () => {
    setFormError(null)
    const next = new URLSearchParams(searchParams)
    next.delete('create')
    setSearchParams(next, { replace: true })
  }

  const createOrg = useApiMutation({
    mutationFn: () =>
      api.orgs.create({ code: code.trim().toLowerCase(), name: name.trim() }),
    successMessage: '组织已创建',
    successDescription: '你已成为该组织的拥有者。',
    invalidate: [['orgs', 'mine']],
    onSuccess: (org: Organization) => {
      setCode('')
      setName('')
      setFormError(null)
      closeCreate()
      if (org.id) navigate(`/orgs/${org.id}`)
    },
    onError: (error) => setFormError(error.message),
  })

  const submitCreate = () => {
    const nextCode = code.trim().toLowerCase()
    const nextName = name.trim()
    if (!ORG_CODE_PATTERN.test(nextCode)) {
      setFormError('组织 code 必须为 2-64 位小写字母、数字或短横线')
      return
    }
    if (!nextName || nextName.length > 128) {
      setFormError('组织名称必须为 1-128 个字符')
      return
    }
    setFormError(null)
    createOrg.mutate(undefined)
  }

  const items = orgsQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="组织" />
      <PageHeader
        eyebrow="Organization"
        title="我的组织"
        description="查看你所在的组织、组织角色与成员规模。组织角色独立于平台 IAM 角色。"
        actions={
          <Button
            size="sm"
            variant="primary"
            onClick={openCreate}
            icon={<Plus className="h-3.5 w-3.5" />}
          >
            创建组织
          </Button>
        }
      />

      <Card>
        <QueryBoundary query={orgsQuery} loadingLabel="读取组织列表…">
          {items.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="还没有加入任何组织"
              description="创建一个组织后会默认成为拥有者，也可以等待组织管理员邀请你加入。"
              action={
                <Button
                  size="sm"
                  variant="primary"
                  onClick={openCreate}
                  icon={<Plus className="h-3.5 w-3.5" />}
                >
                  创建组织
                </Button>
              }
            />
          ) : (
            <Table minWidth="min-w-[760px]">
              <THead>
                <TR>
                  <TH>组织</TH>
                  <TH>我的角色</TH>
                  <TH>状态</TH>
                  <TH>成员数</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((org) => (
                  <TR
                    key={org.id}
                    onClick={() => navigate(`/orgs/${org.id}`)}
                  >
                    <TD>
                      <div className="flex items-center gap-2">
                        <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-indigo-50 text-indigo-600">
                          <Building2 className="h-3.5 w-3.5" />
                        </span>
                        <div className="min-w-0">
                          <div className="max-w-[220px] truncate text-xs font-medium text-slate-800">
                            {org.name || org.code}
                          </div>
                          <div className="font-mono text-[10px] text-slate-400">
                            {org.code} · id={org.id}
                          </div>
                        </div>
                      </div>
                    </TD>
                    <TD>
                      <OrganizationRoleBadge role={org.role} />
                    </TD>
                    <TD>
                      <OrganizationStatusBadge status={org.status} />
                    </TD>
                    <TD>
                      <span className="inline-flex items-center gap-1 text-xs text-slate-700">
                        <Users className="h-3.5 w-3.5 text-slate-400" />
                        {formatNumber(org.member_count)}
                      </span>
                    </TD>
                    <TD className="font-mono text-[11px] text-slate-500">
                      {org.revision}
                    </TD>
                    <TD className="text-right">
                      <span className="text-[11px] font-medium text-indigo-700">
                        进入
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={createOpen}
        onClose={closeCreate}
        title="创建组织"
        description="创建后你将成为组织拥有者，可添加成员、部门并管理设置。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={closeCreate}
              disabled={createOrg.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitCreate}
              loading={createOrg.isPending}
            >
              创建组织
            </Button>
          </>
        }
      >
        <Field
          label="组织 code"
          htmlFor="org-create-code"
          required
          hint="全局唯一，2-64 位小写字母、数字或短横线，例如 acme-lab。"
        >
          <Input
            id="org-create-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="acme-lab"
            autoComplete="off"
          />
        </Field>
        <Field
          label="组织名称"
          htmlFor="org-create-name"
          required
          hint="1-128 个字符，可在创建后修改。"
        >
          <Input
            id="org-create-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="例如：Acme 实验室"
          />
        </Field>
        {formError ? (
          <div className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
            {formError}
          </div>
        ) : null}
      </Dialog>
    </div>
  )
}
