import { Plus, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router'

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
import { Field, Input, Select, Textarea } from '../../components/input'
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
import { useAuth } from '../../lib/auth'
import { useApiMutation } from '../../lib/mutations'

export function AdminRolesPage() {
  const navigate = useNavigate()
  const { can, authorization } = useAuth()
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [status, setStatus] = useState('')

  const rolesQuery = useQuery({
    queryKey: ['admin', 'iam', 'roles', { keyword, status }],
    queryFn: () =>
      api.iam.listRoles({
        keyword: keyword || undefined,
        status: status || undefined,
      }),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const [createOpen, setCreateOpen] = useState(false)
  const [code, setCode] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [maxMembers, setMaxMembers] = useState('')
  const [reason, setReason] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const createRole = useApiMutation({
    mutationFn: () =>
      api.iam.createRole({
        code: code.trim(),
        name: name.trim(),
        description: description.trim() || undefined,
        max_members: maxMembers.trim() || undefined,
        grants: [],
        inherits: [],
        reason: reason.trim(),
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '角色已创建',
    invalidate: [['admin', 'iam', 'roles']],
    refreshAuth: true,
    onSuccess: (role) => {
      setCreateOpen(false)
      setCode('')
      setName('')
      setDescription('')
      setMaxMembers('')
      setReason('')
      if (role.id) navigate(`/admin/iam/roles/${role.id}`)
    },
  })

  const submitCreate = (event?: FormEvent) => {
    event?.preventDefault()
    setFormError(null)
    if (!code.trim() || !name.trim()) {
      setFormError('角色代码与名称不能为空')
      return
    }
    if (reason.trim().length < 2) {
      setFormError('请填写创建原因（至少 2 个字符）')
      return
    }
    createRole.mutate(undefined)
  }

  const roles = rolesQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="角色管理" />
      <PageHeader
        eyebrow="IAM"
        title="角色管理"
        description="角色聚合授权 grants，可继承其他角色，并受职责分离约束。"
        actions={
          <>
            {can('iam.role.create') ? (
              <Button
                size="sm"
                variant="primary"
                onClick={() => {
                  setFormError(null)
                  setCreateOpen(true)
                }}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                创建角色
              </Button>
            ) : null}
          </>
        }
      />

      <Card className="p-3">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            setKeyword(keywordInput.trim())
          }}
        >
          <div className="min-w-[220px] flex-1">
            <Field label="搜索角色" htmlFor="role-keyword">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                <Input
                  id="role-keyword"
                  value={keywordInput}
                  onChange={(event) => setKeywordInput(event.target.value)}
                  placeholder="角色代码或名称"
                  className="pl-8"
                />
              </div>
            </Field>
          </div>
          <Field label="状态" htmlFor="role-status" className="w-32">
            <Select
              id="role-status"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              <option value="">全部</option>
              <option value="active">启用中</option>
              <option value="disabled">已停用</option>
              <option value="archived">已归档</option>
            </Select>
          </Field>
          <Button type="submit" size="sm" variant="primary">
            搜索
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            aria-label="刷新"
            onClick={() => void rolesQuery.refetch()}
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </form>
      </Card>

      <Card>
        <QueryBoundary query={rolesQuery} loadingLabel="读取角色…">
          {roles.length === 0 ? (
            <EmptyState
              title="没有匹配的角色"
              description="调整筛选条件，或创建一个新角色。"
              icon={ShieldCheck}
            />
          ) : (
            <Table minWidth="min-w-[860px]">
              <THead>
                <TR>
                  <TH>角色</TH>
                  <TH>状态</TH>
                  <TH>类型</TH>
                  <TH>grants</TH>
                  <TH>继承</TH>
                  <TH>成员上限</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {roles.map((role) => (
                  <TR key={role.id}>
                    <TD>
                      <div className="text-xs font-medium text-slate-800">
                        {role.name}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">
                        {role.code} · id={role.id}
                      </div>
                      {role.description ? (
                        <div className="mt-0.5 max-w-[280px] truncate text-[10px] text-slate-500">
                          {role.description}
                        </div>
                      ) : null}
                    </TD>
                    <TD>
                      <StatusBadge status={role.status} />
                    </TD>
                    <TD>
                      {role.builtin ? (
                        <Badge tone="violet">内置</Badge>
                      ) : (
                        <Badge tone="outline">自定义</Badge>
                      )}
                    </TD>
                    <TD className="tabular-nums text-xs text-slate-700">
                      {role.grants?.length ?? 0}
                    </TD>
                    <TD className="tabular-nums text-xs text-slate-700">
                      {role.inherits?.length ?? 0}
                    </TD>
                    <TD className="text-xs text-slate-600">
                      {role.max_members || '不限'}
                    </TD>
                    <TD className="font-mono text-[11px] text-slate-500">
                      {role.revision}
                    </TD>
                    <TD className="text-right">
                      <Link
                        to={`/admin/iam/roles/${role.id}`}
                        className="text-[11px] font-medium text-indigo-700 hover:underline"
                      >
                        管理
                      </Link>
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
        onClose={() => setCreateOpen(false)}
        title="创建角色"
        description="新角色默认没有 grants，可在详情页配置。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createRole.isPending}
            >
              取消
            </Button>
            <Button
              type="submit"
              form="create-role-form"
              variant="primary"
              size="sm"
              loading={createRole.isPending}
            >
              创建
            </Button>
          </>
        }
      >
        <form id="create-role-form" className="space-y-3" onSubmit={submitCreate}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="角色代码" htmlFor="role-code" required hint="创建后不可修改">
              <Input
                id="role-code"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="例如 auditor"
                className="font-mono"
              />
            </Field>
            <Field label="角色名称" htmlFor="role-name" required>
              <Input
                id="role-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="例如 审计员"
              />
            </Field>
          </div>
          <Field label="描述" htmlFor="role-description">
            <Input
              id="role-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="角色用途说明"
            />
          </Field>
          <Field
            label="成员上限"
            htmlFor="role-max-members"
            hint="留空表示不限制，十进制数字字符串"
          >
            <Input
              id="role-max-members"
              value={maxMembers}
              onChange={(event) => setMaxMembers(event.target.value)}
              inputMode="numeric"
              placeholder="例如 50"
            />
          </Field>
          <Field
            label="创建原因"
            htmlFor="role-create-reason"
            required
            hint="写入审计日志，至少 2 个字符"
          >
            <Textarea
              id="role-create-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={2}
            />
          </Field>
          {formError ? (
            <InlineAlert tone="danger">{formError}</InlineAlert>
          ) : null}
        </form>
      </Dialog>
    </div>
  )
}
