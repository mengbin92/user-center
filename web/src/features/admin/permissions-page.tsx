import {
  Ban,
  BookOpen,
  CheckCircle2,
  ListTree,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge, RiskBadge, StatusBadge } from '../../components/badge'
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
import { useAuth } from '../../lib/auth'
import { useApiMutation } from '../../lib/mutations'
import type { Permission } from '../../lib/types'

type ScopeKey = 'all' | 'self' | 'user_ids'

const SCOPES: ScopeKey[] = ['all', 'self', 'user_ids']

type PendingAction = {
  title: string
  description?: string
  confirmLabel: string
  tone?: 'primary' | 'danger'
  run: (reason: string) => void
}

export function AdminPermissionsPage() {
  const { can, authorization } = useAuth()
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [category, setCategory] = useState('')
  const [status, setStatus] = useState('')
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [referencesId, setReferencesId] = useState<string | null>(null)

  const permissionsQuery = useQuery({
    queryKey: ['admin', 'iam', 'permissions', { keyword, category, status }],
    queryFn: () =>
      api.iam.listPermissions({
        keyword: keyword || undefined,
        category: category || undefined,
        status: status || undefined,
      }),
    retry: false,
  })
  const resourcesQuery = useQuery({
    queryKey: ['admin', 'iam', 'resources'],
    queryFn: () => api.iam.listResources(),
    retry: false,
  })
  const referencesQuery = useQuery({
    queryKey: ['admin', 'iam', 'permission', referencesId, 'references'],
    queryFn: () => api.iam.permissionReferences(referencesId ?? ''),
    enabled: Boolean(referencesId),
    retry: false,
  })

  const [createOpen, setCreateOpen] = useState(false)
  const [resourceId, setResourceId] = useState('')
  const [code, setCode] = useState('')
  const [name, setName] = useState('')
  const [formCategory, setFormCategory] = useState('')
  const [risk, setRisk] = useState('medium')
  const [scopes, setScopes] = useState<Set<ScopeKey>>(new Set(['all']))
  const [description, setDescription] = useState('')
  const [sort, setSort] = useState('0')
  const [reason, setReason] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const [editTarget, setEditTarget] = useState<Permission | null>(null)
  const [editName, setEditName] = useState('')
  const [editCategory, setEditCategory] = useState('')
  const [editRisk, setEditRisk] = useState('medium')
  const [editScopes, setEditScopes] = useState<Set<ScopeKey>>(new Set())
  const [editDescription, setEditDescription] = useState('')
  const [editSort, setEditSort] = useState('0')
  const [editReason, setEditReason] = useState('')

  const createPermission = useApiMutation({
    mutationFn: () =>
      api.iam.createPermission({
        resource_id: resourceId,
        code: code.trim(),
        name: name.trim(),
        category: formCategory.trim(),
        risk_level: risk,
        supported_scopes: [...scopes],
        context_types: ['platform'],
        description: description.trim(),
        sort: Number(sort) || 0,
        expected_policy_revision: authorization?.policy_revision,
        reason: reason.trim(),
      }),
    successMessage: '权限已创建',
    invalidate: [['admin', 'iam', 'permissions']],
    refreshAuth: true,
    onSuccess: () => {
      setCreateOpen(false)
      resetCreate()
    },
  })

  const updatePermission = useApiMutation({
    mutationFn: () => {
      if (!editTarget) throw new Error('未选择权限')
      return api.iam.updatePermission(editTarget.id ?? '', {
        id: editTarget.id,
        name: editName.trim(),
        category: editCategory.trim(),
        risk_level: editRisk,
        supported_scopes: [...editScopes],
        description: editDescription.trim(),
        sort: Number(editSort) || 0,
        expected_revision: editTarget.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: editReason.trim(),
      })
    },
    successMessage: '权限已更新',
    invalidate: [['admin', 'iam', 'permissions']],
    refreshAuth: true,
    onSuccess: () => setEditTarget(null),
  })

  const setPermissionStatus = useApiMutation({
    mutationFn: (input: { permission: Permission; status: string; reason: string }) =>
      api.iam.setPermissionStatus(input.permission.id ?? '', {
        id: input.permission.id,
        status: input.status,
        expected_revision: input.permission.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: '权限状态已更新',
    invalidate: [['admin', 'iam', 'permissions']],
    refreshAuth: true,
    onSuccess: () => setPending(null),
  })

  const archivePermission = useApiMutation({
    mutationFn: (input: { permission: Permission; reason: string }) =>
      api.iam.archivePermission(input.permission.id ?? '', {
        id: input.permission.id,
        expected_revision: input.permission.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: '权限已归档',
    invalidate: [['admin', 'iam', 'permissions']],
    refreshAuth: true,
    onSuccess: () => setPending(null),
  })

  const resetCreate = () => {
    setResourceId('')
    setCode('')
    setName('')
    setFormCategory('')
    setRisk('medium')
    setScopes(new Set(['all']))
    setDescription('')
    setSort('0')
    setReason('')
    setFormError(null)
  }

  const submitCreate = (event: FormEvent) => {
    event.preventDefault()
    setFormError(null)
    if (!resourceId || !code.trim() || !name.trim()) {
      setFormError('资源、权限代码与名称不能为空')
      return
    }
    if (scopes.size === 0) {
      setFormError('至少选择一个支持的数据范围')
      return
    }
    if (reason.trim().length < 2) {
      setFormError('请填写创建原因')
      return
    }
    createPermission.mutate(undefined)
  }

  const openEdit = (permission: Permission) => {
    setEditTarget(permission)
    setEditName(permission.name ?? '')
    setEditCategory(permission.category ?? '')
    setEditRisk(permission.risk_level ?? 'medium')
    setEditScopes(
      new Set(
        (permission.supported_scopes ?? []).filter(
          (scope): scope is ScopeKey => SCOPES.includes(scope as ScopeKey),
        ),
      ),
    )
    setEditDescription(permission.description ?? '')
    setEditSort(String(permission.sort ?? 0))
    setEditReason('')
  }

  const toggleScope = (
    scope: ScopeKey,
    target: 'create' | 'edit',
  ) => {
    const setter = target === 'create' ? setScopes : setEditScopes
    setter((current) => {
      const next = new Set(current)
      if (next.has(scope)) next.delete(scope)
      else next.add(scope)
      return next
    })
  }

  const permissions = permissionsQuery.data?.items ?? []
  const resources = resourcesQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="权限目录" />
      <PageHeader
        eyebrow="IAM"
        title="权限目录"
        description="平台操作权限的权威目录。权限状态与引用关系会影响角色 grant 的可用性。"
        actions={
          can('iam.permission.create') ? (
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                resetCreate()
                setCreateOpen(true)
              }}
              icon={<Plus className="h-3.5 w-3.5" />}
            >
              登记权限
            </Button>
          ) : undefined
        }
      />

      {resourcesQuery.isError ? (
        <InlineAlert tone="warning" title="无法读取资源目录">
          缺少 iam.resource.read 权限时，分类筛选与新建权限的资源选择可能不可用。
        </InlineAlert>
      ) : null}
      <div className="flex flex-wrap gap-1.5">
        {resources.map((resource) => (
          <Badge key={resource.id} tone="outline">
            {resource.name} · {resource.code}
          </Badge>
        ))}
      </div>

      <Card className="p-3">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            setKeyword(keywordInput.trim())
          }}
        >
          <div className="min-w-[200px] flex-1">
            <Field label="搜索" htmlFor="permission-keyword">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                <Input
                  id="permission-keyword"
                  value={keywordInput}
                  onChange={(event) => setKeywordInput(event.target.value)}
                  placeholder="代码、名称或描述"
                  className="pl-8"
                />
              </div>
            </Field>
          </div>
          <Field label="分类" htmlFor="permission-category" className="w-36">
            <Select
              id="permission-category"
              value={category}
              onChange={(event) => setCategory(event.target.value)}
            >
              <option value="">全部</option>
              {resources.map((resource) => (
                <option key={resource.id} value={resource.code}>
                  {resource.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="状态" htmlFor="permission-status" className="w-28">
            <Select
              id="permission-status"
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
            onClick={() => void permissionsQuery.refetch()}
            aria-label="刷新"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </form>
      </Card>

      <Card>
        <QueryBoundary query={permissionsQuery} loadingLabel="读取权限目录…">
          {permissions.length === 0 ? (
            <EmptyState
              title="没有匹配的权限"
              description="调整筛选条件，或登记新的操作权限。"
              icon={ListTree}
            />
          ) : (
            <Table minWidth="min-w-[980px]">
              <THead>
                <TR>
                  <TH>权限</TH>
                  <TH>分类</TH>
                  <TH>风险</TH>
                  <TH>状态</TH>
                  <TH>绑定</TH>
                  <TH>支持范围</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {permissions.map((permission) => (
                  <TR key={permission.id}>
                    <TD>
                      <div className="text-xs font-medium text-slate-800">
                        {permission.name}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">
                        {permission.code} · id={permission.id}
                      </div>
                      {permission.description ? (
                        <div className="mt-0.5 max-w-[300px] truncate text-[10px] text-slate-500">
                          {permission.description}
                        </div>
                      ) : null}
                    </TD>
                    <TD className="text-[11px] text-slate-600">
                      {permission.category || '—'}
                    </TD>
                    <TD>
                      <RiskBadge level={permission.risk_level} />
                    </TD>
                    <TD>
                      <StatusBadge status={permission.status} />
                    </TD>
                    <TD>
                      <Badge
                        tone={permission.binding === 'bound' ? 'success' : 'neutral'}
                      >
                        {permission.binding === 'bound' ? '已绑定' : '未绑定'}
                      </Badge>
                    </TD>
                    <TD>
                      <div className="flex flex-wrap gap-1">
                        {(permission.supported_scopes ?? []).map((scope) => (
                          <Badge key={scope} tone="outline">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </TD>
                    <TD className="font-mono text-[11px] text-slate-500">
                      {permission.revision}
                    </TD>
                    <TD>
                      <div className="flex justify-end gap-0.5">
                        {can('iam.permission.update') ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() => openEdit(permission)}
                            icon={<Pencil className="h-3 w-3" />}
                          >
                            编辑
                          </Button>
                        ) : null}
                        <Button
                          size="xs"
                          variant="ghost"
                          onClick={() => setReferencesId(permission.id ?? null)}
                          icon={<BookOpen className="h-3 w-3" />}
                        >
                          引用
                        </Button>
                        {can('iam.permission.update') &&
                        permission.status === 'active' &&
                        !permission.protected ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() =>
                              setPending({
                                title: '停用权限',
                                description:
                                  '停用后该权限不能用于新的 grant，已有 grant 会失去效果。',
                                confirmLabel: '确认停用',
                                tone: 'danger',
                                run: (actionReason) =>
                                  setPermissionStatus.mutate({
                                    permission,
                                    status: 'disabled',
                                    reason: actionReason,
                                  }),
                              })
                            }
                            icon={<Ban className="h-3 w-3" />}
                          >
                            停用
                          </Button>
                        ) : null}
                        {can('iam.permission.update') &&
                        permission.status === 'disabled' ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() =>
                              setPending({
                                title: '启用权限',
                                description: '启用后该权限可重新用于角色 grants。',
                                confirmLabel: '确认启用',
                                run: (actionReason) =>
                                  setPermissionStatus.mutate({
                                    permission,
                                    status: 'active',
                                    reason: actionReason,
                                  }),
                              })
                            }
                            icon={<CheckCircle2 className="h-3 w-3" />}
                          >
                            启用
                          </Button>
                        ) : null}
                        {can('iam.permission.update') &&
                        !permission.protected &&
                        permission.status !== 'archived' ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() =>
                              setPending({
                                title: '归档权限',
                                description:
                                  '归档后不可恢复。请先确认没有仍在引用的角色。',
                                confirmLabel: '确认归档',
                                tone: 'danger',
                                run: (actionReason) =>
                                  archivePermission.mutate({
                                    permission,
                                    reason: actionReason,
                                  }),
                              })
                            }
                            icon={<Trash2 className="h-3 w-3" />}
                          >
                            归档
                          </Button>
                        ) : null}
                      </div>
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
        title="登记权限"
        description="权限代码是授权判断的稳定标识，创建后不可修改。"
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createPermission.isPending}
            >
              取消
            </Button>
            <Button
              type="submit"
              form="create-permission-form"
              variant="primary"
              size="sm"
              loading={createPermission.isPending}
            >
              创建
            </Button>
          </>
        }
      >
        <form
          id="create-permission-form"
          className="space-y-3"
          onSubmit={submitCreate}
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="所属资源" htmlFor="permission-resource" required>
              <Select
                id="permission-resource"
                value={resourceId}
                onChange={(event) => {
                  setResourceId(event.target.value)
                  const resource = resources.find(
                    (item) => item.id === event.target.value,
                  )
                  setFormCategory(resource?.code ?? '')
                }}
              >
                <option value="">选择资源</option>
                {resources.map((resource) => (
                  <option key={resource.id} value={resource.id}>
                    {resource.name}（{resource.code}）
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="分类代码" htmlFor="permission-category-code" required>
              <Input
                id="permission-category-code"
                value={formCategory}
                onChange={(event) => setFormCategory(event.target.value)}
                className="font-mono"
                placeholder="identity"
              />
            </Field>
            <Field label="权限代码" htmlFor="permission-code" required>
              <Input
                id="permission-code"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                className="font-mono"
                placeholder="identity.user.read"
              />
            </Field>
            <Field label="权限名称" htmlFor="permission-name" required>
              <Input
                id="permission-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="查看用户详情"
              />
            </Field>
            <Field label="风险等级" htmlFor="permission-risk">
              <Select
                id="permission-risk"
                value={risk}
                onChange={(event) => setRisk(event.target.value)}
              >
                <option value="low">低</option>
                <option value="medium">中</option>
                <option value="high">高</option>
                <option value="critical">严重</option>
              </Select>
            </Field>
            <Field label="排序" htmlFor="permission-sort">
              <Input
                id="permission-sort"
                value={sort}
                onChange={(event) => setSort(event.target.value)}
                inputMode="numeric"
              />
            </Field>
          </div>
          <Field label="支持的数据范围" required>
            <div className="flex gap-3">
              {SCOPES.map((scope) => (
                <label
                  key={scope}
                  className="flex items-center gap-1.5 text-[11px] text-slate-700"
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                    checked={scopes.has(scope)}
                    onChange={() => toggleScope(scope, 'create')}
                  />
                  {scope}
                </label>
              ))}
            </div>
          </Field>
          <Field label="描述" htmlFor="permission-description">
            <Textarea
              id="permission-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              rows={2}
            />
          </Field>
          <Field label="操作原因" htmlFor="permission-reason" required>
            <Input
              id="permission-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="写入审计日志"
            />
          </Field>
          {formError ? (
            <InlineAlert tone="danger">{formError}</InlineAlert>
          ) : null}
        </form>
      </Dialog>

      <Dialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={`编辑权限 · ${editTarget?.code ?? ''}`}
        description="权限代码与所属资源不可修改。"
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
              disabled={updatePermission.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => updatePermission.mutate(undefined)}
              loading={updatePermission.isPending}
              disabled={!editName.trim() || editScopes.size === 0 || !editReason.trim()}
            >
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="权限名称" htmlFor="edit-permission-name" required>
            <Input
              id="edit-permission-name"
              value={editName}
              onChange={(event) => setEditName(event.target.value)}
            />
          </Field>
          <Field label="分类" htmlFor="edit-permission-category">
            <Input
              id="edit-permission-category"
              value={editCategory}
              onChange={(event) => setEditCategory(event.target.value)}
            />
          </Field>
          <Field label="风险等级" htmlFor="edit-permission-risk">
            <Select
              id="edit-permission-risk"
              value={editRisk}
              onChange={(event) => setEditRisk(event.target.value)}
            >
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
              <option value="critical">严重</option>
            </Select>
          </Field>
          <Field label="排序" htmlFor="edit-permission-sort">
            <Input
              id="edit-permission-sort"
              value={editSort}
              onChange={(event) => setEditSort(event.target.value)}
              inputMode="numeric"
            />
          </Field>
        </div>
        <Field label="支持的数据范围" required>
          <div className="flex gap-3">
            {SCOPES.map((scope) => (
              <label
                key={scope}
                className="flex items-center gap-1.5 text-[11px] text-slate-700"
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                  checked={editScopes.has(scope)}
                  onChange={() => toggleScope(scope, 'edit')}
                />
                {scope}
              </label>
            ))}
          </div>
        </Field>
        <Field label="描述" htmlFor="edit-permission-description">
          <Textarea
            id="edit-permission-description"
            value={editDescription}
            onChange={(event) => setEditDescription(event.target.value)}
            rows={2}
          />
        </Field>
        <Field label="操作原因" htmlFor="edit-permission-reason">
          <Input
            id="edit-permission-reason"
            value={editReason}
            onChange={(event) => setEditReason(event.target.value)}
            placeholder="请填写本次变更的原因" required
          />
        </Field>
        <div className="text-[11px] text-slate-500">
          当前 revision：<span className="font-mono">{editTarget?.revision}</span>
        </div>
      </Dialog>

      <Dialog
        open={referencesId !== null}
        onClose={() => setReferencesId(null)}
        title="权限引用"
        description="引用该权限的角色或分配。归档前请确认引用已清理。"
        size="md"
        bodyClassName="space-y-3"
      >
        {referencesQuery.isPending ? (
          <div className="py-6 text-center text-xs text-slate-500">加载中…</div>
        ) : referencesQuery.isError ? (
          <InlineAlert tone="danger">无法读取引用关系</InlineAlert>
        ) : referencesQuery.data?.items?.length ? (
          <Table minWidth="min-w-[360px]">
            <THead>
              <TR>
                <TH>类型</TH>
                <TH>ID</TH>
                <TH>用户</TH>
              </TR>
            </THead>
            <TBody>
              {referencesQuery.data.items.map((reference, index) => (
                <TR key={`${reference.kind}-${reference.id}-${index}`}>
                  <TD className="text-xs text-slate-700">{reference.kind}</TD>
                  <TD className="font-mono text-[11px] text-slate-600">
                    {reference.id}
                  </TD>
                  <TD className="font-mono text-[11px] text-slate-500">
                    {reference.user_id || '—'}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : (
          <EmptyState
            title="没有引用"
            description="该权限尚未被任何角色使用。"
            icon={ListTree}
          />
        )}
      </Dialog>

      <ReasonDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={(actionReason) => pending?.run(actionReason)}
        title={pending?.title ?? ''}
        description={pending?.description}
        confirmLabel={pending?.confirmLabel}
        tone={pending?.tone ?? 'danger'}
        busy={setPermissionStatus.isPending || archivePermission.isPending}
      />
    </div>
  )
}
