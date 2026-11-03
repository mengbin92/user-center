import {
  Columns3,
  Pencil,
  Plus,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
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
import type { Constraint } from '../../lib/types'
import { roleById, useAllRoles } from './common'

const KIND_LABELS: Record<string, string> = {
  mutual_exclusion: '互斥（不能同时拥有）',
  max_roles: '角色数量上限',
}

export function AdminConstraintsPage() {
  const { can, authorization } = useAuth()
  const rolesQuery = useAllRoles()
  const [createOpen, setCreateOpen] = useState(false)
  const [kind, setKind] = useState('mutual_exclusion')
  const [name, setName] = useState('')
  const [roleIds, setRoleIds] = useState<Set<string>>(new Set())
  const [maxCount, setMaxCount] = useState('')
  const [reason, setReason] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const [editTarget, setEditTarget] = useState<Constraint | null>(null)
  const [editName, setEditName] = useState('')
  const [editRoleIds, setEditRoleIds] = useState<Set<string>>(new Set())
  const [editMaxCount, setEditMaxCount] = useState('')
  const [editEnabled, setEditEnabled] = useState(true)
  const [editReason, setEditReason] = useState('')

  const [deleteTarget, setDeleteTarget] = useState<Constraint | null>(null)

  const constraintsQuery = useQuery({
    queryKey: ['admin', 'iam', 'constraints'],
    queryFn: () => api.iam.listConstraints(),
    retry: false,
  })

  const createConstraint = useApiMutation({
    mutationFn: () =>
      api.iam.createConstraint({
        kind,
        name: name.trim(),
        role_ids: [...roleIds],
        max_count: kind === 'max_roles' ? maxCount.trim() : undefined,
        reason: reason.trim(),
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '职责分离约束已创建',
    invalidate: [['admin', 'iam', 'constraints']],
    refreshAuth: true,
    onSuccess: () => {
      setCreateOpen(false)
      resetCreate()
    },
  })

  const updateConstraint = useApiMutation({
    mutationFn: () => {
      if (!editTarget) throw new Error('未选择约束')
      return api.iam.updateConstraint(editTarget.id ?? '', {
        id: editTarget.id,
        name: editName.trim(),
        role_ids: [...editRoleIds],
        max_count: editMaxCount.trim() || undefined,
        enabled: editEnabled,
        expected_revision: editTarget.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: editReason.trim(),
      })
    },
    successMessage: '约束已更新',
    invalidate: [['admin', 'iam', 'constraints']],
    refreshAuth: true,
    onSuccess: () => setEditTarget(null),
  })

  const deleteConstraint = useApiMutation({
    mutationFn: (input: { constraint: Constraint; reason: string }) =>
      api.iam.deleteConstraint(input.constraint.id ?? '', {
        expected_revision: input.constraint.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: '约束已删除',
    invalidate: [['admin', 'iam', 'constraints']],
    refreshAuth: true,
    onSuccess: () => setDeleteTarget(null),
  })

  const resetCreate = () => {
    setKind('mutual_exclusion')
    setName('')
    setRoleIds(new Set())
    setMaxCount('')
    setReason('')
    setFormError(null)
  }

  const toggleRole = (
    roleId: string,
    target: 'create' | 'edit',
  ) => {
    const setter = target === 'create' ? setRoleIds : setEditRoleIds
    setter((current) => {
      const next = new Set(current)
      if (next.has(roleId)) next.delete(roleId)
      else next.add(roleId)
      return next
    })
  }

  const validate = (
    targetName: string,
    targetRoles: Set<string>,
    targetKind: string,
    targetMax: string,
  ): string | null => {
    if (!targetName.trim()) return '约束名称不能为空'
    if (targetRoles.size < 1) return '至少选择一个角色'
    if (targetKind === 'mutual_exclusion' && targetRoles.size < 2) {
      return '互斥约束至少需要两个角色'
    }
    if (targetKind === 'max_roles' && (!targetMax || Number(targetMax) <= 0)) {
      return '数量上限必须是大于 0 的十进制数字'
    }
    return null
  }

  const submitCreate = (event: FormEvent) => {
    event.preventDefault()
    const error = validate(name, roleIds, kind, maxCount)
    if (error) {
      setFormError(error)
      return
    }
    if (reason.trim().length < 2) {
      setFormError('请填写创建原因')
      return
    }
    setFormError(null)
    createConstraint.mutate(undefined)
  }

  const openEdit = (constraint: Constraint) => {
    setFormError(null)
    setEditTarget(constraint)
    setEditName(constraint.name ?? '')
    setEditRoleIds(new Set(constraint.role_ids ?? []))
    setEditMaxCount(constraint.max_count ?? '')
    setEditEnabled(constraint.enabled ?? true)
    setEditReason('')
  }

  const submitEdit = () => {
    const error = validate(
      editName,
      editRoleIds,
      editTarget?.kind ?? 'mutual_exclusion',
      editMaxCount,
    )
    if (error) {
      setFormError(error)
      return
    }
    setFormError(null)
    updateConstraint.mutate(undefined)
  }

  const roles = rolesQuery.data?.items ?? []
  const items = constraintsQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="职责分离" />
      <PageHeader
        eyebrow="IAM"
        title="职责分离约束"
        description="互斥约束禁止用户同时持有指定角色；数量上限限制角色组合规模。"
        actions={
          can('iam.constraint.update') ? (
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                resetCreate()
                setCreateOpen(true)
              }}
              icon={<Plus className="h-3.5 w-3.5" />}
            >
              新建约束
            </Button>
          ) : undefined
        }
      />

      <Card>
        <QueryBoundary query={constraintsQuery} loadingLabel="读取约束…">
          {items.length === 0 ? (
            <EmptyState
              title="暂无职责分离约束"
              description="创建互斥约束可防止高风险角色被同时授予。"
              icon={Columns3}
            />
          ) : (
            <Table minWidth="min-w-[820px]">
              <THead>
                <TR>
                  <TH>约束</TH>
                  <TH>类型</TH>
                  <TH>角色</TH>
                  <TH>上限</TH>
                  <TH>状态</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((constraint) => (
                  <TR key={constraint.id}>
                    <TD>
                      <div className="text-xs font-medium text-slate-800">
                        {constraint.name}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">
                        id={constraint.id}
                      </div>
                    </TD>
                    <TD>
                      <Badge tone="info">
                        {KIND_LABELS[constraint.kind ?? ''] ?? constraint.kind}
                      </Badge>
                    </TD>
                    <TD>
                      <div className="flex flex-wrap gap-1">
                        {(constraint.role_ids ?? []).map((roleId) => {
                          const role = roleById(roles, roleId)
                          return (
                            <Badge key={roleId} tone="violet">
                              {role?.name || roleId}
                            </Badge>
                          )
                        })}
                      </div>
                    </TD>
                    <TD className="text-xs text-slate-700">
                      {constraint.kind === 'max_roles'
                        ? constraint.max_count || '—'
                        : '—'}
                    </TD>
                    <TD>
                      {constraint.enabled ? (
                        <Badge tone="success" dot>
                          已启用
                        </Badge>
                      ) : (
                        <Badge tone="neutral">已停用</Badge>
                      )}
                    </TD>
                    <TD className="font-mono text-[11px] text-slate-500">
                      {constraint.revision}
                    </TD>
                    <TD>
                      <div className="flex justify-end gap-0.5">
                        {can('iam.constraint.update') ? (
                          <>
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => openEdit(constraint)}
                              icon={<Pencil className="h-3 w-3" />}
                            >
                              编辑
                            </Button>
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => setDeleteTarget(constraint)}
                              icon={<Trash2 className="h-3 w-3" />}
                            >
                              删除
                            </Button>
                          </>
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
        title="新建职责分离约束"
        description="约束会参与角色分配与切换时的校验。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createConstraint.isPending}
            >
              取消
            </Button>
            <Button
              type="submit"
              form="create-constraint-form"
              variant="primary"
              size="sm"
              loading={createConstraint.isPending}
            >
              创建
            </Button>
          </>
        }
      >
        <form id="create-constraint-form" className="space-y-3" onSubmit={submitCreate}>
          <Field label="约束类型" htmlFor="constraint-kind" required>
            <Select
              id="constraint-kind"
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              <option value="mutual_exclusion">互斥（不能同时拥有）</option>
              <option value="max_roles">角色数量上限</option>
            </Select>
          </Field>
          <Field label="名称" htmlFor="constraint-name" required>
            <Input
              id="constraint-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="例如 财务与审计互斥"
            />
          </Field>
          {kind === 'max_roles' ? (
            <Field label="最大角色数" htmlFor="constraint-max" required>
              <Input
                id="constraint-max"
                value={maxCount}
                onChange={(event) => setMaxCount(event.target.value)}
                inputMode="numeric"
                placeholder="例如 2"
              />
            </Field>
          ) : null}
          <div>
            <div className="mb-1 text-xs font-medium text-slate-700">
              角色范围 <span className="text-rose-500">*</span>
            </div>
            <div className="grid max-h-44 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2 sm:grid-cols-2">
              {roles.map((role) => (
                <label
                  key={role.id}
                  className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                    checked={roleIds.has(role.id ?? '')}
                    onChange={() => toggleRole(role.id ?? '', 'create')}
                  />
                  <span className="truncate text-slate-700">{role.name}</span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {role.code}
                  </span>
                </label>
              ))}
            </div>
          </div>
          <Field label="操作原因" htmlFor="constraint-reason" required>
            <Textarea
              id="constraint-reason"
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

      <Dialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={`编辑约束 · ${editTarget?.name ?? ''}`}
        description="类型不可修改；可调整名称、角色范围、上限与启用状态。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
              disabled={updateConstraint.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitEdit}
              loading={updateConstraint.isPending}
              disabled={!editReason.trim()}
            >
              保存
            </Button>
          </>
        }
      >
        <Field label="名称" htmlFor="edit-constraint-name" required>
          <Input
            id="edit-constraint-name"
            value={editName}
            onChange={(event) => setEditName(event.target.value)}
          />
        </Field>
        {editTarget?.kind === 'max_roles' ? (
          <Field label="最大角色数" htmlFor="edit-constraint-max" required>
            <Input
              id="edit-constraint-max"
              value={editMaxCount}
              onChange={(event) => setEditMaxCount(event.target.value)}
              inputMode="numeric"
            />
          </Field>
        ) : null}
        <div>
          <div className="mb-1 text-xs font-medium text-slate-700">角色范围</div>
          <div className="grid max-h-44 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {roles.map((role) => (
              <label
                key={role.id}
                className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                  checked={editRoleIds.has(role.id ?? '')}
                  onChange={() => toggleRole(role.id ?? '', 'edit')}
                />
                <span className="truncate text-slate-700">{role.name}</span>
              </label>
            ))}
          </div>
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-700">
          <input
            type="checkbox"
            className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
            checked={editEnabled}
            onChange={(event) => setEditEnabled(event.target.checked)}
          />
          启用该约束
        </label>
        <Field label="操作原因" htmlFor="edit-constraint-reason">
          <Input
            id="edit-constraint-reason"
            value={editReason}
            onChange={(event) => setEditReason(event.target.value)}
            placeholder="请填写本次变更的原因" required
          />
        </Field>
        {formError ? (
          <InlineAlert tone="danger">{formError}</InlineAlert>
        ) : null}
      </Dialog>

      <ReasonDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={(actionReason) => {
          if (deleteTarget) {
            deleteConstraint.mutate({ constraint: deleteTarget, reason: actionReason })
          }
        }}
        title="删除职责分离约束"
        description="删除后不再校验该约束。操作写入审计。"
        confirmLabel="确认删除"
        tone="danger"
        busy={deleteConstraint.isPending}
      />
    </div>
  )
}
