import {
  Plus,
  RefreshCw,
  Share2,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardHeader,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Checkbox, Field, Input, Select, Textarea } from '../../components/input'
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
import { errorMessage } from '../../lib/errors'
import {
  formatDateTime,
  splitList,
  toRfc3339,
} from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type {
  Delegation,
  DelegationCeiling,
  Scope,
} from '../../lib/types'
import { ScopeBadge, roleById, useAllRoles } from './common'

type ScopeKind = 'all' | 'self' | 'user_ids'

type CeilingDraft = {
  operation: string
  scopeKind: ScopeKind
  userIds: string
}

function buildScope(kind: ScopeKind, userIds: string): Scope {
  if (kind === 'all') return { all: true }
  if (kind === 'self') return { self: true }
  return { user_ids: splitList(userIds) }
}

function delegationState(delegation: Delegation) {
  if (delegation.revoked) {
    return { label: '已撤销', tone: 'neutral' as const }
  }
  if (
    delegation.expires_at &&
    new Date(delegation.expires_at).getTime() <= Date.now()
  ) {
    return { label: '已过期', tone: 'warning' as const }
  }
  return { label: '生效中', tone: 'success' as const }
}

export function AdminDelegationsPage() {
  const { authorization, can } = useAuth()
  const rolesQuery = useAllRoles()
  const canManage = can('iam.delegation.update')

  const [filterManagerId, setFilterManagerId] = useState('')
  const [filterTargetId, setFilterTargetId] = useState('')
  const [filterStatus, setFilterStatus] = useState('')

  const delegationsQuery = useQuery({
    queryKey: [
      'admin',
      'iam',
      'delegations',
      { filterManagerId, filterTargetId, filterStatus },
    ],
    queryFn: () =>
      api.iam.listDelegations({
        manager_role_id: filterManagerId || undefined,
        target_role_id: filterTargetId || undefined,
        status: filterStatus || undefined,
      }),
    retry: false,
  })

  const [createOpen, setCreateOpen] = useState(false)
  const [managerRoleId, setManagerRoleId] = useState('')
  const [targetRoleId, setTargetRoleId] = useState('')
  const [actions, setActions] = useState<Set<string>>(new Set(['assign']))
  const [scopeKind, setScopeKind] = useState<ScopeKind>('all')
  const [scopeUserIds, setScopeUserIds] = useState('')
  const [ceilingRows, setCeilingRows] = useState<CeilingDraft[]>([])
  const [canRedelegate, setCanRedelegate] = useState(false)
  const [startsAt, setStartsAt] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [reason, setReason] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<Delegation | null>(null)

  const roles = rolesQuery.data?.items ?? []
  const delegations = delegationsQuery.data?.items ?? []

  const resetForm = () => {
    setManagerRoleId('')
    setTargetRoleId('')
    setActions(new Set(['assign']))
    setScopeKind('all')
    setScopeUserIds('')
    setCeilingRows([])
    setCanRedelegate(false)
    setStartsAt('')
    setExpiresAt('')
    setReason('')
    setFormError(null)
  }

  const toggleAction = (action: string) => {
    setActions((current) => {
      const next = new Set(current)
      if (next.has(action)) next.delete(action)
      else next.add(action)
      return next
    })
  }

  const buildGrantCeiling = (): DelegationCeiling[] =>
    ceilingRows
      .filter((row) => row.operation.trim())
      .map((row) => ({
        operation: row.operation.trim(),
        scope: buildScope(row.scopeKind, row.userIds),
      }))

  const createDelegation = useApiMutation({
    mutationFn: () =>
      api.iam.createDelegation({
        manager_role_id: managerRoleId,
        target_role_id: targetRoleId,
        actions: [...actions],
        target_user_scope: buildScope(scopeKind, scopeUserIds),
        grant_ceiling: buildGrantCeiling(),
        can_redelegate: canRedelegate,
        starts_at: toRfc3339(startsAt),
        expires_at: toRfc3339(expiresAt),
        reason: reason.trim(),
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '角色委派已创建',
    successDescription: '策略版本已更新，委派立即生效。',
    invalidate: [['admin', 'iam', 'delegations']],
    refreshAuth: true,
    onSuccess: () => {
      setCreateOpen(false)
      resetForm()
    },
  })

  const revokeDelegation = useApiMutation({
    mutationFn: (input: { delegation: Delegation; reason: string }) =>
      api.iam.revokeDelegation(input.delegation.id ?? '', {
        id: input.delegation.id,
        expected_revision: input.delegation.revision ?? '0',
        reason: input.reason,
      }),
    successMessage: '委派已撤销',
    invalidate: [['admin', 'iam', 'delegations']],
    refreshAuth: true,
    onSuccess: () => setRevokeTarget(null),
  })

  const submitCreate = () => {
    setFormError(null)
    if (!managerRoleId || !targetRoleId) {
      setFormError('请选择管理角色与目标角色')
      return
    }
    if (managerRoleId === targetRoleId) {
      setFormError('管理角色不能委派给自身')
      return
    }
    if (actions.size === 0) {
      setFormError('至少选择一个委派动作')
      return
    }
    if (scopeKind === 'user_ids' && splitList(scopeUserIds).length === 0) {
      setFormError('目标用户范围为指定用户时，至少填写一个用户 ID')
      return
    }
    if (
      ceilingRows.some(
        (row) =>
          row.scopeKind === 'user_ids' && splitList(row.userIds).length === 0,
      )
    ) {
      setFormError('委派上限的指定用户范围不能为空')
      return
    }
    if (reason.trim().length < 2) {
      setFormError('请填写至少 2 个字符的操作原因')
      return
    }
    createDelegation.mutate(undefined)
  }

  const addCeilingRow = () => {
    setCeilingRows((current) => [
      ...current,
      { operation: '', scopeKind: 'all', userIds: '' },
    ])
  }

  const updateCeilingRow = (index: number, patch: Partial<CeilingDraft>) => {
    setCeilingRows((current) =>
      current.map((row, rowIndex) =>
        rowIndex === index ? { ...row, ...patch } : row,
      ),
    )
  }

  return (
    <div className="space-y-4">
      <PageTitle title="委派管理" />
      <PageHeader
        eyebrow="IAM"
        title="委派管理"
        description="把管理角色的分配/撤销能力在限定范围内委派给其他角色。所有写操作需要近期安全验证。"
        actions={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                void rolesQuery.refetch()
                void delegationsQuery.refetch()
              }}
              icon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              刷新
            </Button>
            {canManage ? (
              <Button
                size="sm"
                variant="primary"
                onClick={() => {
                  resetForm()
                  setCreateOpen(true)
                }}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                新建委派
              </Button>
            ) : (
              <Badge tone="neutral">只读：缺少 iam.delegation.update</Badge>
            )}
          </>
        }
      />

      <Card className="p-3">
        <div className="flex flex-wrap items-end gap-2">
          <Field label="管理角色" htmlFor="delegation-filter-manager" className="w-52">
            <Select
              id="delegation-filter-manager"
              value={filterManagerId}
              onChange={(event) => setFilterManagerId(event.target.value)}
            >
              <option value="">全部管理角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>
                  {role.name}（{role.code}）
                </option>
              ))}
            </Select>
          </Field>
          <Field label="目标角色" htmlFor="delegation-filter-target" className="w-52">
            <Select
              id="delegation-filter-target"
              value={filterTargetId}
              onChange={(event) => setFilterTargetId(event.target.value)}
            >
              <option value="">全部目标角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>
                  {role.name}（{role.code}）
                </option>
              ))}
            </Select>
          </Field>
          <Field label="状态" htmlFor="delegation-filter-status" className="w-32">
            <Select
              id="delegation-filter-status"
              value={filterStatus}
              onChange={(event) => setFilterStatus(event.target.value)}
            >
              <option value="">全部</option>
              <option value="active">生效中</option>
              <option value="revoked">已撤销</option>
            </Select>
          </Field>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setFilterManagerId('')
              setFilterTargetId('')
              setFilterStatus('')
            }}
          >
            重置
          </Button>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="委派列表"
          description="委派记录按创建时间倒序返回，可依据状态筛选。"
          actions={<Badge tone="outline">{delegations.length} 条</Badge>}
        />
        <QueryBoundary query={delegationsQuery} loadingLabel="读取委派列表…">
          {delegations.length === 0 ? (
            <EmptyState
              title="暂无委派记录"
              description="创建委派后，被委派角色可以在限定范围内分配或撤销目标角色。"
              icon={Share2}
            />
          ) : (
            <Table minWidth="min-w-[1120px]">
              <THead>
                <TR>
                  <TH>委派</TH>
                  <TH>管理角色 → 目标角色</TH>
                  <TH>动作</TH>
                  <TH>目标用户范围</TH>
                  <TH>授权上限</TH>
                  <TH>有效期</TH>
                  <TH>再委派</TH>
                  <TH>状态</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {delegations.map((delegation) => {
                  const state = delegationState(delegation)
                  const manager = roleById(roles, delegation.manager_role_id)
                  const target = roleById(roles, delegation.target_role_id)
                  return (
                    <TR key={delegation.id}>
                      <TD>
                        <div className="font-mono text-[11px] text-slate-800">
                          #{delegation.id}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          rev {delegation.revision}
                        </div>
                      </TD>
                      <TD>
                        <div className="text-[11px] font-medium text-slate-800">
                          {manager?.name || delegation.manager_role_id}
                          <span className="mx-1 text-slate-400">→</span>
                          {target?.name || delegation.target_role_id}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {manager?.code || '—'} → {target?.code || '—'}
                        </div>
                      </TD>
                      <TD>
                        <div className="flex flex-wrap gap-1">
                          {(delegation.actions ?? []).map((action) => (
                            <Badge
                              key={action}
                              tone={action === 'assign' ? 'info' : 'warning'}
                            >
                              {action === 'assign' ? '分配' : '撤销'}
                            </Badge>
                          ))}
                        </div>
                      </TD>
                      <TD>
                        <ScopeBadge scope={delegation.target_user_scope} />
                      </TD>
                      <TD>
                        {delegation.grant_ceiling?.length ? (
                          <div className="max-w-[220px] space-y-0.5">
                            {delegation.grant_ceiling.map((ceiling, index) => (
                              <div
                                key={`${ceiling.operation}-${index}`}
                                className="truncate font-mono text-[10px] text-slate-600"
                              >
                                {ceiling.operation}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <Badge tone="neutral">未限制</Badge>
                        )}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        <div>起 {formatDateTime(delegation.starts_at)}</div>
                        <div>
                          止{' '}
                          {delegation.expires_at
                            ? formatDateTime(delegation.expires_at)
                            : '永久'}
                        </div>
                      </TD>
                      <TD>
                        {delegation.can_redelegate ? (
                          <Badge tone="warning">允许</Badge>
                        ) : (
                          <Badge tone="neutral">不允许</Badge>
                        )}
                      </TD>
                      <TD>
                        <div className="space-y-1">
                          <Badge tone={state.tone} dot>
                            {state.label}
                          </Badge>
                          {delegation.revoked_at ? (
                            <div className="text-[10px] text-slate-400">
                              {formatDateTime(delegation.revoked_at)}
                            </div>
                          ) : null}
                        </div>
                      </TD>
                      <TD className="text-right">
                        {canManage &&
                        !delegation.revoked &&
                        state.label !== '已过期' ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() => setRevokeTarget(delegation)}
                            icon={<Trash2 className="h-3 w-3" />}
                          >
                            撤销
                          </Button>
                        ) : null}
                      </TD>
                    </TR>
                  )
                })}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={createOpen}
        onClose={() => {
          if (createDelegation.isPending) return
          setCreateOpen(false)
        }}
        title="新建角色委派"
        description="委派允许管理角色在目标用户范围内分配或撤销目标角色；提交时会校验策略版本。"
        size="lg"
        bodyClassName="space-y-3"
        dismissible={!createDelegation.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setCreateOpen(false)
                resetForm()
              }}
              disabled={createDelegation.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitCreate}
              loading={createDelegation.isPending}
              icon={<Share2 className="h-3.5 w-3.5" />}
            >
              创建委派
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="管理角色" htmlFor="delegation-manager" required>
            <Select
              id="delegation-manager"
              value={managerRoleId}
              onChange={(event) => setManagerRoleId(event.target.value)}
            >
              <option value="">选择管理角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>
                  {role.name}（{role.code}）
                </option>
              ))}
            </Select>
          </Field>
          <Field label="目标角色" htmlFor="delegation-target" required>
            <Select
              id="delegation-target"
              value={targetRoleId}
              onChange={(event) => setTargetRoleId(event.target.value)}
            >
              <option value="">选择目标角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>
                  {role.name}（{role.code}）
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            委派动作 <span className="text-rose-500">*</span>
          </div>
          <div className="flex gap-4 rounded-md border border-slate-200 p-2.5">
            <Checkbox
              checked={actions.has('assign')}
              onChange={() => toggleAction('assign')}
              label="分配（assign）"
            />
            <Checkbox
              checked={actions.has('revoke')}
              onChange={() => toggleAction('revoke')}
              label="撤销（revoke）"
            />
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="目标用户范围" htmlFor="delegation-scope" required>
            <Select
              id="delegation-scope"
              value={scopeKind}
              onChange={(event) =>
                setScopeKind(event.target.value as ScopeKind)
              }
            >
              <option value="all">全部用户</option>
              <option value="self">仅本人</option>
              <option value="user_ids">指定用户</option>
            </Select>
          </Field>
          {scopeKind === 'user_ids' ? (
            <Field
              label="用户 ID 列表"
              htmlFor="delegation-scope-users"
              required
              hint="逗号或换行分隔"
            >
              <Input
                id="delegation-scope-users"
                value={scopeUserIds}
                onChange={(event) => setScopeUserIds(event.target.value)}
                placeholder="例如 12, 34"
              />
            </Field>
          ) : null}
        </div>

        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <div className="text-xs font-medium text-slate-700">
              授权上限（可选）
            </div>
            <Button
              type="button"
              size="xs"
              variant="ghost"
              onClick={addCeilingRow}
              icon={<Plus className="h-3 w-3" />}
            >
              添加
            </Button>
          </div>
          <p className="mb-1.5 text-[11px] text-slate-500">
            留空表示不额外限制；每一行填写权限 operation 与允许的范围。
          </p>
          <div className="space-y-2">
            {ceilingRows.map((row, index) => (
              <div
                key={index}
                className="grid gap-2 rounded-md border border-slate-200 p-2 sm:grid-cols-[1.4fr_0.8fr_1fr_auto]"
              >
                <Input
                  value={row.operation}
                  onChange={(event) =>
                    updateCeilingRow(index, { operation: event.target.value })
                  }
                  placeholder="权限 operation，如 identity.user.archive"
                />
                <Select
                  value={row.scopeKind}
                  onChange={(event) =>
                    updateCeilingRow(index, {
                      scopeKind: event.target.value as ScopeKind,
                    })
                  }
                >
                  <option value="all">全部</option>
                  <option value="self">仅本人</option>
                  <option value="user_ids">指定用户</option>
                </Select>
                <Input
                  value={row.userIds}
                  onChange={(event) =>
                    updateCeilingRow(index, { userIds: event.target.value })
                  }
                  placeholder={
                    row.scopeKind === 'user_ids' ? '用户 ID，逗号分隔' : '—'
                  }
                  disabled={row.scopeKind !== 'user_ids'}
                />
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  aria-label="移除授权上限"
                  onClick={() =>
                    setCeilingRows((current) =>
                      current.filter((_, rowIndex) => rowIndex !== index),
                    )
                  }
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="生效时间" htmlFor="delegation-starts">
            <Input
              id="delegation-starts"
              type="datetime-local"
              value={startsAt}
              onChange={(event) => setStartsAt(event.target.value)}
            />
          </Field>
          <Field
            label="过期时间"
            htmlFor="delegation-expires"
            hint="留空表示永久有效"
          >
            <Input
              id="delegation-expires"
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </Field>
        </div>

        <Checkbox
          checked={canRedelegate}
          onChange={(event) => setCanRedelegate(event.target.checked)}
          label="允许被委派角色继续向下委派"
        />

        {formError ? (
          <InlineAlert tone="danger">{formError}</InlineAlert>
        ) : null}

        <Field
          label="操作原因"
          htmlFor="delegation-reason"
          required
          hint="至少 2 个字符，会写入审计日志。"
        >
          <Textarea
            id="delegation-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            rows={3}
            placeholder="例如：季度权限交接，工单 IAM-3021"
          />
        </Field>

        {createDelegation.isError ? (
          <InlineAlert tone="danger" title="创建失败">
            {errorMessage(createDelegation.error)}
          </InlineAlert>
        ) : null}
      </Dialog>

      <ReasonDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={(revokeReason) => {
          if (revokeTarget) {
            revokeDelegation.mutate({
              delegation: revokeTarget,
              reason: revokeReason,
            })
          }
        }}
        title="撤销角色委派"
        description="撤销后该委派立即失效，策略版本会更新。"
        confirmLabel="确认撤销"
        tone="danger"
        busy={revokeDelegation.isPending}
        error={
          revokeDelegation.isError
            ? errorMessage(revokeDelegation.error)
            : null
        }
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          委派 #{revokeTarget?.id} · revision {revokeTarget?.revision}
        </div>
      </ReasonDialog>
    </div>
  )
}
