import { Pencil, Plus, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Button } from '../../components/button'
import { Card, CardHeader, EmptyState, InlineAlert } from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { useApiMutation } from '../../lib/mutations'
import type {
  CreateOrgDelegationRequest,
  OrgDelegation,
  OrgRole,
  Organization,
  UpdateOrgDelegationRequest,
} from '../../lib/types'

// Organization-scoped delegation management.
//
// A delegation answers "who may hand out a role they do not hold". The server
// still re-checks every use: the manager role must be active in the caller's
// assignments, the action and target user must be covered, and the ceiling
// must cover what the target role actually confers. The UI therefore snapshots
// the target role's grants as the ceiling instead of asking an operator to
// type permission codes -- a hand-written ceiling that misses one grant
// produces a delegation that can never authorise anything.

type Ceiling = NonNullable<CreateOrgDelegationRequest['grant_ceiling']>

type Draft = {
  managerRole: string
  targetRole: string
  actions: string[]
  ceiling: Ceiling
  startsAt: string
  expiresAt: string
  // Empty means "all current and future members"; otherwise the delegation is
  // bounded to these user ids. The server compares this against the assignment
  // target on every write.
  userScope: string[]
}

type Confirm = {
  title: string
  description: string
  confirmLabel: string
  danger?: boolean
  run: (reason: string) => Promise<unknown>
}

function toRFC3339(local: string): string {
  if (!local) return ''
  const parsed = new Date(local)
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString()
}

function toLocalInput(rfc3339?: string | null): string {
  if (!rfc3339) return ''
  const parsed = new Date(rfc3339)
  if (Number.isNaN(parsed.getTime())) return ''
  const offset = parsed.getTimezoneOffset() * 60_000
  return new Date(parsed.getTime() - offset).toISOString().slice(0, 16)
}

export function OrganizationDelegations({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const delegationsQuery = useQuery({
    queryKey: ['orgs', orgId, 'delegations'],
    queryFn: () => api.orgs.listDelegations(orgId),
    retry: false,
  })
  const rolesQuery = useQuery({
    queryKey: ['orgs', orgId, 'roles'],
    queryFn: () => api.orgs.listRoles(orgId),
    retry: false,
  })
  const membersQuery = useQuery({
    queryKey: ['orgs', orgId, 'members'],
    queryFn: () => api.orgs.listMembers(orgId),
    retry: false,
  })

  const { authorization } = useAuth()
  const canManage = org.role === 'owner'
  const policyRevision = authorization?.policy_revision ?? '0'

  const [dialog, setDialog] = useState<{ mode: 'create' } | { mode: 'update'; item: OrgDelegation } | null>(null)
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [managerRole, setManagerRole] = useState('')
  const [targetRole, setTargetRole] = useState('')
  const [actions, setActions] = useState<string[]>(['assign'])
  const [startsAt, setStartsAt] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [scopeAll, setScopeAll] = useState(true)
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])

  const roles = useMemo(() => rolesQuery.data?.items ?? [], [rolesQuery.data])
  const rolesById = useMemo(() => {
    const map = new Map<string, OrgRole>()
    for (const role of roles) if (role.id) map.set(role.id, role)
    return map
  }, [roles])

  // The ceiling is derived, never authored. It is a snapshot of the target
  // role's grants at save time; changing the role later does not widen an
  // already-issued delegation, which is exactly the intended behaviour.
  const ceiling = useMemo<Ceiling>(() => {
    const role = roles.find((r) => r.id === targetRole)
    return (role?.grants ?? [])
      .filter((g) => g.effect === 'allow' && g.operation)
      .map((g) => ({
        operation: g.operation ?? '',
        scope: g.scope ?? { all: true },
      }))
  }, [roles, targetRole])

  const invalidate = [['orgs', orgId, 'delegations']]
  const closeAll = () => {
    setDialog(null)
    setConfirm(null)
    setFormError(null)
  }

  const createMutation = useApiMutation({
    mutationFn: (payload: { reason: string; draft: Draft }) =>
      api.orgs.createDelegation(orgId, {
        manager_role_id: payload.draft.managerRole,
        target_role_id: payload.draft.targetRole,
        actions: payload.draft.actions,
        grant_ceiling: payload.draft.ceiling,
        target_user_scope: payload.draft.userScope.length > 0
          ? { user_ids: payload.draft.userScope }
          : { all: true },
        starts_at: toRFC3339(payload.draft.startsAt),
        expires_at: toRFC3339(payload.draft.expiresAt),
        reason: payload.reason,
        expected_policy_revision: policyRevision,
      }),
    successMessage: '委派已创建',
    successDescription: '只有仍持有管理角色的成员可以使用这条委派。',
    invalidate,
    refreshAuth: true,
    onSuccess: closeAll,
  })

  const updateMutation = useApiMutation({
    mutationFn: (payload: { reason: string; draft: Draft; item: OrgDelegation }) => {
      const body: UpdateOrgDelegationRequest = {
        delegation_id: payload.item.id ?? '',
        actions: payload.draft.actions,
        grant_ceiling: payload.draft.ceiling,
        target_user_scope: payload.draft.userScope.length > 0
          ? { user_ids: payload.draft.userScope }
          : { all: true },
        starts_at: toRFC3339(payload.draft.startsAt),
        expires_at: toRFC3339(payload.draft.expiresAt),
        expected_revision: payload.item.revision ?? '0',
        reason: payload.reason,
        expected_policy_revision: policyRevision,
      }
      return api.orgs.updateDelegation(orgId, payload.item.id ?? '', body)
    },
    successMessage: '委派已更新',
    invalidate,
    refreshAuth: true,
    onSuccess: closeAll,
  })

  const revokeMutation = useApiMutation({
    mutationFn: (payload: { reason: string; item: OrgDelegation }) =>
      api.orgs.revokeDelegation(orgId, payload.item.id ?? '', {
        expected_revision: payload.item.revision ?? '0',
        reason: payload.reason,
        expected_policy_revision: policyRevision,
      }),
    successMessage: '委派已撤销',
    successDescription: '已授出的角色分配不会被自动回滚。',
    invalidate,
    refreshAuth: true,
    onSuccess: closeAll,
  })

  const openCreate = () => {
    setFormError(null)
    setManagerRole('')
    setTargetRole('')
    setActions(['assign'])
    setStartsAt('')
    setExpiresAt('')
    setScopeAll(true)
    setSelectedUsers([])
    setDialog({ mode: 'create' })
  }

  const openUpdate = (item: OrgDelegation) => {
    setFormError(null)
    setManagerRole(item.manager_role_id ?? '')
    setTargetRole(item.target_role_id ?? '')
    setActions(item.actions ?? ['assign'])
    setStartsAt(toLocalInput(item.starts_at))
    setExpiresAt(toLocalInput(item.expires_at))
    const scope = item.target_user_scope
    const scopedUsers = scope?.user_ids ?? []
    setScopeAll(!scope || scope.all === true || scopedUsers.length === 0)
    setSelectedUsers(scopedUsers)
    setDialog({ mode: 'update', item })
  }

  const validate = (): string | null => {
    if (!managerRole || !targetRole) return '请选择管理角色和目标角色'
    if (dialog?.mode === 'create' && managerRole === targetRole) {
      return '管理角色不能与目标角色相同'
    }
    if (actions.length === 0) return '请至少选择一个动作'
    if (!scopeAll && selectedUsers.length === 0) {
      return '请选择至少一个目标用户，或改为全部成员'
    }
    if (ceiling.length === 0) {
      return '目标角色没有可授予的权限，请先为其配置授权'
    }
    return null
  }

  const submit = () => {
    const error = validate()
    if (error) {
      setFormError(error)
      return
    }
    const draft: Draft = {
      managerRole, targetRole, actions: [...actions], ceiling, startsAt, expiresAt,
      userScope: scopeAll ? [] : [...selectedUsers],
    }
    if (dialog?.mode === 'update') {
      const item = dialog.item
      setConfirm({
        title: '保存委派变更',
        description: '变更理由会写入组织审计，并推进策略版本。',
        confirmLabel: '保存',
        run: (reason) => updateMutation.mutateAsync({ reason, draft, item }),
      })
    } else {
      setConfirm({
        title: '创建组织委派',
        description: '委派只放宽目标角色的分配能力，不会授予管理角色、权限或角色本身的修改权。',
        confirmLabel: '创建',
        run: (reason) => createMutation.mutateAsync({ reason, draft }),
      })
    }
  }

  const askRevoke = (item: OrgDelegation) => {
    setConfirm({
      title: '撤销组织委派',
      description: '撤销立即生效；已通过该委派授出的角色分配会保留，需要人工复核。',
      confirmLabel: '撤销',
      danger: true,
      run: (reason) => revokeMutation.mutateAsync({ reason, item }),
    })
  }

  const busy = createMutation.isPending || updateMutation.isPending || revokeMutation.isPending
  const items = delegationsQuery.data?.items ?? []

  return (
    <Card>
      <CardHeader
        title="组织内委派"
        description="把某个角色的分配能力交给持有管理角色的成员。委派只在本组织内生效，平台委派与组织委派互不通用。"
        actions={
          canManage ? (
            <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />} onClick={openCreate}>
              新建委派
            </Button>
          ) : null
        }
      />
      <QueryBoundary query={delegationsQuery} loadingLabel="读取组织委派…">
        {items.length === 0 ? (
          <EmptyState
            title="尚未定义委派"
            description="未定义委派时，成员只能授予自己已经持有的能力。"
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>管理角色</TH>
                <TH>目标角色</TH>
                <TH>动作</TH>
                <TH>有效期</TH>
                <TH>状态</TH>
                <TH />
              </TR>
            </THead>
            <TBody>
              {items.map((d) => (
                <TR key={d.id}>
                  <TD>{rolesById.get(d.manager_role_id ?? '')?.name ?? d.manager_role_id}</TD>
                  <TD>{rolesById.get(d.target_role_id ?? '')?.name ?? d.target_role_id}</TD>
                  <TD>{(d.actions ?? []).map((a) => (a === 'assign' ? '分配' : a === 'revoke' ? '撤销' : a)).join(' / ')}</TD>
                  <TD>{d.expires_at ? `至 ${d.expires_at.slice(0, 10)}` : '长期有效'}</TD>
                  <TD>{d.revoked ? '已撤销' : '生效中'}</TD>
                  <TD>
                    {canManage && !d.revoked ? (
                      <div className="flex gap-1">
                        <Button size="sm" variant="ghost" icon={<Pencil className="h-3.5 w-3.5" />} onClick={() => openUpdate(d)}>
                          编辑
                        </Button>
                        <Button size="sm" variant="ghost" icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => askRevoke(d)}>
                          撤销
                        </Button>
                      </div>
                    ) : null}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </QueryBoundary>

      {!canManage ? (
        <InlineAlert tone="info">只有组织所有者可以管理委派；其他成员可查看。</InlineAlert>
      ) : null}

      <Dialog open={dialog !== null} onClose={closeAll} title={dialog?.mode === 'update' ? '编辑委派' : '新建委派'}>
        <div className="space-y-3">
          <Field label="管理角色" htmlFor="dlg-manager" hint="只有当前持有该角色的成员能使用这条委派">
            <Select
              id="dlg-manager"
              value={managerRole}
              disabled={dialog?.mode === 'update'}
              onChange={(event) => setManagerRole(event.target.value)}
            >
              <option value="">请选择角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>{role.name}（{role.code}）</option>
              ))}
            </Select>
          </Field>
          <Field label="目标角色" htmlFor="dlg-target" hint="委派上限自动取该角色当前持有的权限">
            <Select
              id="dlg-target"
              value={targetRole}
              disabled={dialog?.mode === 'update'}
              onChange={(event) => setTargetRole(event.target.value)}
            >
              <option value="">请选择角色</option>
              {roles.map((role) => (
                <option key={role.id} value={role.id}>{role.name}（{role.code}）</option>
              ))}
            </Select>
          </Field>
          <Field label="允许的动作">
            <div className="flex gap-4">
              {[
                { value: 'assign', label: '分配' },
                { value: 'revoke', label: '撤销' },
              ].map((option) => (
                <label key={option.value} className="flex items-center gap-2 text-sm text-slate-700">
                  <input
                    type="checkbox"
                    checked={actions.includes(option.value)}
                    onChange={(event) =>
                      setActions((prev) =>
                        event.target.checked ? [...prev, option.value] : prev.filter((x) => x !== option.value),
                      )
                    }
                  />
                  {option.label}
                </label>
              ))}
            </div>
          </Field>
          <Field label="目标用户范围" hint="限定这条委派能用于哪些成员的授权；服务端每次分配都会比对">
            <div className="space-y-1">
              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input type="radio" checked={scopeAll} onChange={() => setScopeAll(true)} />
                全部成员（含后续加入）
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input type="radio" checked={!scopeAll} onChange={() => setScopeAll(false)} />
                指定成员
              </label>
              {!scopeAll ? (
                <div className="max-h-40 space-y-1 overflow-y-auto pl-6">
                  {(membersQuery.data?.items ?? []).map((m) => {
                    const uid = m.user_id ?? ''
                    return (
                      <label key={uid || m.username} className="flex items-center gap-2 text-sm text-slate-700">
                        <input
                          type="checkbox"
                          checked={selectedUsers.includes(uid)}
                          onChange={(event) =>
                            setSelectedUsers((prev) =>
                              event.target.checked ? [...prev, uid] : prev.filter((x) => x !== uid),
                            )
                          }
                        />
                        {m.display_name || m.username}
                        <span className="text-slate-400">{m.username}</span>
                      </label>
                    )
                  })}
                  {(membersQuery.data?.items ?? []).length === 0 ? (
                    <p className="text-xs text-slate-500">本组织暂无成员。</p>
                  ) : null}
                </div>
              ) : null}
            </div>
          </Field>
          <Field label="生效时间" htmlFor="dlg-starts" hint="留空表示立即生效">
            <Input id="dlg-starts" type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} />
          </Field>
          <Field label="失效时间" htmlFor="dlg-expires" hint="留空表示长期有效；委派不能授权超出自身的有效期">
            <Input id="dlg-expires" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          </Field>
          <p className="text-sm text-slate-500">
            授权上限（自动带出 {ceiling.length} 项）：
            {ceiling.length > 0 ? ceiling.map((c) => c.operation).join('、') : '目标角色暂无授权'}
          </p>
          {formError ? <InlineAlert tone="danger">{formError}</InlineAlert> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={closeAll}>取消</Button>
            <Button variant="primary" onClick={submit}>下一步</Button>
          </div>
        </div>
      </Dialog>

      <ReasonDialog
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        onConfirm={(reason) => {
          if (!confirm) return
          void confirm.run(reason).catch((error) => setFormError(errorMessage(error)))
        }}
        title={confirm?.title ?? ''}
        description={confirm?.description ?? ''}
        confirmLabel={confirm?.confirmLabel ?? '确认'}
        tone={confirm?.danger ? 'danger' : undefined}
        busy={busy}
        error={formError}
      />
    </Card>
  )
}
