import { Plus, Trash2 } from 'lucide-react'
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
import type { Organization, OrgConstraint, OrgRole } from '../../lib/types'

// Organization-scoped segregation of duties.
//
// The behaviour worth understanding is the acknowledgement step. A constraint
// that invalidates existing assignments locks those members out of the
// organization on their **next request**, not at a later login: organization
// permissions are recomputed per request. The server therefore refuses such a
// write until the caller repeats it with acknowledge_violations, and this tab
// uses that refusal to show the count before anything changes.

type ConstraintKind = 'mutual_exclusion' | 'max_roles'

const KIND_LABEL: Record<ConstraintKind, string> = {
  mutual_exclusion: '互斥角色对',
  max_roles: '角色数量上限',
}

export function OrganizationSodTab({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const constraintsQuery = useQuery({
    queryKey: ['orgs', orgId, 'constraints'],
    queryFn: () => api.orgs.listConstraints(orgId),
    retry: false,
  })
  const rolesQuery = useQuery({
    queryKey: ['orgs', orgId, 'roles'],
    queryFn: () => api.orgs.listRoles(orgId),
    retry: false,
  })

  const { authorization } = useAuth()
  const canManage = org.role === 'owner'
  const [drafting, setDrafting] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [deleting, setDeleting] = useState<OrgConstraint | null>(null)
  const [violationCount, setViolationCount] = useState<number | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pendingReason, setPendingReason] = useState('')

  const [kind, setKind] = useState<ConstraintKind>('mutual_exclusion')
  const [name, setName] = useState('')
  const [maxCount, setMaxCount] = useState('1')
  const [selected, setSelected] = useState<string[]>([])

  const rolesById = useMemo(() => {
    const map = new Map<string, OrgRole>()
    for (const role of rolesQuery.data?.items ?? []) {
      if (role.id) map.set(role.id, role)
    }
    return map
  }, [rolesQuery.data])

  const customRoles = useMemo(
    () => (rolesQuery.data?.items ?? []).filter((role) => !role.builtin),
    [rolesQuery.data],
  )

  // The policy revision is the IAM authorization revision, not the
  // organization record's revision. The server compares it against
  // PolicyRevision(), so quoting the org revision would fail every write with
  // POLICY_CONFLICT the moment the two diverge.
  const policyRevision = authorization?.policy_revision ?? '0'

  const saveConstraint = useApiMutation({
    mutationFn: (payload: {
      reason: string
      acknowledge: boolean
    }) =>
      api.orgs.createConstraint(orgId, {
        id: orgId,
        kind,
        name,
        role_ids: selected,
        // Proto int64 is serialised as a string; sending a number would be
        // silently coerced by the server but fails the generated types.
        max_count: kind === 'max_roles' ? String(Number(maxCount) || 0) : '0',
        enabled: true,
        reason: payload.reason,
        expected_policy_revision: policyRevision,
        acknowledge_violations: payload.acknowledge,
      }),
    successMessage: '职责分离规则已保存',
    successDescription: '规则仅在本组织内生效，对后续授权立即生效。',
    invalidate: [['orgs', orgId, 'constraints']],
    // A write advances the server's policy revision. Without refetching the
    // authorization projection the next write still quotes the previous
    // revision and fails with POLICY_CONFLICT -- so creating two rules in a row
    // could never work.
    refreshAuth: true,
    onSuccess: () => {
      closeAll()
    },
  })

  const removeConstraint = useApiMutation({
    mutationFn: (payload: { reason: string }) =>
      api.orgs.deleteConstraint(orgId, deleting?.id ?? '', {
        expected_revision: deleting?.revision ?? '0',
        reason: payload.reason,
        expected_policy_revision: policyRevision,
      }),
    successMessage: '规则已删除',
    successDescription: '已生效的授权不会被撤销。',
    invalidate: [['orgs', orgId, 'constraints']],
    // Same reason as the create path: deletion bumps the policy revision too.
    refreshAuth: true,
    onSuccess: () => setDeleting(null),
  })

  const closeAll = () => {
    setDrafting(false)
    setConfirming(false)
    setViolationCount(null)
    setPendingReason('')
    setFormError(null)
    setKind('mutual_exclusion')
    setName('')
    setMaxCount('1')
    setSelected([])
  }

  const validate = (): string | null => {
    if (!name.trim()) return '请填写规则名称'
    if (selected.length === 0) return '请选择至少一个角色'
    if (kind === 'mutual_exclusion' && selected.length < 2) {
      return '互斥角色对至少需要两个角色'
    }
    if (kind === 'max_roles') {
      const n = Number(maxCount)
      // The server rejects max_count <= 0 (validateConstraint), and the design
      // deleted the "0 means built-in roles only" reading: the count is scoped
      // to the selected roles, so 0 has no meaning. Offering it here only led
      // the user into a save that can never succeed.
      if (!Number.isInteger(n) || n < 1) return '角色数量上限必须为正整数'
    }
    return null
  }

  const openDraft = () => {
    closeAll()
    setDrafting(true)
  }

  const toConfirm = () => {
    const error = validate()
    if (error) {
      setFormError(error)
      return
    }
    setFormError(null)
    setDrafting(false)
    setConfirming(true)
  }

  // The first attempt never acknowledges. A 409 with the pending reason means
  // existing assignments would break, so the count is surfaced and the user has
  // to decide explicitly.
  const submit = async (reason: string, acknowledge: boolean) => {
    setPendingReason(reason)
    try {
      await saveConstraint.mutateAsync({ reason, acknowledge })
    } catch (error) {
      const pending =
        typeof error === 'object' &&
        error !== null &&
        'reason' in error &&
        (error as { reason?: string }).reason ===
          'ORGANIZATION_POLICY_VIOLATIONS_PENDING'
      if (!pending) {
        setFormError(errorMessage(error))
        setConfirming(false)
        setDrafting(true)
        return
      }
      // The server refuses to tell us the exact count on the conflict (the
      // message is fixed), so re-run the same write with acknowledgement only
      // after the manager confirms. Show a generic, accurate warning here.
      setViolationCount(-1)
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="职责分离"
          description="限制本组织内可以同时持有的角色组合。规则只在本组织内生效，不会放宽平台策略。"
          actions={
            canManage ? (
              <Button
                size="sm"
                variant="primary"
                icon={<Plus className="h-3.5 w-3.5" />}
                onClick={openDraft}
              >
                新建规则
              </Button>
            ) : null
          }
        />
        <QueryBoundary query={constraintsQuery} loadingLabel="读取职责分离规则…">
          {(constraintsQuery.data?.items ?? []).length === 0 ? (
            <EmptyState
              title="尚未定义规则"
              description={
                canManage
                  ? '定义互斥角色对或角色数量上限，例如"审批"与"付款"不能由同一人同时持有。'
                  : '组织所有者尚未为本组织定义职责分离规则。'
              }
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>类型</TH>
                  <TH>角色 / 上限</TH>
                  <TH>状态</TH>
                  <TH />
                </TR>
              </THead>
              <TBody>
                {(constraintsQuery.data?.items ?? []).map((c) => (
                  <TR key={c.id}>
                    <TD>{c.name}</TD>
                    <TD>{KIND_LABEL[c.kind as ConstraintKind] ?? c.kind}</TD>
                    <TD>
                      {c.kind === 'max_roles'
                        ? // The cap counts only the listed roles, so name both
                          // sides. "最多 N 个自定义角色" read as a whole-tenant
                          // total and was wrong for every constraint that did
                          // not list every role.
                          `所选 ${(c.role_ids ?? []).length} 个角色中最多 ${c.max_count ?? 0} 个`
                        : (c.role_ids ?? [])
                            .map((id) => rolesById.get(id ?? '')?.name ?? id)
                            .join(' / ')}
                    </TD>
                    <TD>{c.enabled ? '启用' : '停用'}</TD>
                    <TD>
                      {canManage ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          icon={<Trash2 className="h-3.5 w-3.5" />}
                          onClick={() => setDeleting(c)}
                        >
                          删除
                        </Button>
                      ) : null}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      {!canManage ? (
        <InlineAlert tone="info">
          只有组织所有者可以修改职责分离规则；其他成员可查看。
        </InlineAlert>
      ) : null}

      <Dialog
        open={drafting}
        onClose={closeAll}
        title="新建职责分离规则"
      >
        <div className="space-y-3">
          <Field label="类型" htmlFor="sod-kind">
            <Select
              id="sod-kind"
              value={kind}
              onChange={(event) => {
                setKind(event.target.value as ConstraintKind)
                setSelected([])
              }}
            >
              <option value="mutual_exclusion">互斥角色对</option>
              <option value="max_roles">角色数量上限</option>
            </Select>
          </Field>
          <Field label="名称" htmlFor="sod-name" required>
            <Input
              id="sod-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="例如：审批与付款不得同一人"
            />
          </Field>
          {kind === 'max_roles' ? (
            <Field
              label="所选角色中最多可同时持有"
              htmlFor="sod-max"
              hint="只统计下方勾选的角色，至少为 1；未勾选的内置角色不参与计数"
            >
              <Input
                id="sod-max"
                value={maxCount}
                inputMode="numeric"
                onChange={(event) => setMaxCount(event.target.value)}
              />
            </Field>
          ) : null}
          <Field
            label={kind === 'max_roles' ? '计入的角色' : '互斥角色'}
            hint="只能选择本组织的自定义角色；内置角色由成员角色决定"
          >
            <div className="space-y-1">
              {customRoles.length === 0 ? (
                <p className="text-sm text-slate-500">
                  本组织还没有自定义角色，请先在「角色与授权」中创建。
                </p>
              ) : (
                customRoles.map((role) => (
                  <label
                    key={role.id}
                    className="flex items-center gap-2 text-sm text-slate-700"
                  >
                    <input
                      type="checkbox"
                      checked={selected.includes(role.id ?? '')}
                      onChange={(event) => {
                        const id = role.id ?? ''
                        setSelected((prev) =>
                          event.target.checked
                            ? [...prev, id]
                            : prev.filter((x) => x !== id),
                        )
                      }}
                    />
                    {role.name}
                    <span className="text-slate-400">{role.code}</span>
                  </label>
                ))
              )}
            </div>
          </Field>
          {formError ? <InlineAlert tone="danger">{formError}</InlineAlert> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={closeAll}>
              取消
            </Button>
            <Button variant="primary" onClick={toConfirm}>
              下一步
            </Button>
          </div>
        </div>
      </Dialog>

      <ReasonDialog
        open={confirming && violationCount === null}
        onClose={() => {
          setConfirming(false)
          setDrafting(true)
        }}
        onConfirm={(reason) => void submit(reason, false)}
        title="保存职责分离规则"
        description="变更理由会写入组织审计。"
        confirmLabel="保存"
        busy={saveConstraint.isPending}
      />

      <ReasonDialog
        open={violationCount !== null}
        onClose={closeAll}
        onConfirm={(reason) => void submit(pendingReason || reason, true)}
        title="该规则会使现有成员违规"
        description={
          <>
            保存后，角色组合不再合规的成员将<strong>立即</strong>失去本组织访问权限
            （权限在每次请求时重算，不会等到下次登录）。建议先核对成员列表。
          </>
        }
        confirmLabel="确认并保存"
        tone="danger"
        busy={saveConstraint.isPending}
        requireReason={false}
      />

      <ReasonDialog
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        onConfirm={(reason) => removeConstraint.mutate({ reason })}
        title="删除职责分离规则"
        description={`将删除规则「${deleting?.name ?? ''}」。已生效的授权不会被撤销。`}
        confirmLabel="删除"
        tone="danger"
        busy={removeConstraint.isPending}
      />
    </div>
  )
}
