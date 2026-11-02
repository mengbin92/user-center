import {
  ArrowLeft,
  Copy,
  Eye,
  GitBranch,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
  Users,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button, IconButton } from '../../components/button'
import {
  Card,
  CardContent,
  EmptyState,
  InlineAlert,
  LoadingBlock,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select, Textarea } from '../../components/input'
import { ErrorPanel, QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import {
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { Tabs } from '../../components/tabs'
import { useToast } from '../../components/toast'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { formatDateTime, splitList } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Grant, PreviewReply } from '../../lib/types'
import {
  InfoGrid,
  PermissionSelectOptions,
  useAllRoles,
  usePermissionCatalog,
} from './common'

type ScopeType = 'all' | 'self' | 'user_ids'

type GrantRow = {
  key: string
  operation: string
  effect: 'allow' | 'deny'
  scopeType: ScopeType
  userIds: string
}

type PendingAction = {
  title: string
  description?: string
  confirmLabel: string
  tone?: 'primary' | 'danger'
  run: (reason: string) => void
}

function newKey(): string {
  return typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : `row-${Math.random().toString(16).slice(2)}`
}

function toRows(grants: Grant[] | undefined): GrantRow[] {
  return (grants ?? []).map((grant) => ({
    key: newKey(),
    operation: grant.operation ?? '',
    effect: grant.effect === 'deny' ? 'deny' : 'allow',
    scopeType: grant.scope?.all
      ? 'all'
      : grant.scope?.self
        ? 'self'
        : 'user_ids',
    userIds: (grant.scope?.user_ids ?? []).join(', '),
  }))
}

function toGrant(row: GrantRow): Grant {
  if (row.scopeType === 'all') {
    return { operation: row.operation, effect: row.effect, scope: { all: true } }
  }
  if (row.scopeType === 'self') {
    return { operation: row.operation, effect: row.effect, scope: { self: true } }
  }
  return {
    operation: row.operation,
    effect: row.effect,
    scope: { user_ids: splitList(row.userIds) },
  }
}

export function AdminRoleDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { can, authorization } = useAuth()
  const toast = useToast()
  const [tab, setTab] = useState('grants')
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [editOpen, setEditOpen] = useState(false)
  const [copyOpen, setCopyOpen] = useState(false)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [preview, setPreview] = useState<PreviewReply | null>(null)

  const roleQuery = useQuery({
    queryKey: ['admin', 'iam', 'role', id],
    queryFn: () => api.iam.getRole(id),
    enabled: Boolean(id),
    retry: false,
  })
  const role = roleQuery.data

  const permsQuery = useQuery({
    queryKey: ['admin', 'iam', 'role', id, 'permissions'],
    queryFn: () => api.iam.rolePermissions(id),
    enabled: Boolean(id),
    retry: false,
  })
  const inheritanceQuery = useQuery({
    queryKey: ['admin', 'iam', 'role', id, 'inheritance'],
    queryFn: () => api.iam.roleInheritance(id),
    enabled: Boolean(id),
    retry: false,
  })
  const membersQuery = useQuery({
    queryKey: ['admin', 'iam', 'role', id, 'members'],
    queryFn: () => api.iam.roleMembers(id),
    enabled: Boolean(id),
    retry: false,
  })

  const rolesQuery = useAllRoles()
  const catalogQuery = usePermissionCatalog()

  const [grants, setGrants] = useState<GrantRow[]>([])
  const [inherits, setInherits] = useState<Set<string>>(new Set())
  const [roleName, setRoleName] = useState('')
  const [roleDescription, setRoleDescription] = useState('')
  const [roleMaxMembers, setRoleMaxMembers] = useState('')
  const [roleEditReason, setRoleEditReason] = useState('')
  const [copyCode, setCopyCode] = useState('')
  const [copyName, setCopyName] = useState('')
  const [copyReason, setCopyReason] = useState('')

  useEffect(() => {
    if (permsQuery.data) setGrants(toRows(permsQuery.data.grants))
  }, [permsQuery.data])

  useEffect(() => {
    if (inheritanceQuery.data) {
      setInherits(new Set(inheritanceQuery.data.inherits ?? []))
    }
  }, [inheritanceQuery.data])

  useEffect(() => {
    if (!role) return
    setRoleName(role.name ?? '')
    setRoleDescription(role.description ?? '')
    setRoleMaxMembers(role.max_members ?? '')
  }, [role])

  const policyRevision = authorization?.policy_revision ?? ''

  const invalidateRole = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['admin', 'iam', 'role', id] }),
      queryClient.invalidateQueries({ queryKey: ['admin', 'iam', 'roles'] }),
    ])
  }

  const saveGrants = useApiMutation({
    mutationFn: (reason: string) =>
      api.iam.putRolePermissions(id, {
        id,
        grants: grants
          .filter((row) => row.operation)
          .map((row) => toGrant(row)),
        expected_revision: permsQuery.data?.revision ?? '0',
        expected_policy_revision: policyRevision,
        reason,
      }),
    successMessage: '角色 grants 已更新',
    successDescription: '授权策略 revision 已递增。',
    refreshAuth: true,
    onSuccess: async () => {
      setPending(null)
      await invalidateRole()
    },
  })

  const saveInheritance = useApiMutation({
    mutationFn: (reason: string) =>
      api.iam.putRoleInheritance(id, {
        id,
        inherits: [...inherits],
        expected_revision: inheritanceQuery.data?.revision ?? '0',
        expected_policy_revision: policyRevision,
        reason,
      }),
    successMessage: '角色继承已更新',
    refreshAuth: true,
    onSuccess: async () => {
      setPending(null)
      await invalidateRole()
    },
  })

  const updateRole = useApiMutation({
    mutationFn: () =>
      api.iam.updateRole(id, {
        id,
        name: roleName.trim(),
        description: roleDescription.trim(),
        max_members: roleMaxMembers.trim() || undefined,
        expected_revision: role?.revision ?? '0',
        reason: roleEditReason.trim() || 'update role profile',
      }),
    successMessage: '角色资料已更新',
    onSuccess: async () => {
      setEditOpen(false)
      await invalidateRole()
    },
  })

  const setStatus = useApiMutation({
    mutationFn: (input: { status: string; reason: string }) =>
      api.iam.setRoleStatus(id, {
        id,
        status: input.status,
        expected_revision: role?.revision ?? '0',
        reason: input.reason,
      }),
    successMessage: '角色状态已更新',
    refreshAuth: true,
    onSuccess: async () => {
      setPending(null)
      await invalidateRole()
    },
  })

  const archiveRole = useApiMutation({
    mutationFn: (reason: string) =>
      api.iam.archiveRole(id, {
        id,
        expected_revision: role?.revision ?? '0',
        reason,
      }),
    successMessage: '角色已归档',
    refreshAuth: true,
    onSuccess: async () => {
      setPending(null)
      await invalidateRole()
    },
  })

  const copyRole = useApiMutation({
    mutationFn: () =>
      api.iam.copyRole(id, {
        id,
        code: copyCode.trim(),
        name: copyName.trim(),
        reason: copyReason.trim(),
      }),
    successMessage: '角色已复制',
    onSuccess: async (created) => {
      setCopyOpen(false)
      await invalidateRole()
      if (created.id) navigate(`/admin/iam/roles/${created.id}`)
    },
  })

  const runPreview = useApiMutation({
    mutationFn: () =>
      api.iam.previewRoleChange(id, {
        id,
        grants: grants.filter((row) => row.operation).map((row) => toGrant(row)),
        inherits: [...inherits],
      }),
    onSuccess: (data) => {
      setPreview(data)
      setPreviewOpen(true)
    },
  })

  const pendingBusy =
    saveGrants.isPending ||
    saveInheritance.isPending ||
    setStatus.isPending ||
    archiveRole.isPending

  const roleTabs = [
    { key: 'grants', label: '权限 grants', count: grants.length },
    { key: 'inheritance', label: '继承', count: inherits.size },
    { key: 'members', label: '成员', count: membersQuery.data?.items?.length },
    { key: 'overview', label: '概览' },
  ]

  const otherRoles = useMemo(
    () => (rolesQuery.data?.items ?? []).filter((item) => item.id !== id),
    [rolesQuery.data, id],
  )

  const updateGrant = (key: string, patch: Partial<GrantRow>) => {
    setGrants((current) =>
      current.map((row) => (row.key === key ? { ...row, ...patch } : row)),
    )
  }

  const removeGrant = (key: string) => {
    setGrants((current) => current.filter((row) => row.key !== key))
  }

  const toggleInherit = (roleId: string) => {
    setInherits((current) => {
      const next = new Set(current)
      if (next.has(roleId)) next.delete(roleId)
      else next.add(roleId)
      return next
    })
  }

  const openStatus = () => {
    if (!role) return
    const nextStatus = role.status === 'active' ? 'disabled' : 'active'
    setPending({
      title: nextStatus === 'active' ? '启用角色' : '停用角色',
      description:
        nextStatus === 'active'
          ? '启用后持有该角色的会话将重新获得对应权限。'
          : '停用后该角色的权限不再生效，但保留分配与审计。',
      confirmLabel: nextStatus === 'active' ? '确认启用' : '确认停用',
      tone: nextStatus === 'active' ? 'primary' : 'danger',
      run: (reason) => setStatus.mutate({ status: nextStatus, reason }),
    })
  }

  const openArchive = () => {
    setPending({
      title: '归档角色',
      description: '归档后角色不可再分配，权限立即失效。操作写入审计。',
      confirmLabel: '确认归档',
      tone: 'danger',
      run: (reason) => archiveRole.mutate(reason),
    })
  }

  const validateGrants = (): string | null => {
    for (const row of grants) {
      if (!row.operation && row.scopeType === 'user_ids' && row.userIds.trim()) {
        return '存在未选择操作权限的 grant 行'
      }
      if (row.operation && row.scopeType === 'user_ids' && !splitList(row.userIds).length) {
        return `权限 ${row.operation} 指定了 user_ids 范围但未填写用户 ID`
      }
    }
    return null
  }

  const openSaveGrants = () => {
    const error = validateGrants()
    if (error) {
      toast.error('无法保存 grants', error)
      return
    }
    setPending({
      title: '保存角色 grants',
      description:
        '将覆盖该角色的全部 grants。提交时携带权限 revision 与授权策略 revision。',
      confirmLabel: '保存 grants',
      run: (reason) => saveGrants.mutate(reason),
    })
  }

  const openSaveInheritance = () => {
    setPending({
      title: '保存角色继承',
      description: '角色会继承所选角色的 grants。禁止循环继承。',
      confirmLabel: '保存继承',
      run: (reason) => saveInheritance.mutate(reason),
    })
  }

  if (!id) return <InlineAlert tone="danger">缺少角色 ID</InlineAlert>

  return (
    <div className="space-y-4">
      <PageTitle title={role?.name || '角色详情'} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Link
          to="/admin/iam/roles"
          className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 hover:text-slate-800"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          返回角色列表
        </Link>
        <Button
          size="xs"
          variant="ghost"
          onClick={() => {
            void roleQuery.refetch()
            void permsQuery.refetch()
            void inheritanceQuery.refetch()
            void membersQuery.refetch()
          }}
          loading={roleQuery.isFetching}
          icon={<RefreshCw className="h-3 w-3" />}
        >
          刷新
        </Button>
      </div>

      <QueryBoundary query={roleQuery} loadingLabel="读取角色…">
        {role ? (
          <>
            <Card>
              <div className="flex flex-wrap items-start justify-between gap-3 p-4">
                <div className="flex items-start gap-3">
                  <span className="grid h-11 w-11 place-items-center rounded-xl bg-indigo-50 text-indigo-600">
                    <ShieldCheck className="h-5 w-5" />
                  </span>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-base font-semibold text-slate-900">
                        {role.name}
                      </h1>
                      <StatusBadge status={role.status} />
                      {role.builtin ? (
                        <Badge tone="violet">内置角色</Badge>
                      ) : (
                        <Badge tone="outline">自定义角色</Badge>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-slate-500">
                      <span className="font-mono">{role.code}</span>
                      <span className="font-mono">id={role.id}</span>
                      <span>revision {role.revision}</span>
                      <span>成员上限 {role.max_members || '不限'}</span>
                    </div>
                    {role.description ? (
                      <p className="mt-1 max-w-2xl text-[11px] text-slate-500">
                        {role.description}
                      </p>
                    ) : null}
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {can('iam.role.update') ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        setRoleEditReason('')
                        setEditOpen(true)
                      }}
                    >
                      编辑资料
                    </Button>
                  ) : null}
                  {can('iam.role.update') &&
                  role.status !== 'archived' &&
                  role.code !== 'root' ? (
                    <Button size="sm" variant="secondary" onClick={openStatus}>
                      {role.status === 'active' ? '停用' : '启用'}
                    </Button>
                  ) : role.code === 'root' ? (
                    <Badge tone="neutral">root 受保护</Badge>
                  ) : null}
                  {can('iam.role.create') ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        setCopyCode(`${role.code}_copy`)
                        setCopyName(`${role.name}（副本）`)
                        setCopyReason('')
                        setCopyOpen(true)
                      }}
                      icon={<Copy className="h-3.5 w-3.5" />}
                    >
                      复制
                    </Button>
                  ) : null}
                  {can('iam.role.update') &&
                  role.status !== 'archived' &&
                  !role.builtin ? (
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={openArchive}
                      icon={<Trash2 className="h-3.5 w-3.5" />}
                    >
                      归档
                    </Button>
                  ) : null}
                </div>
              </div>
            </Card>

            <Card>
              <div className="px-3 pt-2">
                <Tabs tabs={roleTabs} value={tab} onChange={setTab} />
              </div>

              {tab === 'grants' ? (
                <CardContent className="space-y-3">
                  {catalogQuery.isError ? (
                    <InlineAlert tone="warning" title="无法读取权限目录">
                      缺少 iam.permission.read 权限时无法选择新的操作权限，仍可查看已保存的 grants。
                    </InlineAlert>
                  ) : null}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-800">
                        权限 grants
                      </div>
                      <p className="text-[11px] text-slate-500">
                        显式 deny 优先于 allow。数据范围支持全部、仅本人或指定用户。
                      </p>
                    </div>
                    <div className="flex gap-1.5">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => runPreview.mutate(undefined)}
                        loading={runPreview.isPending}
                        disabled={!permsQuery.data}
                        icon={<Eye className="h-3.5 w-3.5" />}
                      >
                        预览影响
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() =>
                          setGrants((current) => [
                            ...current,
                            {
                              key: newKey(),
                              operation: '',
                              effect: 'allow',
                              scopeType: 'all',
                              userIds: '',
                            },
                          ])
                        }
                        icon={<Plus className="h-3.5 w-3.5" />}
                      >
                        添加 grant
                      </Button>
                      {can('iam.role.update') ? (
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={openSaveGrants}
                          disabled={!permsQuery.data}
                          icon={<Save className="h-3.5 w-3.5" />}
                        >
                          保存
                        </Button>
                      ) : null}
                    </div>
                  </div>

                  {permsQuery.isPending ? (
                    <LoadingBlock label="读取角色权限…" />
                  ) : permsQuery.isError ? (
                    <ErrorPanel
                      error={permsQuery.error}
                      onRetry={() => void permsQuery.refetch()}
                      compact
                    />
                  ) : grants.length === 0 ? (
                    <EmptyState
                      title="该角色没有 grants"
                      description="添加操作权限，或通过继承获得权限。"
                    />
                  ) : (
                    <div className="space-y-2">
                      {grants.map((row, index) => (
                        <div
                          key={row.key}
                          className="rounded-lg border border-slate-200 p-2.5"
                        >
                          <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_96px_110px_minmax(0,0.8fr)_32px]">
                            <Field label={index === 0 ? '操作权限' : undefined}>
                              <Select
                                value={row.operation}
                                onChange={(event) =>
                                  updateGrant(row.key, {
                                    operation: event.target.value,
                                  })
                                }
                              >
                                <option value="">选择操作权限</option>
                                <PermissionSelectOptions
                                  permissions={catalogQuery.data?.items}
                                />
                              </Select>
                            </Field>
                            <Field label={index === 0 ? '效果' : undefined}>
                              <Select
                                value={row.effect}
                                onChange={(event) =>
                                  updateGrant(row.key, {
                                    effect: event.target.value as 'allow' | 'deny',
                                  })
                                }
                              >
                                <option value="allow">允许</option>
                                <option value="deny">拒绝</option>
                              </Select>
                            </Field>
                            <Field label={index === 0 ? '数据范围' : undefined}>
                              <Select
                                value={row.scopeType}
                                onChange={(event) =>
                                  updateGrant(row.key, {
                                    scopeType: event.target.value as ScopeType,
                                  })
                                }
                              >
                                <option value="all">全部</option>
                                <option value="self">仅本人</option>
                                <option value="user_ids">指定用户</option>
                              </Select>
                            </Field>
                            <Field label={index === 0 ? '用户 ID（逗号分隔）' : undefined}>
                              <Input
                                value={row.userIds}
                                disabled={row.scopeType !== 'user_ids'}
                                onChange={(event) =>
                                  updateGrant(row.key, {
                                    userIds: event.target.value,
                                  })
                                }
                                placeholder="1, 2, 3"
                                className="font-mono text-[11px]"
                              />
                            </Field>
                            <div className="flex items-end pb-0.5">
                              <IconButton
                                label="移除 grant"
                                onClick={() => removeGrant(row.key)}
                                className="hover:bg-rose-50 hover:text-rose-600"
                              >
                                <X className="h-3.5 w-3.5" />
                              </IconButton>
                            </div>
                          </div>
                          {row.scopeType === 'user_ids' && row.operation ? (
                            <div className="mt-1 text-[10px] text-slate-400">
                              仅对列出的用户 ID 生效。
                            </div>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  )}

                  {!can('iam.role.update') ? (
                    <InlineAlert tone="warning">
                      当前账号缺少 iam.role.update 权限，无法保存 grants。
                    </InlineAlert>
                  ) : null}
                </CardContent>
              ) : null}

              {tab === 'inheritance' ? (
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-800">
                        角色继承
                      </div>
                      <p className="text-[11px] text-slate-500">
                        所选角色生效时，本角色会继承其 grants。服务端会拒绝循环。
                      </p>
                    </div>
                    {can('iam.role.update') ? (
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={openSaveInheritance}
                        disabled={!inheritanceQuery.data}
                        icon={<Save className="h-3.5 w-3.5" />}
                      >
                        保存继承
                      </Button>
                    ) : null}
                  </div>
                  {inheritanceQuery.isPending ? (
                    <LoadingBlock label="读取继承关系…" />
                  ) : inheritanceQuery.isError ? (
                    <ErrorPanel
                      error={inheritanceQuery.error}
                      onRetry={() => void inheritanceQuery.refetch()}
                      compact
                    />
                  ) : null}
                  {inheritanceQuery.isSuccess ? (
                    <>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {otherRoles.map((item) => (
                      <label
                        key={item.id}
                        className="flex cursor-pointer items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-xs hover:bg-slate-50"
                      >
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                          checked={inherits.has(item.id ?? '')}
                          onChange={() => toggleInherit(item.id ?? '')}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-medium text-slate-800">
                            {item.name}
                          </span>
                          <span className="block font-mono text-[10px] text-slate-400">
                            {item.code}
                          </span>
                        </span>
                        <StatusBadge status={item.status} />
                      </label>
                    ))}
                    {otherRoles.length === 0 ? (
                      <div className="text-xs text-slate-500">
                        没有可继承的其他角色。
                      </div>
                    ) : null}
                  </div>
                  {inherits.size > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      <span className="text-[11px] text-slate-500">将继承：</span>
                      {[...inherits].map((roleId) => {
                        const item = rolesQuery.data?.items?.find(
                          (entry) => entry.id === roleId,
                        )
                        return (
                          <Badge key={roleId} tone="info">
                            <GitBranch className="h-3 w-3" />
                            {item?.name || roleId}
                          </Badge>
                        )
                      })}
                    </div>
                  ) : null}
                    </>
                  ) : null}
                </CardContent>
              ) : null}

              {tab === 'members' ? (
                <CardContent>
                  <QueryBoundary query={membersQuery} loadingLabel="读取成员…">
                    {membersQuery.data?.items?.length ? (
                      <Table minWidth="min-w-[720px]">
                        <THead>
                          <TR>
                            <TH>用户</TH>
                            <TH>assignment</TH>
                            <TH>分配时间</TH>
                            <TH>过期时间</TH>
                            <TH>来源</TH>
                          </TR>
                        </THead>
                        <TBody>
                          {membersQuery.data.items.map((member) => (
                            <TR key={member.assignment_id}>
                              <TD>
                                <div className="text-xs font-medium text-slate-800">
                                  {member.display_name || member.username}
                                </div>
                                <div className="font-mono text-[10px] text-slate-400">
                                  @{member.username} · id={member.user_id}
                                </div>
                              </TD>
                              <TD className="font-mono text-[10px] text-slate-500">
                                {member.assignment_id}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {formatDateTime(member.assigned_at)}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {member.expires_at
                                  ? formatDateTime(member.expires_at)
                                  : '永久'}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {member.origin || '—'}
                              </TD>
                            </TR>
                          ))}
                        </TBody>
                      </Table>
                    ) : (
                      <EmptyState
                        title="暂无成员"
                        description="可以通过授权分配页把该角色授予用户。"
                        icon={Users}
                      />
                    )}
                  </QueryBoundary>
                </CardContent>
              ) : null}

              {tab === 'overview' ? (
                <CardContent className="space-y-4">
                  <InfoGrid
                    items={[
                      { label: '角色 ID', value: role.id, mono: true },
                      { label: '代码', value: role.code, mono: true },
                      { label: '名称', value: role.name },
                      { label: '状态', value: <StatusBadge status={role.status} /> },
                      {
                        label: '内置',
                        value: role.builtin ? '是（受保护）' : '否',
                      },
                      { label: '成员上限', value: role.max_members || '不限' },
                      { label: 'revision', value: role.revision, mono: true },
                      {
                        label: 'grants revision',
                        value: permsQuery.data?.revision ?? '—',
                        mono: true,
                      },
                      {
                        label: '权限策略 revision',
                        value: policyRevision || '—',
                        mono: true,
                      },
                    ]}
                  />
                  <div className="grid gap-2 sm:grid-cols-3">
                    <div className="rounded-lg border border-slate-200 p-3">
                      <div className="text-[11px] text-slate-500">grants</div>
                      <div className="text-lg font-semibold tabular-nums text-slate-900">
                        {role.grants?.length ?? 0}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 p-3">
                      <div className="text-[11px] text-slate-500">继承</div>
                      <div className="text-lg font-semibold tabular-nums text-slate-900">
                        {role.inherits?.length ?? 0}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 p-3">
                      <div className="text-[11px] text-slate-500">成员</div>
                      <div className="text-lg font-semibold tabular-nums text-slate-900">
                        {membersQuery.data?.items?.length ?? 0}
                      </div>
                    </div>
                  </div>
                  {role.builtin ? (
                    <InlineAlert tone="info" title="内置角色">
                      内置角色不可归档，部分字段可能受服务端保护。
                    </InlineAlert>
                  ) : null}
                </CardContent>
              ) : null}
            </Card>

            <Dialog
              open={editOpen}
              onClose={() => setEditOpen(false)}
              title="编辑角色资料"
              description="角色代码不可修改。提交时携带当前 revision。"
              size="md"
              bodyClassName="space-y-3"
              footer={
                <>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setEditOpen(false)}
                    disabled={updateRole.isPending}
                  >
                    取消
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => updateRole.mutate(undefined)}
                    loading={updateRole.isPending}
                    disabled={!roleName.trim()}
                  >
                    保存
                  </Button>
                </>
              }
            >
              <Field label="名称" htmlFor="role-edit-name" required>
                <Input
                  id="role-edit-name"
                  value={roleName}
                  onChange={(event) => setRoleName(event.target.value)}
                />
              </Field>
              <Field label="描述" htmlFor="role-edit-desc">
                <Textarea
                  id="role-edit-desc"
                  value={roleDescription}
                  onChange={(event) => setRoleDescription(event.target.value)}
                  rows={2}
                />
              </Field>
              <Field label="成员上限" htmlFor="role-edit-max" hint="留空不限制">
                <Input
                  id="role-edit-max"
                  value={roleMaxMembers}
                  onChange={(event) => setRoleMaxMembers(event.target.value)}
                  inputMode="numeric"
                />
              </Field>
              <Field label="操作原因" htmlFor="role-edit-reason">
                <Input
                  id="role-edit-reason"
                  value={roleEditReason}
                  onChange={(event) => setRoleEditReason(event.target.value)}
                  placeholder="可选，写入审计"
                />
              </Field>
            </Dialog>

            <Dialog
              open={copyOpen}
              onClose={() => setCopyOpen(false)}
              title="复制角色"
              description="复制会克隆 grants 与继承关系，并生成新角色。"
              size="md"
              bodyClassName="space-y-3"
              footer={
                <>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setCopyOpen(false)}
                    disabled={copyRole.isPending}
                  >
                    取消
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => copyRole.mutate(undefined)}
                    loading={copyRole.isPending}
                    disabled={!copyCode.trim() || !copyName.trim() || !copyReason.trim()}
                  >
                    复制角色
                  </Button>
                </>
              }
            >
              <Field label="新角色代码" htmlFor="copy-code" required>
                <Input
                  id="copy-code"
                  value={copyCode}
                  onChange={(event) => setCopyCode(event.target.value)}
                  className="font-mono"
                />
              </Field>
              <Field label="新角色名称" htmlFor="copy-name" required>
                <Input
                  id="copy-name"
                  value={copyName}
                  onChange={(event) => setCopyName(event.target.value)}
                />
              </Field>
              <Field label="操作原因" htmlFor="copy-reason" required>
                <Textarea
                  id="copy-reason"
                  value={copyReason}
                  onChange={(event) => setCopyReason(event.target.value)}
                  rows={2}
                />
              </Field>
            </Dialog>

            <Dialog
              open={previewOpen}
              onClose={() => setPreviewOpen(false)}
              title="角色变更预览"
              description="预览基于当前编辑中的 grants 与继承，不会写入任何数据。"
              size="lg"
              bodyClassName="space-y-3"
            >
              {preview ? (
                <>
                  <InfoGrid
                    items={[
                      {
                        label: '影响用户数',
                        value: preview.affected_user_count || '0',
                        mono: true,
                      },
                      {
                        label: '新增权限',
                        value: String(preview.permission_diff_added?.length ?? 0),
                      },
                      {
                        label: '移除权限',
                        value: String(preview.permission_diff_removed?.length ?? 0),
                      },
                    ]}
                  />
                  {preview.warnings?.length ? (
                    <div className="space-y-1">
                      <div className="text-[11px] font-medium text-amber-700">
                        警告
                      </div>
                      <ul className="list-disc space-y-1 pl-5 text-[11px] text-amber-700">
                        {preview.warnings.map((warning) => (
                          <li key={warning}>{warning}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <div className="mb-1 text-[11px] font-medium text-emerald-700">
                        新增权限
                      </div>
                      <div className="flex max-h-48 flex-wrap gap-1 overflow-y-auto rounded-md border border-slate-200 p-2">
                        {preview.permission_diff_added?.length ? (
                          preview.permission_diff_added.map((permission) => (
                            <Badge key={permission} tone="success">
                              {permission}
                            </Badge>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-400">无</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="mb-1 text-[11px] font-medium text-rose-700">
                        移除权限
                      </div>
                      <div className="flex max-h-48 flex-wrap gap-1 overflow-y-auto rounded-md border border-slate-200 p-2">
                        {preview.permission_diff_removed?.length ? (
                          preview.permission_diff_removed.map((permission) => (
                            <Badge key={permission} tone="danger">
                              {permission}
                            </Badge>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-400">无</span>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              ) : null}
            </Dialog>

            <ReasonDialog
              open={pending !== null}
              onClose={() => setPending(null)}
              onConfirm={(reason) => pending?.run(reason)}
              title={pending?.title ?? ''}
              description={pending?.description}
              confirmLabel={pending?.confirmLabel}
              tone={pending?.tone ?? 'danger'}
              busy={pendingBusy}
            />
          </>
        ) : (
          <EmptyState title="角色不存在" />
        )}
      </QueryBoundary>
    </div>
  )
}
