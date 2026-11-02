import {
  ArrowLeft,
  Ban,
  KeyRound,
  MonitorSmartphone,
  Pencil,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserCheck,
} from 'lucide-react'
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  EmptyState,
  InlineAlert,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
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
import { Tabs } from '../../components/tabs'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import {
  formatDate,
  formatDateTime,
  formatScopeCode,
  prettyJson,
} from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Assignment, AuditEvent, SessionInfo } from '../../lib/types'
import { InfoGrid, JsonBlock, ScopeBadge, roleById, useAllRoles } from './common'

type TabKey = 'profile' | 'security' | 'roles' | 'sessions' | 'audits'

type ReasonAction = {
  title: string
  description?: string
  confirmLabel: string
  tone?: 'primary' | 'danger'
  run: (reason: string) => void
  busy?: boolean
}

export function AdminUserDetailPage() {
  const { id = '' } = useParams()
  const queryClient = useQueryClient()
  const { can, authorization } = useAuth()
  const [tab, setTab] = useState<TabKey>('profile')
  const [reasonAction, setReasonAction] = useState<ReasonAction | null>(null)
  const [editOpen, setEditOpen] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [editReason, setEditReason] = useState('')
  const [auditDetailId, setAuditDetailId] = useState<string | null>(null)

  const rolesQuery = useAllRoles()

  const userQuery = useQuery({
    queryKey: ['admin', 'user', id],
    queryFn: () => api.admin.getUser(id),
    enabled: Boolean(id),
    retry: false,
  })
  const user = userQuery.data

  const assignmentsQuery = useQuery({
    queryKey: ['admin', 'user', id, 'assignments'],
    queryFn: () => api.admin.userRoles(id),
    enabled: Boolean(id) && can('iam.assignment.read'),
    retry: false,
  })

  const effectiveQuery = useQuery({
    queryKey: ['admin', 'user', id, 'effective'],
    queryFn: () => api.admin.effectivePermissions(id),
    enabled: Boolean(id) && can('identity.user.authorization.read'),
    retry: false,
  })

  const sessionsQuery = useQuery({
    queryKey: ['admin', 'user', id, 'sessions'],
    queryFn: () => api.admin.userSessions(id),
    enabled: Boolean(id) && can('identity.user.session.read'),
    retry: false,
  })

  const auditsQuery = useQuery({
    queryKey: ['admin', 'user', id, 'audits'],
    queryFn: () => api.audits.list({ target: id, page_size: 30 }),
    enabled: Boolean(id) && tab === 'audits' && can('audit.read'),
    retry: false,
  })

  const auditDetailQuery = useQuery({
    queryKey: ['admin', 'audit', auditDetailId],
    queryFn: () => api.audits.get(auditDetailId ?? ''),
    enabled: Boolean(auditDetailId),
    retry: false,
  })

  const policyRevision =
    effectiveQuery.data?.policy_revision ??
    authorization?.policy_revision ??
    ''

  const invalidateUser = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', id] }),
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] }),
      queryClient.invalidateQueries({ queryKey: ['admin', 'overview'] }),
    ])
  }

  const updateUser = useApiMutation({
    mutationFn: () =>
      api.admin.updateUser(id, {
        id,
        display_name: displayName.trim(),
        update_mask: 'display_name',
        expected_revision: user?.revision ?? '0',
        reason: editReason.trim() || 'administrator update',
      }),
    successMessage: '用户资料已更新',
    onSuccess: async () => {
      setEditOpen(false)
      await invalidateUser()
    },
  })

  const setStatus = useApiMutation({
    mutationFn: (input: { status: string; reason: string }) =>
      api.admin.setUserStatus(id, {
        id,
        status: input.status,
        expected_revision: user?.revision ?? '0',
        reason: input.reason,
      }),
    successMessage: '账号状态已更新',
    invalidate: [['admin', 'user', id], ['admin', 'users'], ['admin', 'overview']],
    onSuccess: () => setReasonAction(null),
  })

  const archiveUser = useApiMutation({
    mutationFn: (reason: string) =>
      api.admin.archiveUser(id, {
        id,
        expected_revision: user?.revision ?? '0',
        reason,
      }),
    successMessage: '账号已归档',
    invalidate: [['admin', 'user', id], ['admin', 'users'], ['admin', 'overview']],
    onSuccess: () => setReasonAction(null),
  })

  const resetMfa = useApiMutation({
    mutationFn: (reason: string) => api.admin.resetMfa(id, { id, reason }),
    successMessage: 'MFA 已重置',
    invalidate: [['admin', 'user', id], ['admin', 'users']],
    onSuccess: () => setReasonAction(null),
  })

  const requestPasswordReset = useApiMutation({
    mutationFn: (reason: string) =>
      api.admin.createPasswordResetRequest(id, { id, reason }),
    successMessage: '密码重置请求已创建',
    successDescription: '重置链接已发送到用户邮箱，30 分钟内有效。',
    invalidate: [['admin', 'user', id]],
    onSuccess: () => setReasonAction(null),
  })

  const revokeSessions = useApiMutation({
    mutationFn: (input: { sessionIds: string[]; all: boolean; reason: string }) =>
      api.admin.revokeUserSessions(id, {
        id,
        session_ids: input.sessionIds,
        revoke_all: input.all,
        reason: input.reason,
      }),
    successMessage: '用户会话已撤销',
    invalidate: [['admin', 'user', id, 'sessions'], ['admin', 'user', id]],
    onSuccess: () => setReasonAction(null),
  })

  const revokeAssignment = useApiMutation({
    mutationFn: (input: { assignmentId: string; reason: string }) =>
      api.iam.revokeAssignment(input.assignmentId, {
        id: input.assignmentId,
        reason: input.reason,
        expected_policy_revision: policyRevision,
      }),
    successMessage: '角色分配已撤销',
    invalidate: [
      ['admin', 'user', id, 'assignments'],
      ['admin', 'user', id, 'effective'],
    ],
    refreshAuth: true,
    onSuccess: () => setReasonAction(null),
  })

  const reasonBusy =
    setStatus.isPending ||
    archiveUser.isPending ||
    resetMfa.isPending ||
    requestPasswordReset.isPending ||
    revokeSessions.isPending ||
    revokeAssignment.isPending

  const toggleStatus = () => {
    if (!user) return
    const nextStatus = user.status === 'enabled' ? 'disabled' : 'enabled'
    setReasonAction({
      title: nextStatus === 'disabled' ? '禁用账号' : '启用账号',
      description:
        nextStatus === 'disabled'
          ? '禁用后该账号的所有会话会被撤销，且无法登录。'
          : '启用后账号可以重新登录。',
      confirmLabel: nextStatus === 'disabled' ? '确认禁用' : '确认启用',
      tone: nextStatus === 'disabled' ? 'danger' : 'primary',
      run: (reason) => setStatus.mutate({ status: nextStatus, reason }),
    })
  }

  const openArchive = () => {
    setReasonAction({
      title: '归档账号',
      description:
        '归档会保留账号历史与审计记录，撤销所有会话，且不可恢复。此操作需要近期安全验证。',
      confirmLabel: '确认归档',
      tone: 'danger',
      run: (reason) => archiveUser.mutate(reason),
    })
  }

  const openResetMfa = () => {
    setReasonAction({
      title: '重置用户 MFA',
      description:
        '会移除该用户的第二因素与恢复码，用户需重新绑定。此操作需要近期安全验证。',
      confirmLabel: '确认重置',
      tone: 'danger',
      run: (reason) => resetMfa.mutate(reason),
    })
  }

  const openPasswordReset = () => {
    setReasonAction({
      title: '发起密码重置',
      description:
        '系统会向用户邮箱发送一次性重置链接。此操作需要近期安全验证。',
      confirmLabel: '发送重置邮件',
      run: (reason) => requestPasswordReset.mutate(reason),
    })
  }

  const openRevokeAllSessions = () => {
    setReasonAction({
      title: '撤销全部会话',
      description: '该用户在所有设备上的登录会立即失效。',
      confirmLabel: '全部撤销',
      tone: 'danger',
      run: (reason) =>
        revokeSessions.mutate({ sessionIds: [], all: true, reason }),
    })
  }

  const openRevokeSession = (session: SessionInfo) => {
    setReasonAction({
      title: '撤销单个会话',
      description: `设备：${session.device || '未知'}（${session.ip_masked || 'IP 未知'}）`,
      confirmLabel: '撤销会话',
      tone: 'danger',
      run: (reason) =>
        revokeSessions.mutate({
          sessionIds: [session.id ?? ''],
          all: false,
          reason,
        }),
    })
  }

  const openRevokeAssignment = (assignment: Assignment) => {
    setReasonAction({
      title: '撤销角色分配',
      description: `角色 ID ${assignment.role_id} · 分配 ${assignment.id}`,
      confirmLabel: '撤销分配',
      tone: 'danger',
      run: (reason) =>
        revokeAssignment.mutate({ assignmentId: assignment.id ?? '', reason }),
    })
  }

  const tabs = [
    { key: 'profile', label: '资料' },
    { key: 'security', label: '安全' },
    ...(can('iam.assignment.read') || can('identity.user.authorization.read')
      ? [{ key: 'roles', label: '角色' }]
      : []),
    ...(can('identity.user.session.read')
      ? [{ key: 'sessions', label: '会话', count: sessionsQuery.data?.items?.length }]
      : []),
    ...(can('audit.read') ? [{ key: 'audits', label: '审计' }] : []),
  ]

  if (!id) {
    return <InlineAlert tone="danger">缺少用户 ID</InlineAlert>
  }

  return (
    <div className="space-y-4">
      <PageTitle title={user?.display_name || '用户详情'} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Link
          to="/admin/users"
          className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 hover:text-slate-800"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          返回用户列表
        </Link>
        <Button
          size="xs"
          variant="ghost"
          onClick={() => {
            void userQuery.refetch()
            void assignmentsQuery.refetch()
            void effectiveQuery.refetch()
            void sessionsQuery.refetch()
          }}
          loading={userQuery.isFetching}
          icon={<RefreshCw className="h-3 w-3" />}
        >
          刷新
        </Button>
      </div>

      <QueryBoundary query={userQuery} loadingLabel="读取用户详情…">
        {user ? (
          <>
            <Card>
              <div className="flex flex-wrap items-start justify-between gap-4 p-4">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-500 text-lg font-semibold text-white">
                    {(user.display_name || user.username || '?').slice(0, 1)}
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="truncate text-base font-semibold text-slate-900">
                        {user.display_name || user.username}
                      </h1>
                      <StatusBadge status={user.status} />
                      {user.mfa_enabled ? (
                        <Badge tone="success">
                          <ShieldCheck className="h-3 w-3" /> MFA
                        </Badge>
                      ) : (
                        <Badge tone="warning">未启用 MFA</Badge>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
                      <span className="font-mono">@{user.username}</span>
                      <span>{user.email || '无权查看邮箱或未绑定'}</span>
                      <span className="font-mono">id={user.id}</span>
                      <span>revision {user.revision}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {(user.roles ?? []).map((role) => (
                        <Badge key={role.id} tone="violet">
                          {role.name || role.code}
                        </Badge>
                      ))}
                      {!user.roles?.length ? (
                        <span className="text-[11px] text-slate-400">未分配角色</span>
                      ) : null}
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {can('identity.user.update') ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        setDisplayName(user.display_name ?? '')
                        setEditReason('')
                        setEditOpen(true)
                      }}
                      icon={<Pencil className="h-3.5 w-3.5" />}
                    >
                      编辑
                    </Button>
                  ) : null}
                  {user.status !== 'archived' &&
                  can(
                    user.status === 'enabled'
                      ? 'identity.user.disable'
                      : 'identity.user.enable',
                  ) ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={toggleStatus}
                      icon={
                        user.status === 'enabled' ? (
                          <Ban className="h-3.5 w-3.5" />
                        ) : (
                          <UserCheck className="h-3.5 w-3.5" />
                        )
                      }
                    >
                      {user.status === 'enabled' ? '禁用' : '启用'}
                    </Button>
                  ) : null}
                  {user.status !== 'archived' && can('identity.user.archive') ? (
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
                <Tabs
                  tabs={tabs}
                  value={tab}
                  onChange={(key) => setTab(key as TabKey)}
                />
              </div>

              {tab === 'profile' ? (
                <CardContent className="space-y-4">
                  <InfoGrid
                    items={[
                      { label: '用户 ID', value: user.id, mono: true },
                      { label: '用户名', value: user.username, mono: true },
                      { label: '显示昵称', value: user.display_name || '—' },
                      {
                        label: '邮箱',
                        value: (
                          <span className="inline-flex items-center gap-1">
                            {user.email || '—'}
                            {user.email_verified ? (
                              <Badge tone="success">已验证</Badge>
                            ) : (
                              <Badge tone="warning">未验证</Badge>
                            )}
                          </span>
                        ),
                      },
                      { label: '状态', value: <StatusBadge status={user.status} /> },
                      {
                        label: 'MFA',
                        value: user.mfa_enabled ? '已启用' : '未启用',
                      },
                      {
                        label: 'identity_version',
                        value: user.identity_version,
                        mono: true,
                      },
                      { label: 'revision', value: user.revision, mono: true },
                      { label: '创建时间', value: formatDateTime(user.created_at) },
                      { label: '更新时间', value: formatDateTime(user.updated_at) },
                      {
                        label: '归档时间',
                        value: user.archived_at ? formatDate(user.archived_at) : '—',
                      },
                    ]}
                  />
                  <InlineAlert tone="info" title="数据范围">
                    邮箱是否展示取决于当前账号的 <code>identity.user.contact.read</code>{' '}
                    权限。所有写操作都要求目标 revision 与原因。
                  </InlineAlert>
                </CardContent>
              ) : null}

              {tab === 'security' ? (
                <CardContent className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-semibold text-slate-800">
                        多因素认证
                      </div>
                      {user.mfa_enabled ? (
                        <Badge tone="success" dot>
                          已启用
                        </Badge>
                      ) : (
                        <Badge tone="neutral" dot>
                          未启用
                        </Badge>
                      )}
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      重置会移除第二因素与全部恢复码，并要求用户重新绑定。需要近期安全验证。
                    </p>
                    {can('identity.user.mfa.reset') ? (
                      <Button
                        className="mt-2"
                        size="sm"
                        variant="secondary"
                        onClick={openResetMfa}
                        disabled={!user.mfa_enabled}
                        icon={<ShieldOff className="h-3.5 w-3.5" />}
                      >
                        重置 MFA
                      </Button>
                    ) : (
                      <p className="mt-2 text-[10px] text-slate-400">
                        缺少 identity.user.mfa.reset 权限
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="text-xs font-semibold text-slate-800">
                      密码与凭据
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      向用户邮箱发送一次性密码重置链接，30 分钟内有效。需要近期安全验证；若用户无邮箱，服务端会拒绝。
                    </p>
                    {can('identity.user.credential.update') ? (
                      <Button
                        className="mt-2"
                        size="sm"
                        variant="secondary"
                        onClick={openPasswordReset}
                        disabled={user.status === 'archived'}
                        icon={<KeyRound className="h-3.5 w-3.5" />}
                      >
                        发起密码重置
                      </Button>
                    ) : (
                      <p className="mt-2 text-[10px] text-slate-400">
                        缺少 identity.user.credential.update 权限
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="text-xs font-semibold text-slate-800">
                      邮箱与身份版本
                    </div>
                    <div className="mt-2 space-y-1 text-[11px] text-slate-600">
                      <div>邮箱：{user.email || '—'}</div>
                      <div>
                        验证状态：{user.email_verified ? '已验证' : '未验证'}
                      </div>
                      <div className="font-mono">
                        identity_version={user.identity_version}
                      </div>
                    </div>
                    <p className="mt-2 text-[10px] text-slate-400">
                      管理员端邮箱变更接口未在当前 OpenAPI 契约中提供。
                    </p>
                  </div>

                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="text-xs font-semibold text-slate-800">
                      近期安全状态
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      高风险操作会在缺少 step-up 时返回 STEP_UP_REQUIRED，前端会自动弹出验证对话框并允许重试一次。
                    </p>
                    <Badge tone="warning" className="mt-2">
                      验证窗口 5 分钟
                    </Badge>
                  </div>
                </CardContent>
              ) : null}

              {tab === 'roles' ? (
                <CardContent className="space-y-4">
                  <div>
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <div className="text-xs font-semibold text-slate-700">
                        角色分配
                      </div>
                      {!can('iam.assignment.read') ? (
                        <Badge tone="neutral">缺少 iam.assignment.read</Badge>
                      ) : null}
                    </div>
                    {can('iam.assignment.read') ? (
                      <QueryBoundary
                        query={assignmentsQuery}
                        loadingLabel="读取角色分配…"
                      >
                        {assignmentsQuery.data?.items?.length ? (
                          <Table minWidth="min-w-[720px]">
                            <THead>
                              <TR>
                                <TH>角色</TH>
                                <TH>数据范围</TH>
                                <TH>生效时间</TH>
                                <TH>过期时间</TH>
                                <TH>来源</TH>
                                <TH>状态</TH>
                                <TH className="text-right">操作</TH>
                              </TR>
                            </THead>
                            <TBody>
                              {assignmentsQuery.data.items.map((assignment) => {
                                const role = roleById(
                                  rolesQuery.data?.items,
                                  assignment.role_id,
                                )
                                return (
                                  <TR key={assignment.id}>
                                    <TD>
                                      <div className="text-xs font-medium text-slate-800">
                                        {role?.name || assignment.role_id}
                                      </div>
                                      <div className="font-mono text-[10px] text-slate-400">
                                        {role?.code || '—'} · {assignment.id}
                                      </div>
                                    </TD>
                                    <TD>
                                      <ScopeBadge scope={assignment.boundary} />
                                    </TD>
                                    <TD className="text-[11px] text-slate-500">
                                      {formatDateTime(assignment.starts_at)}
                                    </TD>
                                    <TD className="text-[11px] text-slate-500">
                                      {assignment.expires_at
                                        ? formatDateTime(assignment.expires_at)
                                        : '永久'}
                                    </TD>
                                    <TD className="text-[11px] text-slate-500">
                                      {assignment.origin || '—'}
                                    </TD>
                                    <TD>
                                      {assignment.revoked ? (
                                        <Badge tone="neutral">已撤销</Badge>
                                      ) : (
                                        <Badge tone="success" dot>
                                          生效中
                                        </Badge>
                                      )}
                                    </TD>
                                    <TD className="text-right">
                                      {can('iam.assignment.revoke') &&
                                      !assignment.revoked ? (
                                        <Button
                                          size="xs"
                                          variant="ghost"
                                          onClick={() =>
                                            openRevokeAssignment(assignment)
                                          }
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
                        ) : (
                          <EmptyState
                            title="暂无角色分配"
                            description="可以在授权分配页为此用户分配角色。"
                          />
                        )}
                      </QueryBoundary>
                    ) : null}
                  </div>

                  <div>
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <div className="text-xs font-semibold text-slate-700">
                        有效权限
                      </div>
                      {effectiveQuery.data ? (
                        <Badge tone="outline">
                          policy {effectiveQuery.data.policy_revision ?? '—'} · user{' '}
                          {effectiveQuery.data.user_revision ?? '—'}
                        </Badge>
                      ) : null}
                    </div>
                    {can('identity.user.authorization.read') ? (
                      <QueryBoundary
                        query={effectiveQuery}
                        loadingLabel="计算有效权限…"
                      >
                        {effectiveQuery.data?.permissions?.length ? (
                          <Table minWidth="min-w-[760px]">
                            <THead>
                              <TR>
                                <TH>操作</TH>
                                <TH>效果</TH>
                                <TH>范围</TH>
                                <TH>角色</TH>
                                <TH>来源</TH>
                              </TR>
                            </THead>
                            <TBody>
                              {effectiveQuery.data.permissions.map(
                                (permission, index) => (
                                  <TR
                                    key={`${permission.operation}-${permission.assignment_id}-${index}`}
                                  >
                                    <TD className="font-mono text-[11px] text-slate-800">
                                      {permission.operation}
                                    </TD>
                                    <TD>
                                      <Badge
                                        tone={
                                          permission.effect === 'allow'
                                            ? 'success'
                                            : 'danger'
                                        }
                                      >
                                        {permission.effect === 'allow'
                                          ? '允许'
                                          : '拒绝'}
                                      </Badge>
                                    </TD>
                                    <TD className="text-[11px] text-slate-600">
                                      {formatScopeCode(permission.scope)}
                                    </TD>
                                    <TD className="text-[11px] text-slate-600">
                                      {permission.role_code ||
                                        permission.role_id ||
                                        '—'}
                                    </TD>
                                    <TD className="text-[11px] text-slate-500">
                                      {permission.source || '—'}
                                    </TD>
                                  </TR>
                                ),
                              )}
                            </TBody>
                          </Table>
                        ) : (
                          <EmptyState title="无有效权限" />
                        )}
                      </QueryBoundary>
                    ) : (
                      <p className="text-[11px] text-slate-500">
                        缺少 identity.user.authorization.read 权限。
                      </p>
                    )}
                  </div>
                </CardContent>
              ) : null}

              {tab === 'sessions' ? (
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-xs text-slate-500">
                      仅列出未过期且未撤销的会话。
                    </div>
                    {can('identity.user.session.revoke') ? (
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={openRevokeAllSessions}
                        icon={<MonitorSmartphone className="h-3.5 w-3.5" />}
                      >
                        撤销全部会话
                      </Button>
                    ) : null}
                  </div>
                  <QueryBoundary query={sessionsQuery} loadingLabel="读取用户会话…">
                    {sessionsQuery.data?.items?.length ? (
                      <Table minWidth="min-w-[760px]">
                        <THead>
                          <TR>
                            <TH>设备</TH>
                            <TH>IP</TH>
                            <TH>签发</TH>
                            <TH>最近活跃</TH>
                            <TH>过期</TH>
                            <TH className="text-right">操作</TH>
                          </TR>
                        </THead>
                        <TBody>
                          {sessionsQuery.data.items.map((session) => (
                            <TR key={session.id}>
                              <TD>
                                <div className="max-w-[220px] truncate text-xs text-slate-800">
                                  {session.device || '未知设备'}
                                </div>
                                <div className="text-[10px] text-slate-400">
                                  {session.application_code || '—'}
                                </div>
                              </TD>
                              <TD className="font-mono text-[11px] text-slate-600">
                                {session.ip_masked || '—'}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {formatDateTime(session.issued_at)}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {formatDateTime(session.last_seen_at)}
                              </TD>
                              <TD className="text-[11px] text-slate-500">
                                {formatDateTime(session.expires_at)}
                              </TD>
                              <TD className="text-right">
                                {can('identity.user.session.revoke') ? (
                                  <Button
                                    size="xs"
                                    variant="ghost"
                                    onClick={() => openRevokeSession(session)}
                                  >
                                    撤销
                                  </Button>
                                ) : null}
                              </TD>
                            </TR>
                          ))}
                        </TBody>
                      </Table>
                    ) : (
                      <EmptyState
                        title="没有有效会话"
                        description="该用户当前未登录任何设备。"
                        icon={MonitorSmartphone}
                      />
                    )}
                  </QueryBoundary>
                </CardContent>
              ) : null}

              {tab === 'audits' ? (
                <CardContent>
                  <QueryBoundary query={auditsQuery} loadingLabel="读取用户审计…">
                    {auditsQuery.data?.items?.length ? (
                      <Table minWidth="min-w-[760px]">
                        <THead>
                          <TR>
                            <TH>时间</TH>
                            <TH>操作</TH>
                            <TH>操作者</TH>
                            <TH>结果</TH>
                            <TH>原因</TH>
                            <TH className="text-right">详情</TH>
                          </TR>
                        </THead>
                        <TBody>
                          {auditsQuery.data.items.map((event: AuditEvent) => (
                            <TR key={event.id}>
                              <TD className="whitespace-nowrap text-[11px] text-slate-500">
                                {formatDateTime(event.occurred_at)}
                              </TD>
                              <TD className="font-mono text-[11px] text-slate-800">
                                {event.action}
                              </TD>
                              <TD className="text-[11px] text-slate-600">
                                {event.actor_user_id || event.actor_service_id || '—'}
                              </TD>
                              <TD>
                                <StatusBadge status={event.result} />
                              </TD>
                              <TD className="max-w-[200px] truncate text-[11px] text-slate-500">
                                {event.reason || '—'}
                              </TD>
                              <TD className="text-right">
                                <Button
                                  size="xs"
                                  variant="ghost"
                                  onClick={() => setAuditDetailId(event.id ?? null)}
                                >
                                  查看
                                </Button>
                              </TD>
                            </TR>
                          ))}
                        </TBody>
                      </Table>
                    ) : (
                      <EmptyState title="暂无审计记录" />
                    )}
                  </QueryBoundary>
                </CardContent>
              ) : null}
            </Card>

            <Dialog
              open={editOpen}
              onClose={() => setEditOpen(false)}
              title="编辑用户资料"
              description="仅支持修改显示昵称。提交时携带当前 revision。"
              size="md"
              bodyClassName="space-y-3"
              footer={
                <>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setEditOpen(false)}
                    disabled={updateUser.isPending}
                  >
                    取消
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => updateUser.mutate(undefined)}
                    loading={updateUser.isPending}
                    disabled={!displayName.trim()}
                  >
                    保存
                  </Button>
                </>
              }
            >
              <Field label="显示昵称" htmlFor="admin-display-name" required>
                <Input
                  id="admin-display-name"
                  value={displayName}
                  maxLength={64}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </Field>
              <Field label="操作原因" htmlFor="admin-edit-reason">
                <Input
                  id="admin-edit-reason"
                  value={editReason}
                  onChange={(event) => setEditReason(event.target.value)}
                  placeholder="可选，写入审计日志"
                />
              </Field>
              <div className="text-[11px] text-slate-500">
                当前 revision：<span className="font-mono">{user.revision}</span>
              </div>
            </Dialog>

            <ReasonDialog
              open={reasonAction !== null}
              onClose={() => setReasonAction(null)}
              onConfirm={(reason) => reasonAction?.run(reason)}
              title={reasonAction?.title ?? ''}
              description={reasonAction?.description}
              confirmLabel={reasonAction?.confirmLabel}
              tone={reasonAction?.tone ?? 'danger'}
              busy={reasonBusy}
            />

            <Dialog
              open={auditDetailId !== null}
              onClose={() => setAuditDetailId(null)}
              title="审计事件详情"
              description={auditDetailQuery.data?.action}
              size="lg"
              bodyClassName="space-y-3"
            >
              {auditDetailQuery.isPending ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  加载中…
                </div>
              ) : auditDetailQuery.isError ? (
                <InlineAlert tone="danger">
                  无法读取审计详情
                </InlineAlert>
              ) : auditDetailQuery.data ? (
                <>
                  <InfoGrid
                    items={[
                      {
                        label: '事件 ID',
                        value: auditDetailQuery.data.id,
                        mono: true,
                      },
                      {
                        label: '操作',
                        value: auditDetailQuery.data.action,
                        mono: true,
                      },
                      {
                        label: '结果',
                        value: (
                          <StatusBadge status={auditDetailQuery.data.result} />
                        ),
                      },
                      {
                        label: '操作者',
                        value:
                          auditDetailQuery.data.actor_user_id ||
                          auditDetailQuery.data.actor_service_id ||
                          '—',
                        mono: true,
                      },
                      {
                        label: '目标',
                        value: auditDetailQuery.data.target || '—',
                        mono: true,
                      },
                      {
                        label: '时间',
                        value: formatDateTime(auditDetailQuery.data.occurred_at),
                      },
                      {
                        label: '请求 ID',
                        value: auditDetailQuery.data.request_id || '—',
                        mono: true,
                      },
                      {
                        label: '原因',
                        value: auditDetailQuery.data.reason || '—',
                      },
                    ]}
                  />
                  <div className="space-y-1">
                    <div className="text-[11px] font-medium text-slate-600">
                      diff
                    </div>
                    <JsonBlock value={auditDetailQuery.data.diff} />
                  </div>
                  <div className="space-y-1">
                    <div className="text-[11px] font-medium text-slate-600">
                      before / after
                    </div>
                    <pre className="max-h-48 overflow-auto rounded-md bg-slate-100 p-3 font-mono text-[10.5px] text-slate-700">
                      {prettyJson(auditDetailQuery.data.before)}
                      {'\n---\n'}
                      {prettyJson(auditDetailQuery.data.after)}
                    </pre>
                  </div>
                </>
              ) : null}
            </Dialog>
          </>
        ) : (
          <EmptyState title="用户不存在" />
        )}
      </QueryBoundary>
    </div>
  )
}
