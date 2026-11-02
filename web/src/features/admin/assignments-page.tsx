import {
  CheckCircle2,
  KeyRound,
  RefreshCw,
  Search,
  ShieldAlert,
  Users,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Field, Input, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import {
  Pagination,
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
import { formatDateTime, toRfc3339 } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type {
  AssignmentItem,
  BatchPreviewReply,
  Scope,
} from '../../lib/types'
import { ScopeBadge, roleById, useAllRoles } from './common'

type BoundaryType = 'all' | 'self' | 'user_ids'

export function AdminAssignmentsPage() {
  const { authorization, can } = useAuth()
  const rolesQuery = useAllRoles()
  const [roleId, setRoleId] = useState('')
  const [boundaryType, setBoundaryType] = useState<BoundaryType>('all')
  const [startsAt, setStartsAt] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [searchKeyword, setSearchKeyword] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [preview, setPreview] = useState<BatchPreviewReply | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [assignOpen, setAssignOpen] = useState(false)
  const [singleAssignOpen, setSingleAssignOpen] = useState(false)
  const [assignResultCount, setAssignResultCount] = useState<number | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<AssignmentItem | null>(null)
  const [filterUserIdInput, setFilterUserIdInput] = useState('')
  const [filterUserId, setFilterUserId] = useState('')
  const [filterRoleId, setFilterRoleId] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [assignmentTokens, setAssignmentTokens] = useState<string[]>([''])
  const assignmentToken = assignmentTokens[assignmentTokens.length - 1] ?? ''

  const usersQuery = useQuery({
    queryKey: ['admin', 'assignments', 'users', searchKeyword],
    queryFn: () =>
      api.admin.listUsers({
        keyword: searchKeyword || undefined,
        page_size: 20,
      }),
    enabled: Boolean(searchKeyword),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const assignmentsQuery = useQuery({
    queryKey: [
      'admin',
      'iam',
      'assignments',
      {
        userId: filterUserId,
        roleId: filterRoleId,
        status: filterStatus,
        pageToken: assignmentToken,
      },
    ],
    queryFn: () =>
      api.iam.listAssignments({
        user_id: filterUserId || undefined,
        role_id: filterRoleId || undefined,
        status: filterStatus || undefined,
        page_size: 20,
        page_token: assignmentToken || undefined,
      }),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const buildBoundary = (): Scope => {
    if (boundaryType === 'all') return { all: true }
    if (boundaryType === 'self') return { self: true }
    return { user_ids: [...selected] }
  }

  const buildPreview = () =>
    api.iam.previewBatchAssign({
      user_ids: [...selected],
      role_id: roleId,
      boundary: buildBoundary(),
      expires_at: toRfc3339(expiresAt),
    })

  const previewMutation = useApiMutation({
    mutationFn: buildPreview,
    onSuccess: (data) => {
      setPreview(data)
      setPreviewError(null)
    },
    onError: () => setPreviewError('预览失败，请检查筛选条件与角色状态'),
  })

  const batchAssign = useApiMutation({
    mutationFn: (reason: string) =>
      api.iam.batchAssign({
        user_ids: [...selected],
        role_id: roleId,
        boundary: buildBoundary(),
        starts_at: toRfc3339(startsAt),
        expires_at: toRfc3339(expiresAt),
        reason,
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '批量分配完成',
    refreshAuth: true,
    invalidate: [['admin', 'iam', 'assignments']],
    onSuccess: async (data) => {
      setAssignOpen(false)
      setPreview(null)
      setAssignResultCount(data.assignments?.length ?? 0)
      setSelected(new Set())
      await Promise.all([usersQuery.refetch(), assignmentsQuery.refetch()])
    },
  })

  const createAssignment = useApiMutation({
    mutationFn: (reason: string) =>
      api.iam.createAssignment({
        user_id: selectedUserId ?? '',
        role_id: roleId,
        boundary: buildBoundary(),
        starts_at: toRfc3339(startsAt),
        expires_at: toRfc3339(expiresAt),
        reason,
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '角色分配已创建',
    refreshAuth: true,
    invalidate: [['admin', 'iam', 'assignments']],
    onSuccess: async () => {
      setSingleAssignOpen(false)
      setAssignResultCount(null)
      await assignmentsQuery.refetch()
    },
  })

  const revokeAssignment = useApiMutation({
    mutationFn: (input: { assignment: AssignmentItem; reason: string }) =>
      api.iam.revokeAssignment(input.assignment.id ?? '', {
        id: input.assignment.id,
        reason: input.reason,
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '角色分配已撤销',
    refreshAuth: true,
    invalidate: [['admin', 'iam', 'assignments']],
    onSuccess: async () => {
      setRevokeTarget(null)
      await assignmentsQuery.refetch()
    },
  })

  const roles = rolesQuery.data?.items ?? []
  const selectedRole = roleById(roles, roleId)
  const selectedUserId = selected.size === 1 ? [...selected][0] : null
  const users = usersQuery.data?.items ?? []
  const assignmentItems = assignmentsQuery.data?.items ?? []
  const nextAssignmentToken = assignmentsQuery.data?.meta?.next_page_token

  const toggleUser = (userId: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(userId)) next.delete(userId)
      else next.add(userId)
      return next
    })
    setPreview(null)
    setAssignResultCount(null)
  }

  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setSearchKeyword(searchInput.trim())
  }

  const runPreview = () => {
    setPreviewError(null)
    setAssignResultCount(null)
    if (!roleId || selected.size === 0) {
      setPreviewError('请先选择角色与至少一个用户')
      return
    }
    if (boundaryType === 'user_ids' && selected.size === 0) {
      setPreviewError('指定用户范围时至少选择一个用户')
      return
    }
    previewMutation.mutate(undefined)
  }

  const openAssign = () => {
    if (!roleId || selected.size === 0) {
      setPreviewError('请先选择角色与至少一个用户')
      return
    }
    setAssignOpen(true)
  }

  return (
    <div className="space-y-4">
      <PageTitle title="授权分配" />
      <PageHeader
        eyebrow="IAM"
        title="授权分配"
        description="按用户、角色与状态查询授权分配；批量创建前先预览资格与冲突，再提交带原因的分配。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              void rolesQuery.refetch()
              void assignmentsQuery.refetch()
            }}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
        }
      />

      {assignResultCount !== null ? (
        <InlineAlert tone="success" title="批量分配成功">
          已创建 {assignResultCount} 个角色分配。
        </InlineAlert>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-[1.15fr_1fr]">
        <Card>
          <CardHeader
            title="分配配置"
            description="角色与数据边界会写入每个 assignment。"
          />
          <CardContent className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="角色" htmlFor="assign-role" required>
                <Select
                  id="assign-role"
                  value={roleId}
                  onChange={(event) => {
                    setRoleId(event.target.value)
                    setPreview(null)
                  }}
                >
                  <option value="">选择角色</option>
                  {roles.map((role) => (
                    <option key={role.id} value={role.id}>
                      {role.name}（{role.code}）
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="数据边界" htmlFor="assign-boundary" required>
                <Select
                  id="assign-boundary"
                  value={boundaryType}
                  onChange={(event) => {
                    setBoundaryType(event.target.value as BoundaryType)
                    setPreview(null)
                  }}
                >
                  <option value="all">全部数据</option>
                  <option value="self">仅本人</option>
                  <option value="user_ids">指定用户</option>
                </Select>
              </Field>
              <Field label="生效时间" htmlFor="assign-starts">
                <Input
                  id="assign-starts"
                  type="datetime-local"
                  value={startsAt}
                  onChange={(event) => {
                    setStartsAt(event.target.value)
                    setPreview(null)
                  }}
                />
              </Field>
              <Field
                label="过期时间"
                htmlFor="assign-expires"
                hint="留空表示永久有效"
              >
                <Input
                  id="assign-expires"
                  type="datetime-local"
                  value={expiresAt}
                  onChange={(event) => {
                    setExpiresAt(event.target.value)
                    setPreview(null)
                  }}
                />
              </Field>
            </div>

            <form className="flex items-end gap-2" onSubmit={submitSearch}>
              <div className="flex-1">
                <Field label="搜索用户" htmlFor="assign-user-search">
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                    <Input
                      id="assign-user-search"
                      value={searchInput}
                      onChange={(event) => setSearchInput(event.target.value)}
                      placeholder="用户名、昵称或邮箱"
                      className="pl-8"
                    />
                  </div>
                </Field>
              </div>
              <Button type="submit" size="sm" variant="secondary">
                搜索
              </Button>
            </form>

            {selected.size > 0 ? (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-[11px] text-slate-500">已选择：</span>
                {[...selected].map((userId) => {
                  const user = [
                    ...users,
                    ...(usersQuery.data?.items ?? []),
                  ].find((item) => item.id === userId)
                  return (
                    <Badge key={userId} tone="info">
                      {user?.display_name || user?.username || `id=${userId}`}
                      <button
                        type="button"
                        className="ml-0.5 hover:text-rose-600"
                        onClick={() => toggleUser(userId)}
                        aria-label="移除用户"
                      >
                        ×
                      </button>
                    </Badge>
                  )
                })}
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => {
                    setSelected(new Set())
                    setPreview(null)
                  }}
                >
                  清空
                </Button>
              </div>
            ) : null}

            {searchKeyword ? (
              <div className="max-h-64 overflow-y-auto rounded-md border border-slate-200">
                {usersQuery.isError ? (
                  <div className="p-3">
                    <InlineAlert tone="danger" title="无法搜索用户">
                      {errorMessage(usersQuery.error)}
                      {!can('identity.user.list')
                        ? ' 当前账号缺少 identity.user.list 权限。'
                        : ''}
                    </InlineAlert>
                  </div>
                ) : usersQuery.isPending ? (
                  <div className="p-4 text-center text-[11px] text-slate-500">
                    搜索中…
                  </div>
                ) : users.length === 0 ? (
                  <div className="p-4 text-center text-[11px] text-slate-500">
                    没有匹配的用户
                  </div>
                ) : (
                  <table className="w-full text-left text-[11px]">
                    <thead className="bg-slate-50 text-slate-500">
                      <tr>
                        <th className="w-8 px-2 py-1.5" />
                        <th className="px-2 py-1.5">用户</th>
                        <th className="px-2 py-1.5">状态</th>
                        <th className="px-2 py-1.5">MFA</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user) => (
                        <tr
                          key={user.id}
                          className="border-t border-slate-100 hover:bg-slate-50"
                        >
                          <td className="px-2 py-1.5">
                            <input
                              type="checkbox"
                              className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                              checked={selected.has(user.id ?? '')}
                              onChange={() => toggleUser(user.id ?? '')}
                            />
                          </td>
                          <td className="px-2 py-1.5">
                            <div className="font-medium text-slate-800">
                              {user.display_name || user.username}
                            </div>
                            <div className="font-mono text-[10px] text-slate-400">
                              @{user.username} · {user.id}
                            </div>
                          </td>
                          <td className="px-2 py-1.5">
                            <StatusBadge status={user.status} />
                          </td>
                          <td className="px-2 py-1.5">
                            {user.mfa_enabled ? '已启用' : '未启用'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ) : (
              <p className="text-[11px] text-slate-500">
                搜索并勾选需要分配角色的用户。
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
              <Button
                size="sm"
                variant="secondary"
                onClick={runPreview}
                loading={previewMutation.isPending}
                disabled={!roleId || selected.size === 0}
              >
                预览资格
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setSingleAssignOpen(true)}
                disabled={!roleId || !selectedUserId}
                icon={<KeyRound className="h-3.5 w-3.5" />}
              >
                单个分配
              </Button>
              <Button
                size="sm"
                variant="primary"
                onClick={openAssign}
                disabled={!roleId || selected.size === 0}
                icon={<KeyRound className="h-3.5 w-3.5" />}
              >
                批量分配
              </Button>
              <span className="text-[11px] text-slate-500">
                {selectedRole ? `角色：${selectedRole.name}` : '未选择角色'} ·{' '}
                {selected.size} 个用户
              </span>
            </div>
            {previewError ? (
              <InlineAlert tone="danger">{previewError}</InlineAlert>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader
            title="预览结果"
            description="预览不会写入数据。失败项会显示原因。"
            actions={
              preview ? (
                <Badge tone="success">
                  可分配 {preview.eligible_user_ids?.length ?? 0}
                </Badge>
              ) : undefined
            }
          />
          <CardContent>
            {!preview ? (
              <EmptyState
                title="尚未运行预览"
                description="选择角色与用户后点击“预览资格”。"
                icon={ShieldAlert}
              />
            ) : (
              <div className="space-y-3">
                <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-emerald-800">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    可分配用户
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {preview.eligible_user_ids?.length ? (
                      preview.eligible_user_ids.map((userId) => (
                        <Badge key={userId} tone="success">
                          {userId}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-[11px] text-emerald-700">无</span>
                    )}
                  </div>
                </div>
                {preview.failures?.length ? (
                  <div className="rounded-md border border-rose-200 bg-rose-50 p-3">
                    <div className="text-xs font-medium text-rose-800">
                      失败项（{preview.failures.length}）
                    </div>
                    <ul className="mt-1 space-y-1 text-[11px] text-rose-700">
                      {preview.failures.map((failure) => (
                        <li key={failure.user_id}>
                          <span className="font-mono">{failure.user_id}</span>：
                          {failure.reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <InlineAlert tone="info">
                  资格可能受角色状态、职责分离约束与成员上限影响，提交时服务端会再次校验。
                </InlineAlert>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="授权分配列表"
          description="按用户、角色与状态筛选全部 assignment，服务端分页返回。"
          actions={
            <Badge tone="outline">
              共 {assignmentsQuery.data?.meta?.total_size ?? '—'} 条
            </Badge>
          }
        />
        <div className="border-b border-slate-100 p-3">
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault()
              setFilterUserId(filterUserIdInput.trim())
              setAssignmentTokens([''])
            }}
          >
            <Field label="用户 ID" htmlFor="assignment-user" className="w-44">
              <Input
                id="assignment-user"
                value={filterUserIdInput}
                onChange={(event) => setFilterUserIdInput(event.target.value)}
                placeholder="精确匹配 user_id"
              />
            </Field>
            <Field label="角色" htmlFor="assignment-role" className="w-44">
              <Select
                id="assignment-role"
                value={filterRoleId}
                onChange={(event) => {
                  setFilterRoleId(event.target.value)
                  setAssignmentTokens([''])
                }}
              >
                <option value="">全部角色</option>
                {roles.map((role) => (
                  <option key={role.id} value={role.id}>
                    {role.name}（{role.code}）
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="状态" htmlFor="assignment-status" className="w-32">
              <Select
                id="assignment-status"
                value={filterStatus}
                onChange={(event) => {
                  setFilterStatus(event.target.value)
                  setAssignmentTokens([''])
                }}
              >
                <option value="">全部</option>
                <option value="active">生效中</option>
                <option value="revoked">已撤销</option>
              </Select>
            </Field>
            <div className="flex gap-2">
              <Button type="submit" size="sm" variant="primary">
                筛选
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => {
                  setFilterUserIdInput('')
                  setFilterUserId('')
                  setFilterRoleId('')
                  setFilterStatus('')
                  setAssignmentTokens([''])
                }}
              >
                重置
              </Button>
            </div>
          </form>
        </div>
        <QueryBoundary query={assignmentsQuery} loadingLabel="读取授权分配…">
          {assignmentItems.length === 0 ? (
            <EmptyState
              title="没有匹配的授权分配"
              description="调整用户、角色或状态筛选，或使用上方批量分配创建授权。"
              icon={Users}
            />
          ) : (
            <>
              <Table minWidth="min-w-[980px]">
                <THead>
                  <TR>
                    <TH>用户</TH>
                    <TH>角色</TH>
                    <TH>数据范围</TH>
                    <TH>生效</TH>
                    <TH>过期</TH>
                    <TH>来源</TH>
                    <TH>状态</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {assignmentItems.map((assignment) => (
                    <TR key={assignment.id}>
                      <TD>
                        <div className="text-xs font-medium text-slate-800">
                          {assignment.display_name ||
                            assignment.username ||
                            assignment.user_id}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          @{assignment.username || '—'} · user {assignment.user_id}
                        </div>
                      </TD>
                      <TD>
                        <div className="text-xs font-medium text-slate-800">
                          {assignment.role_name ||
                            roleById(roles, assignment.role_id)?.name ||
                            assignment.role_id}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {assignment.role_code || '—'} · assignment {assignment.id}
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
                        {!assignment.revoked &&
                        can('iam.assignment.revoke') ? (
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() => setRevokeTarget(assignment)}
                          >
                            撤销
                          </Button>
                        ) : null}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                total={assignmentsQuery.data?.meta?.total_size}
                pageIndex={assignmentTokens.length}
                hasNext={Boolean(nextAssignmentToken)}
                onPrev={() =>
                  setAssignmentTokens((current) =>
                    current.length > 1 ? current.slice(0, -1) : current,
                  )
                }
                onNext={() => {
                  if (nextAssignmentToken) {
                    setAssignmentTokens((current) => [
                      ...current,
                      nextAssignmentToken,
                    ])
                  }
                }}
                onRefresh={() => void assignmentsQuery.refetch()}
                loading={assignmentsQuery.isFetching}
              />
            </>
          )}
        </QueryBoundary>
      </Card>

      <ReasonDialog
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        onConfirm={(reason) => batchAssign.mutate(reason)}
        title="批量分配角色"
        description={`将向 ${selected.size} 个用户分配「${selectedRole?.name ?? roleId}」。`}
        confirmLabel="确认分配"
        busy={batchAssign.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          <div>数据边界：{boundaryType}</div>
          <div>过期时间：{expiresAt ? formatDateTime(toRfc3339(expiresAt)) : '永久'}</div>
          <div>预计可分配：{preview?.eligible_user_ids?.length ?? selected.size}</div>
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={singleAssignOpen}
        onClose={() => setSingleAssignOpen(false)}
        onConfirm={(reason) => createAssignment.mutate(reason)}
        title="创建单个角色分配"
        description={`将为用户 ${selectedUserId ?? '—'} 分配「${selectedRole?.name ?? roleId}」。`}
        confirmLabel="确认创建"
        busy={createAssignment.isPending}
        error={
          createAssignment.isError
            ? errorMessage(createAssignment.error)
            : null
        }
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          <div>用户：{selectedUserId ?? '未选择'}</div>
          <div>数据边界：{boundaryType}</div>
          <div>过期时间：{expiresAt ? formatDateTime(toRfc3339(expiresAt)) : '永久'}</div>
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={(reason) => {
          if (revokeTarget) revokeAssignment.mutate({ assignment: revokeTarget, reason })
        }}
        title="撤销角色分配"
        description="撤销后该用户会失去对应角色带来的权限。"
        confirmLabel="确认撤销"
        tone="danger"
        busy={revokeAssignment.isPending}
        error={
          revokeAssignment.isError
            ? errorMessage(revokeAssignment.error)
            : null
        }
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px]">
          assignment {revokeTarget?.id} · 角色 {revokeTarget?.role_id}
        </div>
      </ReasonDialog>
    </div>
  )
}
