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
import type { Assignment, BatchPreviewReply, Scope } from '../../lib/types'
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
  const [assignResultCount, setAssignResultCount] = useState<number | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<Assignment | null>(null)

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

  const selectedUserId = selected.size === 1 ? [...selected][0] : null

  const userRolesQuery = useQuery({
    queryKey: ['admin', 'assignments', 'user-roles', selectedUserId],
    queryFn: () => api.admin.userRoles(selectedUserId ?? ''),
    enabled: Boolean(selectedUserId),
    retry: false,
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
    onSuccess: async (data) => {
      setAssignOpen(false)
      setPreview(null)
      setAssignResultCount(data.assignments?.length ?? 0)
      setSelected(new Set())
      await Promise.all([
        usersQuery.refetch(),
        userRolesQuery.refetch(),
      ])
    },
  })

  const revokeAssignment = useApiMutation({
    mutationFn: (input: { assignment: Assignment; reason: string }) =>
      api.iam.revokeAssignment(input.assignment.id ?? '', {
        id: input.assignment.id,
        reason: input.reason,
        expected_policy_revision: authorization?.policy_revision ?? undefined,
      }),
    successMessage: '角色分配已撤销',
    refreshAuth: true,
    onSuccess: async () => {
      setRevokeTarget(null)
      await userRolesQuery.refetch()
    },
  })

  const roles = rolesQuery.data?.items ?? []
  const selectedRole = roleById(roles, roleId)
  const users = usersQuery.data?.items ?? []

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
        description="为用户批量分配角色。先预览资格与冲突，再提交带原因的分配。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              void rolesQuery.refetch()
              if (selectedUserId) void userRolesQuery.refetch()
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
          title="当前用户的角色分配"
          description={
            selected.size === 1
              ? '显示所选用户的有效与历史分配，可撤销。'
              : '只勾选一个用户时展示其角色分配。'
          }
          actions={
            selectedUserId ? (
              <Badge tone="info">用户 {selectedUserId}</Badge>
            ) : undefined
          }
        />
        {!selectedUserId ? (
          <EmptyState
            title="选择一个用户"
            description="勾选单个用户后查看其现有授权。"
            icon={Users}
          />
        ) : (
          <QueryBoundary query={userRolesQuery} loadingLabel="读取用户授权…">
            {userRolesQuery.data?.items?.length ? (
              <Table minWidth="min-w-[760px]">
                <THead>
                  <TR>
                    <TH>角色</TH>
                    <TH>数据范围</TH>
                    <TH>生效</TH>
                    <TH>过期</TH>
                    <TH>状态</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {userRolesQuery.data.items.map((assignment) => {
                    const role = roleById(roles, assignment.role_id)
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
                          {!assignment.revoked ? (
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
                    )
                  })}
                </TBody>
              </Table>
            ) : (
              <EmptyState title="该用户暂无角色分配" />
            )}
          </QueryBoundary>
        )}
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
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px]">
          assignment {revokeTarget?.id} · 角色 {revokeTarget?.role_id}
        </div>
      </ReasonDialog>
    </div>
  )
}
