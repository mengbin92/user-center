import {
  Download,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Users,
} from 'lucide-react'
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
import { Checkbox, Field, Input, Select, Textarea } from '../../components/input'
import { ReasonDialog } from '../../components/reason-dialog'
import { QueryBoundary } from '../../components/query-state'
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
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { ExportJob } from '../../lib/types'
import { useAllRoles } from './common'

const EXPORT_FIELDS: Array<{ key: string; label: string; hint?: string }> = [
  { key: 'id', label: '用户 ID' },
  { key: 'username', label: '用户名' },
  { key: 'display_name', label: '昵称' },
  { key: 'status', label: '状态' },
  { key: 'mfa_enabled', label: 'MFA 状态' },
  { key: 'created_at', label: '创建时间' },
  { key: 'roles', label: '角色代码' },
  { key: 'email', label: '邮箱', hint: '需要 contact.read 权限' },
  { key: 'email_verified', label: '邮箱已验证' },
]

export function AdminUsersPage() {
  const navigate = useNavigate()
  const { can } = useAuth()
  const rolesQuery = useAllRoles()

  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [status, setStatus] = useState('')
  const [mfa, setMfa] = useState('any')
  const [roleId, setRoleId] = useState('')
  const [tokens, setTokens] = useState<string[]>([''])
  const token = tokens[tokens.length - 1] ?? ''

  const usersQuery = useQuery({
    queryKey: [
      'admin',
      'users',
      { keyword, status, mfa, roleId, pageToken: token },
    ],
    queryFn: () =>
      api.admin.listUsers({
        keyword: keyword || undefined,
        status: status || undefined,
        mfa_enabled: mfa === 'any' ? undefined : mfa,
        role_id: roleId || undefined,
        page_size: 20,
        page_token: token || undefined,
      }),
    retry: false,
    placeholderData: keepPreviousData,
  })

  const applySearch = (event?: FormEvent) => {
    event?.preventDefault()
    setKeyword(keywordInput.trim())
    setTokens([''])
  }

  const resetFilters = () => {
    setKeywordInput('')
    setKeyword('')
    setStatus('')
    setMfa('any')
    setRoleId('')
    setTokens([''])
  }

  // Create user
  const [createOpen, setCreateOpen] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [initialPassword, setInitialPassword] = useState('')
  const [sendActivation, setSendActivation] = useState(true)
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(new Set())
  const [createReason, setCreateReason] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const createUser = useApiMutation({
    mutationFn: () =>
      api.admin.createUser({
        username: username.trim(),
        email: email.trim(),
        display_name: displayName.trim() || undefined,
        initial_password: initialPassword || undefined,
        send_activation: sendActivation,
        role_ids: [...selectedRoles],
        reason: createReason.trim(),
      }),
    successMessage: '用户已创建',
    invalidate: [
      ['admin', 'users'],
      ['admin', 'overview'],
    ],
    refreshAuth: false,
    onSuccess: (user) => {
      setCreateOpen(false)
      resetCreateForm()
      if (user.id) navigate(`/admin/users/${user.id}`)
    },
  })

  const resetCreateForm = () => {
    setUsername('')
    setEmail('')
    setDisplayName('')
    setInitialPassword('')
    setSendActivation(true)
    setSelectedRoles(new Set())
    setCreateReason('')
    setFormError(null)
  }

  const submitCreate = () => {
    setFormError(null)
    if (!username.trim()) {
      setFormError('请输入用户名')
      return
    }
    if (!sendActivation && initialPassword.length < 10) {
      setFormError('不发送激活邮件时，必须设置至少 10 位的初始密码')
      return
    }
    if (sendActivation && !email.trim()) {
      setFormError('发送激活邮件时必须填写邮箱')
      return
    }
    if (createReason.trim().length < 2) {
      setFormError('请填写创建原因（至少 2 个字符）')
      return
    }
    createUser.mutate(undefined)
  }

  const toggleRole = (id: string) => {
    setSelectedRoles((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // Export
  const [exportOpen, setExportOpen] = useState(false)
  const [exportFields, setExportFields] = useState<Set<string>>(
    new Set(['id', 'username', 'display_name', 'status', 'mfa_enabled', 'created_at']),
  )

  const exportUsers = useApiMutation({
    mutationFn: (reason: string) =>
      api.admin.exportUsers({
        keyword: keyword || undefined,
        status: status || undefined,
        role_id: roleId || undefined,
        mfa_enabled: mfa === 'any' ? undefined : mfa,
        fields: [...exportFields],
        reason,
      }),
    successMessage: '导出任务已创建',
    successDescription: '前往导出任务列表下载 CSV。',
    onSuccess: (job: ExportJob) => {
      setExportOpen(false)
      navigate(`/admin/exports?highlight=${job.id ?? ''}`)
    },
  })

  const toggleExportField = (key: string) => {
    setExportFields((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const items = usersQuery.data?.items ?? []
  const nextToken = usersQuery.data?.meta?.next_page_token
  const roles = rolesQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="用户管理" />
      <PageHeader
        eyebrow="Identity"
        title="用户管理"
        description="按关键字、状态、MFA 与角色筛选账号。列表受数据范围约束。"
        actions={
          <>
            {can('identity.user.export') ? (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setExportOpen(true)}
                icon={<Download className="h-3.5 w-3.5" />}
              >
                导出
              </Button>
            ) : null}
            {can('identity.user.create') ? (
              <Button
                size="sm"
                variant="primary"
                onClick={() => {
                  resetCreateForm()
                  setCreateOpen(true)
                }}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                创建用户
              </Button>
            ) : null}
          </>
        }
      />

      <Card className="p-3">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={applySearch}
        >
          <div className="min-w-[200px] flex-1">
            <Field label="搜索" htmlFor="user-keyword">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                <Input
                  id="user-keyword"
                  value={keywordInput}
                  onChange={(event) => setKeywordInput(event.target.value)}
                  placeholder="用户名、昵称或邮箱"
                  className="pl-8"
                />
              </div>
            </Field>
          </div>
          <Field label="状态" htmlFor="user-status" className="w-28">
            <Select
              id="user-status"
              value={status}
              onChange={(event) => {
                setStatus(event.target.value)
                setTokens([''])
              }}
            >
              <option value="">全部</option>
              <option value="enabled">已启用</option>
              <option value="disabled">已禁用</option>
              <option value="archived">已归档</option>
            </Select>
          </Field>
          <Field label="MFA" htmlFor="user-mfa" className="w-28">
            <Select
              id="user-mfa"
              value={mfa}
              onChange={(event) => {
                setMfa(event.target.value)
                setTokens([''])
              }}
            >
              <option value="any">全部</option>
              <option value="true">已启用</option>
              <option value="false">未启用</option>
            </Select>
          </Field>
          <Field label="角色" htmlFor="user-role" className="w-40">
            <Select
              id="user-role"
              value={roleId}
              onChange={(event) => {
                setRoleId(event.target.value)
                setTokens([''])
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
          <div className="flex gap-2">
            <Button type="submit" size="sm" variant="primary">
              搜索
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={resetFilters}
            >
              重置
            </Button>
            <Button
              type="button"
              size="icon"
              variant="ghost"
              onClick={() => void usersQuery.refetch()}
              aria-label="刷新列表"
              title="刷新列表"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        </form>
      </Card>

      <Card>
        <QueryBoundary query={usersQuery} loadingLabel="读取用户列表…">
          {items.length === 0 ? (
            <EmptyState
              title="没有匹配的用户"
              description="调整搜索条件，或创建一个新账号。"
              icon={Users}
              action={
                can('identity.user.create') ? (
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => {
                      resetCreateForm()
                      setCreateOpen(true)
                    }}
                  >
                    创建用户
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <>
              <Table minWidth="min-w-[900px]">
                <THead>
                  <TR>
                    <TH>用户</TH>
                    <TH>邮箱</TH>
                    <TH>状态</TH>
                    <TH>MFA</TH>
                    <TH>角色</TH>
                    <TH>revision</TH>
                    <TH>创建时间</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {items.map((user) => (
                    <TR
                      key={user.id}
                      onClick={() => navigate(`/admin/users/${user.id}`)}
                    >
                      <TD>
                        <div className="flex items-center gap-2">
                          <span className="grid h-7 w-7 place-items-center rounded-full bg-slate-100 text-[11px] font-semibold text-slate-600">
                            {(user.display_name || user.username || '?').slice(0, 1)}
                          </span>
                          <div className="min-w-0">
                            <div className="max-w-[180px] truncate text-xs font-medium text-slate-800">
                              {user.display_name || user.username}
                            </div>
                            <div className="font-mono text-[10px] text-slate-400">
                              @{user.username} · id={user.id}
                            </div>
                          </div>
                        </div>
                      </TD>
                      <TD className="max-w-[200px] truncate text-[11px] text-slate-600">
                        {user.email || '—'}
                      </TD>
                      <TD>
                        <StatusBadge status={user.status} />
                      </TD>
                      <TD>
                        {user.mfa_enabled ? (
                          <Badge tone="success">
                            <ShieldCheck className="h-3 w-3" /> 已启用
                          </Badge>
                        ) : (
                          <Badge tone="neutral">未启用</Badge>
                        )}
                      </TD>
                      <TD>
                        <div className="flex max-w-[200px] flex-wrap gap-1">
                          {user.roles?.length ? (
                            user.roles.slice(0, 3).map((role) => (
                              <Badge key={role.id} tone="violet">
                                {role.name || role.code}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-[11px] text-slate-400">—</span>
                          )}
                          {user.roles && user.roles.length > 3 ? (
                            <Badge tone="neutral">+{user.roles.length - 3}</Badge>
                          ) : null}
                        </div>
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-500">
                        {user.revision}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(user.created_at)}
                      </TD>
                      <TD className="text-right">
                        <Link
                          to={`/admin/users/${user.id}`}
                          onClick={(event) => event.stopPropagation()}
                          className="text-[11px] font-medium text-indigo-700 hover:underline"
                        >
                          详情
                        </Link>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                total={usersQuery.data?.meta?.total_size}
                pageIndex={tokens.length}
                hasNext={Boolean(nextToken)}
                onPrev={() =>
                  setTokens((current) =>
                    current.length > 1 ? current.slice(0, -1) : current,
                  )
                }
                onNext={() => {
                  if (nextToken) setTokens((current) => [...current, nextToken])
                }}
                onRefresh={() => void usersQuery.refetch()}
                loading={usersQuery.isFetching}
              />
            </>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="创建用户"
        description="创建后会写入审计。未选择角色时默认授予 member。"
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createUser.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitCreate}
              loading={createUser.isPending}
            >
              创建用户
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="用户名" htmlFor="create-username" required>
            <Input
              id="create-username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="登录用户名"
            />
          </Field>
          <Field label="邮箱" htmlFor="create-email">
            <Input
              id="create-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="user@example.com"
            />
          </Field>
          <Field label="显示昵称" htmlFor="create-display-name">
            <Input
              id="create-display-name"
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              placeholder="默认与用户名相同"
            />
          </Field>
          <Field
            label="初始密码"
            htmlFor="create-password"
            hint="留空则不设置本地密码"
          >
            <Input
              id="create-password"
              type="password"
              autoComplete="new-password"
              value={initialPassword}
              onChange={(event) => setInitialPassword(event.target.value)}
              placeholder="至少 10 位"
            />
          </Field>
        </div>

        <Checkbox
          checked={sendActivation}
          onChange={(event) => setSendActivation(event.target.checked)}
          label="发送激活邮件（用户通过邮件设置密码）"
        />

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            分配角色
          </div>
          <div className="grid max-h-40 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {roles.map((role) => (
              <label
                key={role.id}
                className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                  checked={selectedRoles.has(role.id ?? '')}
                  onChange={() => toggleRole(role.id ?? '')}
                />
                <span className="truncate text-slate-700">{role.name}</span>
                <span className="font-mono text-[10px] text-slate-400">
                  {role.code}
                </span>
              </label>
            ))}
            {roles.length === 0 ? (
              <span className="text-[11px] text-slate-500">暂无可用角色</span>
            ) : null}
          </div>
        </div>

        <Field
          label="操作原因"
          htmlFor="create-reason"
          required
          hint="写入审计日志，至少 2 个字符。"
        >
          <Textarea
            id="create-reason"
            value={createReason}
            onChange={(event) => setCreateReason(event.target.value)}
            rows={2}
            placeholder="例如：新员工入职，工单 HR-2048"
          />
        </Field>

        {formError ? (
          <InlineAlert tone="danger">{formError}</InlineAlert>
        ) : null}
      </Dialog>

      <ReasonDialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        onConfirm={(reason) => {
          if (exportFields.size > 0) exportUsers.mutate(reason)
        }}
        title="导出用户 CSV"
        description="应用当前的关键字、状态、角色与 MFA 筛选生成导出文件，产物 24 小时内可下载。"
        confirmLabel="创建导出任务"
        busy={exportUsers.isPending}
        hint="导出原因会写入审计日志。"
      >
        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            导出字段
          </div>
          <div className="grid gap-1 rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {EXPORT_FIELDS.filter(
              (field) =>
                field.key !== 'email' ||
                can('identity.user.contact.read'),
            )
              .filter(
                (field) =>
                  field.key !== 'email_verified' ||
                  can('identity.user.contact.read'),
              )
              .map((field) => (
              <label
                key={field.key}
                className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
                  checked={exportFields.has(field.key)}
                  onChange={() => toggleExportField(field.key)}
                />
                <span className="text-slate-700">{field.label}</span>
                {field.hint ? (
                  <span className="text-[10px] text-amber-600">{field.hint}</span>
                ) : null}
              </label>
              ))}
          </div>
        </div>
        {exportFields.size === 0 ? (
          <InlineAlert tone="warning">至少选择一个导出字段。</InlineAlert>
        ) : null}
      </ReasonDialog>
    </div>
  )
}
