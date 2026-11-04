import {
  AtSign,
  BadgeCheck,
  CalendarClock,
  Fingerprint,
  Mail,
  Pencil,
  ShieldCheck,
  UserRound,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { useState } from 'react'

import { Button } from '../../components/button'
import { Card, CardContent, CardHeader } from '../../components/card'
import { PageTitle } from '../../app/guards'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
import { Badge, StatusBadge } from '../../components/badge'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'

function InfoRow({
  label,
  value,
  icon,
}: {
  label: string
  value: ReactNode
  icon?: ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 py-2.5 last:border-0">
      <dt className="flex items-center gap-1.5 text-xs text-slate-500">
        {icon}
        {label}
      </dt>
      <dd className="min-w-0 text-right text-xs font-medium text-slate-800">
        {value}
      </dd>
    </div>
  )
}

export function ProfilePage() {
  const { user, refresh } = useAuth()
  const [editing, setEditing] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [usernameOpen, setUsernameOpen] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [usernameReason, setUsernameReason] = useState('')
  const [usernameError, setUsernameError] = useState('')

  const updateProfile = useApiMutation({
    mutationFn: (name: string) =>
      api.me.update({
        display_name: name,
        update_mask: 'display_name',
        expected_revision: user?.revision ?? '0',
      }),
    successMessage: '昵称已更新',
    refreshAuth: true,
    onSuccess: () => {
      setEditing(false)
      void refresh(true)
    },
  })

  const updateUsername = useApiMutation({
    mutationFn: () =>
      api.me.updateUsername({
        username: newUsername.trim(),
        current_password: currentPassword,
        expected_revision: user?.revision ?? '0',
        reason: usernameReason.trim() || '用户自助修改用户名',
      }),
    successMessage: '用户名已更新',
    successDescription: '旧用户名已无法登录，变更已写入审计。',
    refreshAuth: true,
    onSuccess: () => {
      setUsernameOpen(false)
      setCurrentPassword('')
      setUsernameError('')
      void refresh(true)
    },
    onError: (cause) => setUsernameError(cause.message),
  })

  if (!user) return null

  const openEditor = () => {
    setDisplayName(user.display_name ?? '')
    setEditing(true)
  }

  const save = () => {
    const next = displayName.trim()
    if (!next) return
    updateProfile.mutate(next)
  }

  return (
    <div className="space-y-4">
      <PageTitle title="个人资料" />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            个人资料
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            查看账号身份信息，并维护展示昵称。
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setNewUsername('')
              setUsernameError('')
              setUsernameOpen(true)
            }}
          >
            修改用户名
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={openEditor}
            icon={<Pencil className="h-3.5 w-3.5" />}
          >
            编辑昵称
          </Button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <Card>
          <div className="flex flex-wrap items-center gap-4 border-b border-slate-100 p-4">
            <span className="grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 text-xl font-semibold text-white shadow-sm">
              {(user.display_name || user.username || '?').slice(0, 1)}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate text-base font-semibold text-slate-900">
                  {user.display_name || user.username}
                </h2>
                <StatusBadge status={user.status} />
                {user.mfa_enabled ? (
                  <Badge tone="success" dot>
                    MFA 已启用
                  </Badge>
                ) : (
                  <Badge tone="warning" dot>
                    MFA 未启用
                  </Badge>
                )}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                <span className="inline-flex items-center gap-1">
                  <AtSign className="h-3 w-3" />
                  {user.username}
                </span>
                <span className="inline-flex items-center gap-1">
                  <Mail className="h-3 w-3" />
                  {user.email || '未绑定邮箱'}
                </span>
              </div>
            </div>
          </div>
          <CardContent>
            <div className="mb-3 text-xs font-semibold text-slate-700">
              角色
            </div>
            <div className="flex flex-wrap gap-1.5">
              {user.roles?.length ? (
                user.roles.map((role) => (
                  <Badge key={role.id} tone="violet">
                    <ShieldCheck className="h-3 w-3" />
                    {role.name || role.code}
                  </Badge>
                ))
              ) : (
                <span className="text-xs text-slate-500">未分配角色</span>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader title="账号标识" description="服务端生成的只读标识" />
          <CardContent className="py-1">
            <dl>
              <InfoRow
                label="用户 ID"
                icon={<Fingerprint className="h-3 w-3" />}
                value={<span className="font-mono">{user.id}</span>}
              />
              <InfoRow
                label="身份版本"
                value={<span className="font-mono">{user.identity_version}</span>}
              />
              <InfoRow
                label="数据版本"
                value={<span className="font-mono">{user.revision}</span>}
              />
              <InfoRow
                label="创建时间"
                icon={<CalendarClock className="h-3 w-3" />}
                value={formatDateTime(user.created_at)}
              />
              <InfoRow
                label="更新时间"
                value={formatDateTime(user.updated_at)}
              />
            </dl>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="账号详情"
          description="邮箱与状态由组织策略控制，变更邮箱请前往安全中心验证。"
        />
        <CardContent className="py-1">
          <dl className="grid gap-x-8 md:grid-cols-2">
            <InfoRow
              label="用户名"
              icon={<UserRound className="h-3 w-3" />}
              value={user.username}
            />
            <InfoRow
              label="邮箱"
              icon={<Mail className="h-3 w-3" />}
              value={
                <span className="inline-flex items-center gap-1.5">
                  {user.email || '—'}
                  {user.email_verified ? (
                    <Badge tone="success">
                      <BadgeCheck className="h-3 w-3" />
                      已验证
                    </Badge>
                  ) : (
                    <Badge tone="warning">未验证</Badge>
                  )}
                </span>
              }
            />
            <InfoRow label="状态" value={<StatusBadge status={user.status} />} />
            <InfoRow
              label="归档时间"
              value={formatDateTime(user.archived_at)}
            />
          </dl>
        </CardContent>
      </Card>

      <Dialog
        open={editing}
        onClose={() => setEditing(false)}
        title="编辑昵称"
        description="昵称会展示在账号中心与管理控制台，长度 1-64 个字符。"
        size="sm"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditing(false)}
              disabled={updateProfile.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={save}
              loading={updateProfile.isPending}
              disabled={!displayName.trim()}
            >
              保存
            </Button>
          </>
        }
      >
        <Field
          label="显示昵称"
          htmlFor="profile-display-name"
          required
          hint="使用当前数据版本提交，若被其他人修改会提示冲突。"
        >
          <Input
            id="profile-display-name"
            value={displayName}
            maxLength={64}
            onChange={(event) => setDisplayName(event.target.value)}
            placeholder="输入昵称"
          />
        </Field>
      </Dialog>

      <Dialog
        open={usernameOpen}
        onClose={() => setUsernameOpen(false)}
        title="修改用户名"
        description="需要近期安全验证与当前密码；规则与注册一致，管理端不能代改。"
        size="sm"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setUsernameOpen(false)}>
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              loading={updateUsername.isPending}
              disabled={newUsername.trim().length < 3 || !currentPassword}
              onClick={() => void updateUsername.mutateAsync()}
            >
              确认修改
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <Field label="新用户名" htmlFor="profile-new-username">
            <Input
              id="profile-new-username"
              value={newUsername}
              onChange={(event) => setNewUsername(event.target.value)}
              placeholder="3-128 位字母、数字、_. -"
            />
          </Field>
          <Field label="当前密码" htmlFor="profile-current-password">
            <Input
              id="profile-current-password"
              type="password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
            />
          </Field>
          <Field label="原因" htmlFor="profile-username-reason">
            <Input
              id="profile-username-reason"
              value={usernameReason}
              onChange={(event) => setUsernameReason(event.target.value)}
              placeholder="用于审计留痕"
            />
          </Field>
          {usernameError ? (
            <p className="text-xs text-rose-600">{usernameError}</p>
          ) : null}
        </div>
      </Dialog>
    </div>
  )
}
