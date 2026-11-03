import { Mail, RefreshCw, Save } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Field, Input, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { api } from '../../lib/api'
import { useApiMutation } from '../../lib/mutations'

type EmailForm = {
  driver: string
  from: string
  smtpHost: string
  smtpPort: string
  smtpUsername: string
  smtpPassword: string
}

const EMPTY_FORM: EmailForm = {
  driver: 'console',
  from: '',
  smtpHost: '',
  smtpPort: '587',
  smtpUsername: '',
  smtpPassword: '',
}

export function AdminEmailSettingsPage() {
  const [form, setForm] = useState<EmailForm>(EMPTY_FORM)
  const [saveOpen, setSaveOpen] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const settingsQuery = useQuery({
    queryKey: ['admin', 'settings', 'email'],
    queryFn: () => api.settings.email(),
    retry: false,
  })

  useEffect(() => {
    const data = settingsQuery.data
    if (!data) return
    setForm({
      driver: data.driver ?? 'console',
      from: data.from ?? '',
      smtpHost: data.smtp_host ?? '',
      smtpPort: String(data.smtp_port ?? 587),
      smtpUsername: data.smtp_username ?? '',
      smtpPassword: '',
    })
  }, [settingsQuery.data])

  const saveSettings = useApiMutation({
    mutationFn: (reason: string) =>
      api.settings.updateEmail({
        driver: form.driver,
        from: form.from.trim(),
        smtp_host: form.smtpHost.trim(),
        smtp_port: Number(form.smtpPort) || 0,
        smtp_username: form.smtpUsername.trim(),
        smtp_password: form.smtpPassword,
        update_mask: 'all',
        expected_revision: settingsQuery.data?.revision ?? '0',
        reason,
      }),
    successMessage: '邮件配置已更新',
    successDescription: '新的邮件驱动在后续发送时生效。',
    invalidate: [['admin', 'settings', 'email']],
    onSuccess: () => {
      setSaveOpen(false)
      setForm((current) => ({ ...current, smtpPassword: '' }))
    },
  })

  const validate = (): string | null => {
    if (form.driver !== 'console' && form.driver !== 'smtp') {
      return '邮件驱动只能是 console 或 smtp'
    }
    if (form.driver === 'smtp') {
      if (!form.smtpHost.trim()) return 'SMTP 主机不能为空'
      const port = Number(form.smtpPort)
      if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        return 'SMTP 端口必须为 1-65535'
      }
    }
    return null
  }

  const openSave = () => {
    const error = validate()
    if (error) {
      setFormError(error)
      return
    }
    setFormError(null)
    setSaveOpen(true)
  }

  return (
    <div className="space-y-4">
      <PageTitle title="邮件配置" />
      <PageHeader
        eyebrow="Settings"
        title="邮件配置"
        description="注册验证、密码重置与激活邮件的发送通道。密钥只接受写入，不会回显。"
        actions={
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void settingsQuery.refetch()}
              loading={settingsQuery.isFetching}
              icon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              刷新
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={openSave}
              disabled={settingsQuery.isPending}
              icon={<Save className="h-3.5 w-3.5" />}
            >
              保存配置
            </Button>
          </div>
        }
      />

      <QueryBoundary query={settingsQuery} loadingLabel="读取邮件配置…">
        <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader
              title="发送通道"
              description="console 驱动仅记录发送元信息，不投递邮件。实际验证流程请配置 SMTP。"
              actions={
                <Badge
                  tone={
                    settingsQuery.data?.password_configured ? 'success' : 'neutral'
                  }
                >
                  {settingsQuery.data?.password_configured
                    ? 'SMTP 密钥已配置'
                    : '未配置 SMTP 密钥'}
                </Badge>
              }
            />
            <CardContent className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="驱动" htmlFor="email-driver" required>
                  <Select
                    id="email-driver"
                    value={form.driver}
                    onChange={(event) =>
                      setForm({ ...form, driver: event.target.value })
                    }
                  >
                    <option value="console">console（仅记录元信息）</option>
                    <option value="smtp">smtp</option>
                  </Select>
                </Field>
                <Field label="发件人" htmlFor="email-from">
                  <Input
                    id="email-from"
                    value={form.from}
                    onChange={(event) =>
                      setForm({ ...form, from: event.target.value })
                    }
                    placeholder="no-reply@example.com"
                  />
                </Field>
                <Field label="SMTP 主机" htmlFor="email-host">
                  <Input
                    id="email-host"
                    value={form.smtpHost}
                    onChange={(event) =>
                      setForm({ ...form, smtpHost: event.target.value })
                    }
                    placeholder="smtp.example.com"
                    disabled={form.driver !== 'smtp'}
                  />
                </Field>
                <Field label="SMTP 端口" htmlFor="email-port">
                  <Input
                    id="email-port"
                    value={form.smtpPort}
                    onChange={(event) =>
                      setForm({ ...form, smtpPort: event.target.value })
                    }
                    inputMode="numeric"
                    disabled={form.driver !== 'smtp'}
                  />
                </Field>
                <Field label="SMTP 用户名" htmlFor="email-username">
                  <Input
                    id="email-username"
                    value={form.smtpUsername}
                    onChange={(event) =>
                      setForm({ ...form, smtpUsername: event.target.value })
                    }
                    autoComplete="off"
                    disabled={form.driver !== 'smtp'}
                  />
                </Field>
                <Field
                  label="SMTP 密码"
                  htmlFor="email-password"
                  hint={
                    settingsQuery.data?.password_configured
                      ? '已配置；留空保持现有密钥'
                      : '只写字段，保存后不会回显'
                  }
                >
                  <Input
                    id="email-password"
                    type="password"
                    value={form.smtpPassword}
                    onChange={(event) =>
                      setForm({ ...form, smtpPassword: event.target.value })
                    }
                    autoComplete="new-password"
                    placeholder={
                      settingsQuery.data?.password_configured
                        ? '••••••••（留空保持不变）'
                        : '输入 SMTP 密码'
                    }
                    disabled={form.driver !== 'smtp'}
                  />
                </Field>
              </div>
              {formError ? (
                <InlineAlert tone="danger">{formError}</InlineAlert>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="当前值" description="服务端返回的非敏感配置摘要。" />
            <CardContent className="space-y-2 text-xs">
              <div className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
                <span className="text-slate-500">驱动</span>
                <Badge tone={settingsQuery.data?.driver === 'smtp' ? 'info' : 'neutral'}>
                  {settingsQuery.data?.driver ?? '—'}
                </Badge>
              </div>
              <div className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
                <span className="text-slate-500">发件人</span>
                <span className="font-mono text-[11px] text-slate-800">
                  {settingsQuery.data?.from || '—'}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
                <span className="text-slate-500">SMTP</span>
                <span className="font-mono text-[11px] text-slate-800">
                  {settingsQuery.data?.smtp_host || '—'}:
                  {settingsQuery.data?.smtp_port ?? '—'}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
                <span className="text-slate-500">revision</span>
                <span className="font-mono text-[11px] text-slate-800">
                  {settingsQuery.data?.revision ?? '—'}
                </span>
              </div>
              <InlineAlert tone="info" title="验证码发送">
                console 驱动不会投递邮件，也不会记录验证码或重置链接。验证注册、换绑或找回密码时请使用 SMTP 测试邮箱。
              </InlineAlert>
              <div className="flex items-center gap-1 text-[10px] text-slate-400">
                <Mail className="h-3 w-3" />
                密钥不会出现在 API 响应或前端状态持久化中
              </div>
            </CardContent>
          </Card>
        </div>
      </QueryBoundary>

      <ReasonDialog
        open={saveOpen}
        onClose={() => setSaveOpen(false)}
        onConfirm={(reason) => saveSettings.mutate(reason)}
        title="保存邮件配置"
        description="保存后新的发送请求会使用更新后的通道。"
        confirmLabel="确认保存"
        busy={saveSettings.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          <div>驱动：{form.driver}</div>
          <div>发件人：{form.from || '—'}</div>
          <div>
            SMTP：{form.driver === 'smtp' ? `${form.smtpHost}:${form.smtpPort}` : '不启用'}
          </div>
          <div>密钥：{form.smtpPassword ? '将轮换' : '保持不变'}</div>
        </div>
      </ReasonDialog>
    </div>
  )
}
