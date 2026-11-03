import { RefreshCw, Save, Settings2 } from 'lucide-react'
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
import { Field, Input, Switch, Textarea } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { api } from '../../lib/api'
import { splitList } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'

type AuthForm = {
  registrationEnabled: boolean
  emailVerificationRequired: boolean
  passwordMinLength: string
  sessionTtlMinutes: string
  idleTimeoutMinutes: string
  mfaRequiredForAdmins: boolean
  allowedEmailDomains: string
  providers: string
}

const EMPTY_FORM: AuthForm = {
  registrationEnabled: true,
  emailVerificationRequired: true,
  passwordMinLength: '10',
  sessionTtlMinutes: '720',
  idleTimeoutMinutes: '60',
  mfaRequiredForAdmins: true,
  allowedEmailDomains: '',
  providers: '',
}

export function AdminAuthSettingsPage() {
  const [form, setForm] = useState<AuthForm>(EMPTY_FORM)
  const [saveOpen, setSaveOpen] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const settingsQuery = useQuery({
    queryKey: ['admin', 'settings', 'auth'],
    queryFn: () => api.settings.auth(),
    retry: false,
  })

  useEffect(() => {
    const data = settingsQuery.data
    if (!data) return
    setForm({
      registrationEnabled: data.registration_enabled ?? true,
      emailVerificationRequired: data.email_verification_required ?? true,
      passwordMinLength: String(data.password_min_length ?? 10),
      sessionTtlMinutes: String(data.session_ttl_minutes ?? 720),
      idleTimeoutMinutes: String(data.idle_timeout_minutes ?? 60),
      mfaRequiredForAdmins: data.mfa_required_for_admins ?? true,
      allowedEmailDomains: (data.allowed_email_domains ?? []).join(', '),
      providers: (data.providers ?? []).join(', '),
    })
  }, [settingsQuery.data])

  const saveSettings = useApiMutation({
    mutationFn: (reason: string) =>
      api.settings.updateAuth({
        registration_enabled: form.registrationEnabled,
        email_verification_required: form.emailVerificationRequired,
        password_min_length: Number(form.passwordMinLength) || 0,
        session_ttl_minutes: Number(form.sessionTtlMinutes) || 0,
        idle_timeout_minutes: Number(form.idleTimeoutMinutes) || 0,
        mfa_required_for_admins: form.mfaRequiredForAdmins,
        allowed_email_domains: splitList(form.allowedEmailDomains),
        providers: splitList(form.providers),
        update_mask: 'all',
        expected_revision: settingsQuery.data?.revision ?? '0',
        reason,
      }),
    successMessage: '认证配置已更新',
    successDescription: '新的登录与会话策略立即生效。',
    invalidate: [['admin', 'settings', 'auth'], ['auth', 'context']],
    refreshAuth: true,
    onSuccess: () => setSaveOpen(false),
  })

  const validate = (): string | null => {
    const passwordMin = Number(form.passwordMinLength)
    const sessionTtl = Number(form.sessionTtlMinutes)
    const idle = Number(form.idleTimeoutMinutes)
    if (!Number.isInteger(passwordMin) || passwordMin < 8 || passwordMin > 72) {
      return '密码最小长度必须为 8-72'
    }
    if (!Number.isInteger(sessionTtl) || sessionTtl < 5 || sessionTtl > 43200) {
      return '会话有效期必须为 5-43200 分钟'
    }
    if (!Number.isInteger(idle) || idle < 5 || idle > sessionTtl) {
      return '闲置超时必须在 5 分钟到会话有效期之间'
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
      <PageTitle title="认证配置" />
      <PageHeader
        eyebrow="Settings"
        title="认证配置"
        description="注册、密码、会话生命周期与 MFA 策略。变更会立即影响所有账号。"
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

      <QueryBoundary query={settingsQuery} loadingLabel="读取认证配置…">
        <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader
              title="注册与验证"
              description="控制自助注册与邮箱验证要求。"
              actions={
                <Badge tone="outline">
                  revision {settingsQuery.data?.revision ?? '—'}
                </Badge>
              }
            />
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-6 rounded-md border border-slate-200 bg-slate-50 p-3">
                <Switch
                  checked={form.registrationEnabled}
                  onCheckedChange={(checked) =>
                    setForm({ ...form, registrationEnabled: checked })
                  }
                  label="开放自助注册"
                />
                <Switch
                  checked={form.emailVerificationRequired}
                  onCheckedChange={(checked) =>
                    setForm({ ...form, emailVerificationRequired: checked })
                  }
                  label="注册必须验证邮箱"
                />
                <Switch
                  checked={form.mfaRequiredForAdmins}
                  onCheckedChange={(checked) =>
                    setForm({ ...form, mfaRequiredForAdmins: checked })
                  }
                  label="管理员强制 MFA"
                />
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <Field
                  label="密码最小长度"
                  htmlFor="settings-password-min"
                  hint="8-72"
                >
                  <Input
                    id="settings-password-min"
                    value={form.passwordMinLength}
                    onChange={(event) =>
                      setForm({ ...form, passwordMinLength: event.target.value })
                    }
                    inputMode="numeric"
                  />
                </Field>
                <Field
                  label="会话有效期（分钟）"
                  htmlFor="settings-session-ttl"
                  hint="5-43200"
                >
                  <Input
                    id="settings-session-ttl"
                    value={form.sessionTtlMinutes}
                    onChange={(event) =>
                      setForm({ ...form, sessionTtlMinutes: event.target.value })
                    }
                    inputMode="numeric"
                  />
                </Field>
                <Field
                  label="闲置超时（分钟）"
                  htmlFor="settings-idle"
                  hint="不超过会话有效期"
                >
                  <Input
                    id="settings-idle"
                    value={form.idleTimeoutMinutes}
                    onChange={(event) =>
                      setForm({ ...form, idleTimeoutMinutes: event.target.value })
                    }
                    inputMode="numeric"
                  />
                </Field>
              </div>

              <Field
                label="允许注册的邮箱域名"
                htmlFor="settings-domains"
                hint="逗号或换行分隔；留空表示不限制"
              >
                <Textarea
                  id="settings-domains"
                  value={form.allowedEmailDomains}
                  onChange={(event) =>
                    setForm({ ...form, allowedEmailDomains: event.target.value })
                  }
                  rows={2}
                  placeholder="example.com, corp.example.com"
                />
              </Field>

              <Field
                label="启用的身份提供方"
                htmlFor="settings-providers"
                hint="逗号分隔的 provider code；留空表示仅密码登录"
              >
                <Textarea
                  id="settings-providers"
                  value={form.providers}
                  onChange={(event) =>
                    setForm({ ...form, providers: event.target.value })
                  }
                  rows={2}
                  placeholder="github, google"
                />
              </Field>

              {formError ? (
                <InlineAlert tone="danger">{formError}</InlineAlert>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader
              title="策略影响"
              description="保存前请确认对现有用户的影响。"
            />
            <CardContent className="space-y-2 text-xs text-slate-600">
              <div className="rounded-md border border-slate-200 p-3">
                <div className="flex items-center gap-1.5 font-medium text-slate-800">
                  <Settings2 className="h-3.5 w-3.5" />
                  会话策略
                </div>
                <p className="mt-1 text-[11px] text-slate-500">
                  修改会话有效期或闲置超时不会立即终止已有会话，但会影响后续签发与续期。
                </p>
              </div>
              <div className="rounded-md border border-slate-200 p-3">
                <div className="font-medium text-slate-800">MFA 强制</div>
                <p className="mt-1 text-[11px] text-slate-500">
                  启用后，管理员账号在未绑定 MFA 时进入管理端会被服务端拒绝。
                </p>
              </div>
              <InlineAlert tone="warning" title="高风险变更">
                认证策略修改会写入审计。请填写明确的原因，便于后续追溯。
              </InlineAlert>
            </CardContent>
          </Card>
        </div>
      </QueryBoundary>

      <ReasonDialog
        open={saveOpen}
        onClose={() => setSaveOpen(false)}
        onConfirm={(reason) => saveSettings.mutate(reason)}
        title="保存认证配置"
        description="该变更会立即影响新的登录、注册与会话。"
        confirmLabel="确认保存"
        busy={saveSettings.isPending}
      >
        <div className="grid gap-1 rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          <div>自助注册：{form.registrationEnabled ? '开放' : '关闭'}</div>
          <div>邮箱验证：{form.emailVerificationRequired ? '必须' : '可选'}</div>
          <div>管理员强制 MFA：{form.mfaRequiredForAdmins ? '是' : '否'}</div>
          <div>
            密码最小长度 {form.passwordMinLength} · 会话 {form.sessionTtlMinutes} 分钟 ·
            闲置 {form.idleTimeoutMinutes} 分钟
          </div>
        </div>
      </ReasonDialog>
    </div>
  )
}
