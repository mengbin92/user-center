import {
  Check,
  Copy,
  Link2,
  LockKeyhole,
  MailCheck,
  QrCode,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Trash2,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { QRCodeSVG } from 'qrcode.react'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  EmptyState,
  InlineAlert,
  LoadingBlock,
} from '../../components/card'
import { ConfirmDialog, Dialog } from '../../components/dialog'
import { ErrorPanel } from '../../components/query-state'
import { Field, Input } from '../../components/input'
import { useToast } from '../../components/toast'
import { api } from '../../lib/api'
import { passwordValidationError } from '../../lib/password'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import { oauthErrorMessage, providerLabel } from '../../lib/oauth'
import { oidcAuthorizationPath } from '../../lib/paths'
import { useSecurityStatus } from '../../lib/security'
import type { SetupMFAReply } from '../../lib/types'
import { PasswordChangeNotice } from './password-change-notice'
import { PasskeyPanel } from './passkey-panel'
import { ProviderButtons } from '../auth/provider-buttons'

function SectionCard({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Card>
      <CardHeader title={title} description={description} actions={actions} />
      <CardContent className="space-y-3">{children}</CardContent>
    </Card>
  )
}

export function SecurityPage() {
  const { user } = useAuth()
  const toast = useToast()
  const [searchParams] = useSearchParams()
  const boundProvider = searchParams.get('bound')
  const oauthError = searchParams.get('oauth_error')
  const verifiedProvider = searchParams.get('verified')
  const oidcNext = oidcAuthorizationPath(searchParams.get('next'))
  const passwordChangeParam =
    searchParams.get('password_change_required') === '1'

  const securityQuery = useSecurityStatus()
  const contextQuery = useQuery({
    queryKey: ['auth', 'context'],
    queryFn: () => api.auth.context(),
    retry: false,
    staleTime: 60_000,
  })
  const minPasswordLength = contextQuery.data?.password_min_length ?? 10
  const identitiesQuery = useQuery({
    queryKey: ['me', 'external-identities'],
    queryFn: () => api.me.externalIdentities(),
    retry: false,
  })

  const security = securityQuery.data
  const mfaEnabled = security?.mfa_enabled ?? false
  const passwordAvailable = security?.password_available !== false
  const boundProviders = [...new Set((identitiesQuery.data?.items ?? []).map((identity) => identity.provider).filter((provider): provider is string => Boolean(provider)))].filter((provider) => contextQuery.data?.providers?.includes(provider))
  const passwordChangeRequired =
    security?.password_change_required === true ||
    (passwordChangeParam && security?.password_change_required !== false)

  const handledBound = useRef<string | null>(null)
  useEffect(() => {
    if (!boundProvider || handledBound.current === boundProvider) return
    handledBound.current = boundProvider
    void identitiesQuery.refetch()
  }, [boundProvider, identitiesQuery])

  // Password change
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)

  const changePassword = useApiMutation({
    mutationFn: () =>
      api.me.changePassword({
        current_password: passwordAvailable ? currentPassword : '',
        new_password: newPassword,
      }),
    successMessage: '密码已更新',
    successDescription: '其他设备上的会话已被撤销。',
    invalidate: [['me', 'security'], ['me', 'external-identities']],
    refreshAuth: true,
    onSuccess: () => {
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordError(null)
    },
  })

  // MFA enrollment
  const [setupOpen, setSetupOpen] = useState(false)
  const [setupPassword, setSetupPassword] = useState('')
  const [setupData, setSetupData] = useState<SetupMFAReply | null>(null)
  const [confirmCode, setConfirmCode] = useState('')

  const setupMfa = useApiMutation({
    mutationFn: () =>
      api.me.setupMfa({ current_password: setupPassword }),
    onSuccess: (data) => {
      setSetupData(data)
      setConfirmCode('')
    },
  })

  // Recovery codes
  const [codes, setCodes] = useState<string[] | null>(null)
  const [codesOpen, setCodesOpen] = useState(false)

  const confirmMfa = useApiMutation({
    mutationFn: () => api.me.confirmMfa({ code: confirmCode.trim() }),
    successMessage: '多因素认证已启用',
    invalidate: [['me', 'security']],
    refreshAuth: true,
    onSuccess: (data) => {
      const nextCodes = data.recovery_codes ?? []
      setSetupOpen(false)
      setSetupData(null)
      setSetupPassword('')
      setConfirmCode('')
      if (nextCodes.length) {
        setCodes(nextCodes)
        setCodesOpen(true)
      }
    },
  })

  // Disable MFA
  const [disableOpen, setDisableOpen] = useState(false)
  const [disablePassword, setDisablePassword] = useState('')
  const [disableCode, setDisableCode] = useState('')

  const disableMfa = useApiMutation({
    mutationFn: () =>
      api.me.disableMfa({
        current_password: passwordAvailable ? disablePassword : '',
        code: disableCode.trim(),
      }),
    successMessage: '多因素认证已关闭',
    invalidate: [['me', 'security']],
    refreshAuth: true,
    onSuccess: () => {
      setDisableOpen(false)
      setDisablePassword('')
      setDisableCode('')
    },
  })

  // Rotate recovery codes
  const [rotateOpen, setRotateOpen] = useState(false)
  const [rotatePassword, setRotatePassword] = useState('')
  const [rotateCode, setRotateCode] = useState('')

  const rotateCodes = useApiMutation({
    mutationFn: () =>
      api.me.rotateRecoveryCodes({
        current_password: passwordAvailable ? rotatePassword : '',
        code: rotateCode.trim(),
      }),
    successMessage: '恢复码已轮换',
    invalidate: [['me', 'security']],
    onSuccess: (data) => {
      setRotateOpen(false)
      setRotatePassword('')
      setRotateCode('')
      setCodes(data.recovery_codes ?? [])
      setCodesOpen(true)
    },
  })

  // Step-up verification
  const [stepPassword, setStepPassword] = useState('')
  const [stepCode, setStepCode] = useState('')

  const verifyStepUp = useApiMutation({
    mutationFn: () =>
      api.me.verifySecurity({
        current_password: passwordAvailable ? stepPassword : '',
        code: stepCode.trim(),
      }),
    successMessage: '安全验证通过',
    invalidate: [['me', 'security']],
    onSuccess: () => {
      setStepPassword('')
      setStepCode('')
    },
  })

  // Email change
  const [emailOpen, setEmailOpen] = useState(false)
  const [newEmail, setNewEmail] = useState('')
  const [emailPassword, setEmailPassword] = useState('')
  const [emailChallengeId, setEmailChallengeId] = useState('')
  const [emailExpires, setEmailExpires] = useState('')
  const [emailCode, setEmailCode] = useState('')

  const requestEmailChange = useApiMutation({
    mutationFn: () =>
      api.me.createEmailChallenge({
        new_email: newEmail.trim(),
        current_password: emailPassword,
      }),
    successMessage: '验证码已发送',
    onSuccess: (data) => {
      setEmailChallengeId(data.challenge_id ?? '')
      setEmailExpires(data.expires_at ?? '')
      setEmailCode('')
    },
  })

  const confirmEmailChange = useApiMutation({
    mutationFn: () =>
      api.me.confirmEmail({
        challenge_id: emailChallengeId,
        code: emailCode.trim(),
      }),
    successMessage: '邮箱已更新',
    refreshAuth: true,
    onSuccess: () => {
      setEmailOpen(false)
      setNewEmail('')
      setEmailPassword('')
      setEmailChallengeId('')
      setEmailCode('')
      void identitiesQuery.refetch()
    },
  })

  // External identity removal
  const [identityToDelete, setIdentityToDelete] = useState<string | null>(null)

  const deleteIdentity = useApiMutation({
    mutationFn: (id: string) => api.me.deleteExternalIdentity(id),
    successMessage: '已解除第三方账号绑定',
    invalidate: [['me', 'external-identities']],
    onSuccess: () => setIdentityToDelete(null),
  })

  const copyCodes = async () => {
    if (!codes?.length) return
    try {
      await navigator.clipboard.writeText(codes.join('\n'))
      toast.success('恢复码已复制', '请粘贴到离线密码管理器中，不要保存在浏览器存储中。')
    } catch {
      toast.error('复制失败', '请手动选择并复制恢复码。')
    }
  }

  if (securityQuery.isError) {
    return (
      <div className="space-y-4">
        <PageTitle title="安全中心" />
        <h1 className="text-lg font-semibold tracking-tight text-slate-900">
          安全中心
        </h1>
        <p className="text-xs text-slate-500">
          无法读取安全状态，未展示任何默认值，以避免误导。
        </p>
        <ErrorPanel
          error={securityQuery.error}
          onRetry={() => void securityQuery.refetch()}
        />
      </div>
    )
  }

  const submitPassword = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setPasswordError(null)
    const policyError = passwordValidationError(newPassword, minPasswordLength)
    if (policyError) {
      setPasswordError(policyError)
      return
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('两次输入的新密码不一致')
      return
    }
    changePassword.mutate(undefined)
  }

  const submitSetupPassword = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setupMfa.mutate(undefined)
  }

  return (
    <div className="space-y-4">
      <PageTitle title="安全中心" />
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            安全中心
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            管理密码、多因素认证、恢复码、近期安全验证与邮箱绑定。
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void securityQuery.refetch()}
          loading={securityQuery.isFetching}
          icon={<RefreshCw className="h-3.5 w-3.5" />}
        >
          刷新状态
        </Button>
      </div>

      <PasswordChangeNotice required={passwordChangeRequired} />

      {oidcNext ? (
        <InlineAlert tone="info" title="应用授权待继续">
          {!passwordChangeRequired && security && (!security.mfa_required || mfaEnabled) ? (
            <a href={oidcNext} className="font-medium text-indigo-700 underline">继续应用授权</a>
          ) : '请先完成密码更新和多因素认证设置，再继续应用授权。'}
        </InlineAlert>
      ) : null}

      {!passwordAvailable ? (
        <SectionCard title="重新验证绑定身份" description="当前账号使用第三方身份登录。设置密码或启用 MFA 前，请先重新验证已经绑定的身份；证明仅对当前会话短期有效。">
          {verifiedProvider ? <InlineAlert tone="success" title="第三方身份验证已完成">现在可以继续设置密码或启用 MFA。已启用 MFA 的高风险变更仍需动态码验证。</InlineAlert> : null}
          {boundProviders.length ? (
            <ProviderButtons providers={boundProviders} mode="verify" />
          ) : (
            <InlineAlert tone="warning">未找到可重新验证的已绑定提供方。请检查绑定与提供方状态后重试。</InlineAlert>
          )}
        </SectionCard>
      ) : null}

      {boundProvider ? (
        <InlineAlert
          tone="success"
          icon={Link2}
          title={`已绑定 ${providerLabel(boundProvider)}`}
        >
          第三方身份已与当前账号关联，可用于后续登录。
        </InlineAlert>
      ) : null}

      {oauthError ? (
        <InlineAlert tone="danger" title="第三方账号操作失败">
          {oauthErrorMessage(oauthError)}
        </InlineAlert>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title="多因素认证"
          description="使用 TOTP 动态码保护账号，管理员账号必须启用。"
          actions={
            mfaEnabled ? (
              <Badge tone="success" dot>
                已启用
              </Badge>
            ) : (
              <Badge tone="warning" dot>
                未启用
              </Badge>
            )
          }
        >
          {securityQuery.isPending ? (
            <LoadingBlock label="读取 MFA 状态…" />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                  <div className="text-slate-500">剩余恢复码</div>
                  <div className="mt-0.5 text-lg font-semibold tabular-nums text-slate-900">
                    {security?.recovery_codes_remaining ?? 0}
                  </div>
                </div>
                <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                  <div className="text-slate-500">密码登录</div>
                  <div className="mt-0.5 text-sm font-semibold text-slate-900">
                    {security?.password_available ? '可用' : '不可用'}
                  </div>
                </div>
              </div>

              {mfaEnabled ? (
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      setRotatePassword('')
                      setRotateCode('')
                      setRotateOpen(true)
                    }}
                    icon={<RefreshCw className="h-3.5 w-3.5" />}
                  >
                    轮换恢复码
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => {
                      setDisablePassword('')
                      setDisableCode('')
                      setDisableOpen(true)
                    }}
                    icon={<ShieldOff className="h-3.5 w-3.5" />}
                  >
                    关闭 MFA
                  </Button>
                </div>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    setSetupPassword('')
                    setSetupData(null)
                    setSetupOpen(true)
                  }}
                  icon={<QrCode className="h-3.5 w-3.5" />}
                >
                  启用 MFA
                </Button>
              )}

              <p className="text-[11px] text-slate-500">
                动态码每 30 秒更新。恢复码只在生成时展示一次，请离线保存。
              </p>
            </>
          )}
        </SectionCard>

        <SectionCard
          title="修改密码"
          description="修改后其他设备上的会话会被撤销，当前会话保持有效。"
          actions={
            <Badge tone={security?.password_available ? 'info' : 'neutral'}>
              {security?.password_available ? '密码登录已启用' : '无本地密码'}
            </Badge>
          }
        >
          <form className="space-y-3" onSubmit={submitPassword}>
            {passwordAvailable ? (
              <Field label="当前密码" htmlFor="current-password" required>
                <Input
                  id="current-password"
                  type="password"
                  autoComplete="current-password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                  required
                />
              </Field>
            ) : (
              <InlineAlert tone="info">请先使用上方已绑定身份完成重新验证，再继续此操作。</InlineAlert>
            )}
            <Field
              label="新密码"
              htmlFor="new-password"
              required
              hint={`至少 ${minPasswordLength} 位，不能与当前密码相同`}
            >
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                minLength={minPasswordLength}
                required
              />
            </Field>
            <Field label="确认新密码" htmlFor="confirm-password" required>
              <Input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                required
              />
            </Field>
            {passwordError ? (
              <InlineAlert tone="danger">{passwordError}</InlineAlert>
            ) : null}
            <Button
              type="submit"
              size="sm"
              variant="primary"
              loading={changePassword.isPending}
              icon={<LockKeyhole className="h-3.5 w-3.5" />}
            >
              更新密码
            </Button>
          </form>
        </SectionCard>

        <SectionCard
          title="近期安全验证（Step-up）"
          description="归档账号、重置 MFA、发起密码重置等高风险操作需要近期验证。"
          actions={
            security?.step_up_verified ? (
              <Badge tone="success" dot>
                已验证
              </Badge>
            ) : (
              <Badge tone="neutral">未验证</Badge>
            )
          }
        >
          {security?.step_up_verified && security.step_up_expires_at ? (
            <InlineAlert tone="success" title="当前会话已完成安全验证">
              有效期至 {formatDateTime(security.step_up_expires_at)}。
            </InlineAlert>
          ) : null}
          <form
            className="space-y-3"
            onSubmit={(event) => {
              event.preventDefault()
              verifyStepUp.mutate(undefined)
            }}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              {passwordAvailable ? (
                <Field label="当前密码" htmlFor="step-password" required>
                  <Input
                    id="step-password"
                    type="password"
                    autoComplete="current-password"
                    value={stepPassword}
                    onChange={(event) => setStepPassword(event.target.value)}
                    required
                  />
                </Field>
              ) : (
                <InlineAlert tone="info">请先使用上方已绑定身份完成重新验证，再继续此操作。</InlineAlert>
              )}
              <Field label="动态验证码 / 恢复码" htmlFor="step-code" required>
                <Input
                  id="step-code"
                  value={stepCode}
                  onChange={(event) => setStepCode(event.target.value)}
                  placeholder="123456"
                  autoComplete="one-time-code"
                  required
                />
              </Field>
            </div>
            {!mfaEnabled ? (
              <InlineAlert tone="warning">
                需先启用 MFA 才能完成安全验证。启用后回到此处验证。
              </InlineAlert>
            ) : null}
            <Button
              type="submit"
              size="sm"
              variant="secondary"
              loading={verifyStepUp.isPending}
              disabled={!mfaEnabled}
              icon={<ShieldCheck className="h-3.5 w-3.5" />}
            >
              验证当前会话
            </Button>
          </form>
        </SectionCard>

        <SectionCard
          title="邮箱绑定"
          description="变更邮箱需要验证当前密码并向新邮箱发送验证码。"
          actions={
            user?.email_verified ? (
              <Badge tone="success" dot>
                已验证
              </Badge>
            ) : (
              <Badge tone="warning" dot>
                未验证
              </Badge>
            )
          }
        >
          <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs">
            <div className="text-slate-500">当前邮箱</div>
            <div className="font-medium text-slate-800">{user?.email || '未绑定'}</div>
          </div>
          <Button
            size="sm"
            variant="secondary"
            disabled={!passwordAvailable}
            onClick={() => {
              setNewEmail('')
              setEmailPassword('')
              setEmailChallengeId('')
              setEmailCode('')
              setEmailOpen(true)
            }}
            icon={<MailCheck className="h-3.5 w-3.5" />}
          >
            变更邮箱
          </Button>
        </SectionCard>
      </div>

      <SectionCard
        title="第三方账号绑定"
        description="绑定启用的身份提供方，或解除已关联的外部身份。解绑前会要求近期安全验证。"
        actions={
          <Button
            size="xs"
            variant="ghost"
            onClick={() => void identitiesQuery.refetch()}
            loading={identitiesQuery.isFetching}
          >
            刷新
          </Button>
        }
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
          <div className="text-xs font-medium text-slate-800">
            绑定第三方账号
          </div>
          <p className="mt-0.5 text-[11px] text-slate-500">
            点击后将整页跳转到身份提供方完成授权，回调由服务端校验 state。
          </p>
          {contextQuery.data?.providers?.length ? (
            <ProviderButtons
              providers={contextQuery.data.providers}
              mode="bind"
              className="mt-2 sm:grid-cols-2"
            />
          ) : (
            <p className="mt-2 text-[11px] text-slate-500">
              当前没有启用的第三方身份提供方。
            </p>
          )}
        </div>

        {identitiesQuery.isPending ? (
          <LoadingBlock />
        ) : identitiesQuery.isError ? (
          <InlineAlert tone="danger" title="读取失败">
            {errorMessage(identitiesQuery.error)}
          </InlineAlert>
        ) : identitiesQuery.data?.items?.length ? (
          <ul className="divide-y divide-slate-100">
            {identitiesQuery.data.items.map((identity) => (
              <li
                key={identity.id}
                className="flex flex-wrap items-center justify-between gap-2 py-2"
              >
                <div className="flex items-center gap-2">
                  <span className="grid h-8 w-8 place-items-center rounded-md bg-slate-100 text-slate-500">
                    <Link2 className="h-4 w-4" />
                  </span>
                  <div className="text-xs">
                    <div className="font-medium text-slate-800">
                      {identity.display || identity.provider}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {identity.provider} · 绑定于 {formatDateTime(identity.created_at)}
                    </div>
                  </div>
                </div>
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => setIdentityToDelete(identity.id ?? null)}
                  icon={<Trash2 className="h-3.5 w-3.5" />}
                >
                  解绑
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            title="尚未绑定第三方账号"
            description="使用上方按钮绑定 GitHub、Google 等身份提供方。"
            icon={Link2}
          />
        )}
      </SectionCard>

      {/* MFA setup */}
      <Dialog
        open={setupOpen}
        onClose={() => {
          setSetupOpen(false)
          setSetupData(null)
        }}
        title={setupData ? '扫描二维码并确认' : '启用多因素认证'}
        description={
          setupData
            ? '使用身份验证器扫描二维码，然后输入当前 6 位动态码完成绑定。'
            : passwordAvailable ? '先验证当前密码，再生成 TOTP 密钥。' : '先重新验证已绑定的第三方身份，再生成 TOTP 密钥。'
        }
        size="md"
        bodyClassName="space-y-4"
        footer={
          setupData ? (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setSetupOpen(false)
                  setSetupData(null)
                }}
                disabled={confirmMfa.isPending}
              >
                取消
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => confirmMfa.mutate(undefined)}
                loading={confirmMfa.isPending}
                disabled={confirmCode.trim().length < 6}
                icon={<Check className="h-3.5 w-3.5" />}
              >
                确认启用
              </Button>
            </>
          ) : undefined
        }
      >
        {!setupData ? (
          <form className="space-y-3" onSubmit={submitSetupPassword}>
            {passwordAvailable ? (
              <Field label="当前密码" htmlFor="setup-password" required>
                <Input
                  id="setup-password"
                  type="password"
                  autoComplete="current-password"
                  value={setupPassword}
                  onChange={(event) => setSetupPassword(event.target.value)}
                  required
                />
              </Field>
            ) : (
              <InlineAlert tone="info">请先使用上方已绑定身份完成重新验证，再继续此操作。</InlineAlert>
            )}
            <Button
              type="submit"
              size="sm"
              variant="primary"
              loading={setupMfa.isPending}
              icon={<Smartphone className="h-3.5 w-3.5" />}
            >
              生成密钥
            </Button>
          </form>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-col items-center gap-2 rounded-lg border border-slate-200 bg-white p-3">
              <QRCodeSVG
                value={setupData.otpauth_uri ?? ''}
                size={168}
                bgColor="#ffffff"
                fgColor="#0f172a"
                level="M"
                marginSize={1}
              />
              <p className="text-[10px] text-slate-500">
                密钥将在{' '}
                {setupData.expires_at ? formatDateTime(setupData.expires_at) : '10 分钟后'}{' '}
                失效
              </p>
            </div>
            <div className="rounded-md border border-amber-200 bg-amber-50 p-3">
              <div className="text-[11px] font-medium text-amber-800">
                无法扫码时手动输入密钥（仅本次展示）
              </div>
              <div className="mt-1 flex items-center gap-2">
                <code className="min-w-0 flex-1 break-all rounded bg-white/70 px-2 py-1 font-mono text-[11px] text-slate-800">
                  {setupData.secret}
                </code>
                <Button
                  size="xs"
                  variant="secondary"
                  onClick={() => {
                    if (!setupData.secret) return
                    void navigator.clipboard
                      .writeText(setupData.secret)
                      .then(() => toast.success('密钥已复制'))
                      .catch(() => toast.error('复制失败'))
                  }}
                  icon={<Copy className="h-3 w-3" />}
                >
                  复制
                </Button>
              </div>
            </div>
            <Field label="动态验证码" htmlFor="setup-code" required>
              <Input
                id="setup-code"
                value={confirmCode}
                onChange={(event) => setConfirmCode(event.target.value)}
                placeholder="输入身份验证器中的 6 位数字"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
              />
            </Field>
            {confirmMfa.isError ? (
              <InlineAlert tone="danger" title="确认失败">
                {errorMessage(confirmMfa.error)}
              </InlineAlert>
            ) : null}
          </div>
        )}
      </Dialog>

      {/* Recovery codes once */}
      <Dialog
        open={codesOpen}
        onClose={() => {
          setCodesOpen(false)
          setCodes(null)
        }}
        title="请立即保存恢复码"
        description="恢复码只在本次展示一次。关闭后无法再次查看，只能重新轮换。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void copyCodes()}
              icon={<Copy className="h-3.5 w-3.5" />}
            >
              复制全部
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                setCodesOpen(false)
                setCodes(null)
              }}
            >
              我已保存
            </Button>
          </>
        }
      >
        <InlineAlert tone="warning" title="不要保存在浏览器存储中">
          请将恢复码保存到离线位置。每个恢复码只能使用一次。
        </InlineAlert>
        <div className="grid grid-cols-2 gap-1.5 rounded-md border border-slate-200 bg-slate-50 p-3">
          {(codes ?? []).map((code) => (
            <code
              key={code}
              className="rounded bg-white px-2 py-1 text-center font-mono text-[11px] text-slate-800"
            >
              {code}
            </code>
          ))}
          {!codes?.length ? (
            <span className="col-span-2 text-center text-xs text-slate-500">
              未返回恢复码
            </span>
          ) : null}
        </div>
      </Dialog>

      {/* Disable MFA */}
      <Dialog
        open={disableOpen}
        onClose={() => setDisableOpen(false)}
        title="关闭多因素认证"
        description="关闭后账号安全性会降低。需要验证当前密码与动态码。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setDisableOpen(false)}
              disabled={disableMfa.isPending}
            >
              取消
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => disableMfa.mutate(undefined)}
              loading={disableMfa.isPending}
              disabled={(passwordAvailable && !disablePassword) || disableCode.trim().length < 6}
            >
              确认关闭
            </Button>
          </>
        }
      >
        {passwordAvailable ? (
          <Field label="当前密码" htmlFor="disable-password" required>
            <Input
              id="disable-password"
              type="password"
              autoComplete="current-password"
              value={disablePassword}
              onChange={(event) => setDisablePassword(event.target.value)}
              required
            />
          </Field>
        ) : (
          <InlineAlert tone="info">请先重新验证上方已绑定的第三方身份，然后输入动态验证码继续。</InlineAlert>
        )}
        <Field label="动态验证码 / 恢复码" htmlFor="disable-code" required>
          <Input
            id="disable-code"
            value={disableCode}
            onChange={(event) => setDisableCode(event.target.value)}
            autoComplete="one-time-code"
            required
          />
        </Field>
        {disableMfa.isError ? (
          <InlineAlert tone="danger">{errorMessage(disableMfa.error)}</InlineAlert>
        ) : null}
      </Dialog>

      {/* Rotate recovery codes */}
      <Dialog
        open={rotateOpen}
        onClose={() => setRotateOpen(false)}
        title="轮换恢复码"
        description="现有恢复码会全部失效，并生成一组新的恢复码。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setRotateOpen(false)}
              disabled={rotateCodes.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => rotateCodes.mutate(undefined)}
              loading={rotateCodes.isPending}
              disabled={(passwordAvailable && !rotatePassword) || rotateCode.trim().length < 6}
            >
              轮换恢复码
            </Button>
          </>
        }
      >
        {passwordAvailable ? (
          <Field label="当前密码" htmlFor="rotate-password" required>
            <Input
              id="rotate-password"
              type="password"
              autoComplete="current-password"
              value={rotatePassword}
              onChange={(event) => setRotatePassword(event.target.value)}
              required
            />
          </Field>
        ) : (
          <InlineAlert tone="info">请先重新验证上方已绑定的第三方身份，然后输入动态验证码继续。</InlineAlert>
        )}
        <Field label="动态验证码 / 恢复码" htmlFor="rotate-code" required>
          <Input
            id="rotate-code"
            value={rotateCode}
            onChange={(event) => setRotateCode(event.target.value)}
            autoComplete="one-time-code"
            required
          />
        </Field>
        {rotateCodes.isError ? (
          <InlineAlert tone="danger">{errorMessage(rotateCodes.error)}</InlineAlert>
        ) : null}
      </Dialog>

      {/* Email change */}
      <Dialog
        open={emailOpen}
        onClose={() => setEmailOpen(false)}
        title="变更邮箱"
        description="验证当前密码后，系统会向新邮箱发送验证码。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          emailChallengeId ? (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setEmailChallengeId('')
                  setEmailCode('')
                }}
                disabled={confirmEmailChange.isPending}
              >
                更换邮箱
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => confirmEmailChange.mutate(undefined)}
                loading={confirmEmailChange.isPending}
                disabled={emailCode.trim().length < 4}
              >
                确认变更
              </Button>
            </>
          ) : undefined
        }
      >
        {!emailChallengeId ? (
          <>
            <Field label="新邮箱" htmlFor="new-email" required>
              <Input
                id="new-email"
                type="email"
                value={newEmail}
                onChange={(event) => setNewEmail(event.target.value)}
                placeholder="new@example.com"
                required
              />
            </Field>
            <Field label="当前密码" htmlFor="email-password" required>
              <Input
                id="email-password"
                type="password"
                autoComplete="current-password"
                value={emailPassword}
                onChange={(event) => setEmailPassword(event.target.value)}
                required
              />
            </Field>
            <Button
              variant="primary"
              size="sm"
              onClick={() => requestEmailChange.mutate(undefined)}
              loading={requestEmailChange.isPending}
              disabled={!newEmail.trim() || !emailPassword}
              icon={<MailCheck className="h-3.5 w-3.5" />}
            >
              发送验证码
            </Button>
            {requestEmailChange.isError ? (
              <InlineAlert tone="danger">
                {errorMessage(requestEmailChange.error)}
              </InlineAlert>
            ) : null}
          </>
        ) : (
          <>
            <InlineAlert tone="info" title={`验证码已发送至 ${newEmail}`}>
              {emailExpires ? `有效期至 ${formatDateTime(emailExpires)}。` : ''}
            </InlineAlert>
            <Field label="邮箱验证码" htmlFor="email-code" required>
              <Input
                id="email-code"
                value={emailCode}
                onChange={(event) => setEmailCode(event.target.value)}
                autoComplete="one-time-code"
                required
              />
            </Field>
            {confirmEmailChange.isError ? (
              <InlineAlert tone="danger">
                {errorMessage(confirmEmailChange.error)}
              </InlineAlert>
            ) : null}
          </>
        )}
      </Dialog>

      <ConfirmDialog
        open={identityToDelete !== null}
        onClose={() => setIdentityToDelete(null)}
        onConfirm={() => {
          if (identityToDelete) deleteIdentity.mutate(identityToDelete)
        }}
        title="解除第三方账号绑定"
        description="解绑后，该身份将无法再用于登录。"
        confirmLabel="解除绑定"
        tone="danger"
        loading={deleteIdentity.isPending}
      />

      <PasskeyPanel />

      {securityQuery.isSuccess && user?.status === 'archived' ? (
        <div className="text-center text-xs text-slate-500">
          <StatusBadge status={user.status} /> 账号已归档，仅可查看历史信息。
        </div>
      ) : null}
    </div>
  )
}
