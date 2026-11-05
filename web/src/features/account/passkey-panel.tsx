import { Fingerprint, KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, EmptyState, InlineAlert } from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { WebAuthnCredential } from '../../lib/types'
import { createPasskey, getAssertion } from '../../lib/webauthn'

type Action = 'register' | 'verify' | 'delete'

export function PasskeyPanel() {
  const [action, setAction] = useState<Action | null>(null)
  const [target, setTarget] = useState<WebAuthnCredential | null>(null)
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')

  const credentials = useQuery({
    queryKey: ['me', 'webauthn', 'credentials'],
    queryFn: () => api.me.webAuthnCredentials(),
    retry: false,
  })
  const items = credentials.data?.items ?? []

  const reset = () => {
    setAction(null)
    setTarget(null)
    setPassword('')
    setName('')
    setError('')
  }

  const register = useApiMutation({
    mutationFn: async () => {
      const challenge = await api.me.webAuthnRegistrationChallenge(password)
      const body = await createPasskey(challenge, challenge.challenge_id ?? '', name || 'Passkey')
      return api.me.confirmWebAuthnRegistration(body)
    },
    successMessage: 'Passkey 已绑定',
    successDescription: '可用作登录与安全验证的第二因素。',
    invalidate: [['me', 'webauthn', 'credentials']],
    refreshAuth: true,
    onSuccess: reset,
    onError: (cause) => setError(cause.message),
  })

  const verify = useApiMutation({
    mutationFn: async () => {
      const challenge = await api.me.webAuthnAssertionChallenge(password)
      return api.me.verifyWebAuthnAssertion(
        await getAssertion(challenge, challenge.challenge_id ?? '', password),
      )
    },
    successMessage: '安全验证已通过',
    invalidate: [['me', 'security']],
    refreshAuth: true,
    onSuccess: reset,
    onError: (cause) => setError(cause.message),
  })

  const remove = useApiMutation({
    mutationFn: () =>
      api.me.deleteWebAuthnCredential(target?.id ?? '', password),
    successMessage: 'Passkey 已删除',
    invalidate: [['me', 'webauthn', 'credentials']],
    refreshAuth: true,
    onSuccess: reset,
    onError: (cause) => setError(cause.message),
  })

  const busy = register.isPending || verify.isPending || remove.isPending
  const submit = () => {
    if (action === 'register') void register.mutateAsync()
    if (action === 'verify') void verify.mutateAsync()
    if (action === 'delete') void remove.mutateAsync()
  }

  return (
    <>
      <Card>
        <CardHeader
          title="Passkey / 安全密钥"
          description="平台认证器或硬件密钥可作为第二因素；用户名与密码仍是第一因素。"
          actions={
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setAction('verify')}>
                <ShieldCheck className="h-3.5 w-3.5" />
                安全验证
              </Button>
              <Button size="sm" variant="primary" onClick={() => setAction('register')}>
                <Plus className="h-3.5 w-3.5" />
                绑定 Passkey
              </Button>
            </div>
          }
        />
        <CardContent className="space-y-2">
          <InlineAlert tone="info" title="第二因素">
            注册、删除与安全验证都需要重新输入当前密码；凭据公钥保存在服务端，认证器计数器回退会被拒绝。
          </InlineAlert>
          {items.length === 0 ? (
            <EmptyState
              icon={Fingerprint}
              title="还没有绑定 Passkey"
              description="绑定后可在登录 MFA 与高风险操作的 Step-up 中使用。"
            />
          ) : (
            <div className="divide-y divide-slate-100">
              {items.map((item) => (
                <div key={item.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 text-xs font-medium text-slate-800">
                      <KeyRound className="h-3.5 w-3.5 text-indigo-600" />
                      {item.name || 'Passkey'}
                      <Badge tone="neutral">计数 {item.sign_count ?? '0'}</Badge>
                    </p>
                    <p className="truncate font-mono text-[10px] text-slate-400">
                      {item.aaguid || '—'} · 创建 {formatDateTime(item.created_at)}
                      {item.last_used_at ? ` · 最近使用 ${formatDateTime(item.last_used_at)}` : ''}
                    </p>
                  </div>
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => {
                      setTarget(item)
                      setAction('delete')
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    删除
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={action !== null}
        onClose={reset}
        title={
          action === 'register'
            ? '绑定 Passkey'
            : action === 'verify'
              ? '使用 Passkey 完成安全验证'
              : '删除 Passkey'
        }
        description="操作需要重新验证当前密码。"
        size="sm"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={reset}>取消</Button>
            <Button
              variant={action === 'delete' ? 'danger' : 'primary'}
              size="sm"
              loading={busy}
              disabled={!password}
              onClick={submit}
            >
              确认
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <Field label="当前密码">
            <Input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          {action === 'register' ? (
            <Field label="凭据名称">
              <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：MacBook Touch ID" />
            </Field>
          ) : null}
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
        </div>
      </Dialog>
    </>
  )
}
