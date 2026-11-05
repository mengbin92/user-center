import {
  AppWindow,
  Ban,
  Copy,
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

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
import { Dialog } from '../../components/dialog'
import {
  Checkbox,
  Field,
  Input,
  Switch,
  Textarea,
} from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { useToast } from '../../components/toast'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { useApiMutation } from '../../lib/mutations'
import type {
  OIDCClient,
  OIDCClientCredentialReply,
} from '../../lib/types'

const OIDC_SCOPES = [
  { value: 'openid', label: 'openid', hint: '必需，OIDC 身份认证 scope' },
  { value: 'profile', label: 'profile', hint: '姓名、用户名等资料' },
  { value: 'email', label: 'email', hint: '邮箱与验证状态' },
  { value: 'offline_access', label: 'offline_access', hint: '允许签发 refresh token' },
] as const

const ACCESS_TTL_MIN = 60
const ACCESS_TTL_MAX = 86_400
const REFRESH_TTL_MIN = 300
const REFRESH_TTL_MAX = 2_592_000

const DEFAULT_ACCESS_TTL = '900'
const DEFAULT_REFRESH_TTL = '86400'

function ttlError(
  value: string,
  min: number,
  max: number,
): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return '请输入有效期'
  const seconds = Number(trimmed)
  if (!Number.isInteger(seconds)) return '有效期必须是整数秒'
  if (seconds < min || seconds > max) {
    return `允许范围 ${min}–${max} 秒`
  }
  return undefined
}

function scopeSet(scopes?: string[]): Set<string> {
  const next = new Set(scopes ?? [])
  next.add('openid')
  return next
}

function redirectList(value: string): string[] {
  return value.split('\n').map((uri) => uri.trim()).filter(Boolean)
}

function toggleInSet(
  current: Set<string>,
  value: string,
  required = false,
): Set<string> {
  if (required) return current
  const next = new Set(current)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  next.add('openid')
  return next
}

function copyText(value: string): Promise<void> {
  if (!value) return Promise.reject(new Error('没有可复制的内容'))
  if (!navigator.clipboard?.writeText) {
    return Promise.reject(new Error('浏览器不支持剪贴板'))
  }
  return navigator.clipboard.writeText(value)
}

function CopyButton({ value, label }: { value?: string; label: string }) {
  const toast = useToast()

  const copy = async () => {
    try {
      await copyText(value ?? '')
      toast.success('已复制', `${label}已复制到剪贴板。`)
    } catch {
      toast.error('复制失败', '请手动选择并复制。')
    }
  }

  return (
    <Button
      size="xs"
      variant="ghost"
      onClick={() => void copy()}
      disabled={!value}
      icon={<Copy className="h-3 w-3" />}
      aria-label={`复制 ${label}`}
    >
      复制
    </Button>
  )
}

function EndpointRow({ label, value }: { label: string; value?: string }) {
  return (
    <div className="flex items-start justify-between gap-2 rounded-md border border-slate-200 bg-slate-50/60 px-3 py-2">
      <div className="min-w-0">
        <div className="text-[11px] text-slate-500">{label}</div>
        <div className="mt-0.5 break-all font-mono text-[11px] text-slate-800">
          {value || '—'}
        </div>
      </div>
      <CopyButton value={value} label={label} />
    </div>
  )
}

function OIDCEndpointsCard() {
  const query = useQuery({
    queryKey: ['oidc', 'discovery'],
    queryFn: () => api.oidc.discovery(),
    staleTime: 5 * 60_000,
    retry: false,
  })
  const discovery = query.data

  return (
    <Card>
      <CardHeader
        title="OIDC 端点"
        description="来自公开发现文档 /.well-known/openid-configuration，可供应用接入时复制。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => void query.refetch()}
            loading={query.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
        }
      />
      <QueryBoundary query={query} loadingLabel="读取 OIDC 发现文档…">
        <CardContent className="grid gap-2 lg:grid-cols-2">
          <EndpointRow label="Issuer" value={discovery?.issuer} />
          <EndpointRow
            label="Authorization Endpoint"
            value={discovery?.authorization_endpoint}
          />
          <EndpointRow
            label="Token Endpoint"
            value={discovery?.token_endpoint}
          />
          <EndpointRow
            label="UserInfo Endpoint"
            value={discovery?.userinfo_endpoint}
          />
          <EndpointRow label="JWKS URI" value={discovery?.jwks_uri} />
          <div className="flex items-center gap-1.5 rounded-md border border-dashed border-slate-200 px-3 py-2 text-[11px] text-slate-500">
            <KeyRound className="h-3.5 w-3.5 shrink-0" />
            授权码 + PKCE S256；token 端点支持 client_secret_basic 与
            client_secret_post。
          </div>
        </CardContent>
      </QueryBoundary>
    </Card>
  )
}

export function ClientSecretDialog({
  credential,
  onClose,
}: {
  credential: OIDCClientCredentialReply | null
  onClose: () => void
}) {
  const toast = useToast()
  const secret = credential?.client_secret ?? ''
  const client = credential?.client

  const copySecret = async () => {
    try {
      await copyText(secret)
      toast.success('客户端密钥已复制', '请立即保存到安全的密钥管理系统中。')
    } catch {
      toast.error('复制失败', '请手动选择并复制客户端密钥。')
    }
  }

  return (
    <Dialog
      open={credential !== null}
      onClose={onClose}
      title={client?.public && !secret ? `${client?.name || '公开应用'}已创建` : '请立即保存客户端密钥'}
      description="client_secret 仅在本次响应中返回一次，关闭后无法再次查看，也不会写入浏览器存储。"
      size="md"
      bodyClassName="space-y-3"
      footer={
        <>
          {secret ? (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void copySecret()}
              disabled={!secret}
              icon={<Copy className="h-3.5 w-3.5" />}
            >
              复制客户端密钥
            </Button>
          ) : null}
          <Button variant="primary" size="sm" onClick={onClose}>
            {secret ? '我已保存' : '完成'}
          </Button>
        </>
      }
    >
      <InlineAlert tone="warning" title="一次性客户端密钥">
        请立即保存到密钥管理系统。关闭此对话框后平台无法恢复明文密钥，只能重新轮换。
      </InlineAlert>
      <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
        <div className="text-[11px] text-slate-500">应用</div>
        <div className="text-xs font-medium text-slate-800">
          {client?.name || '—'} ·{' '}
          <span className="font-mono">{client?.client_id || '—'}</span>
        </div>
      </div>
      {secret ? (
        <div className="rounded-md border border-amber-200 bg-amber-50 p-3">
          <div className="text-[11px] font-medium text-amber-800">
            client_secret
          </div>
          <code className="mt-1 block break-all rounded bg-white/80 px-2 py-1.5 font-mono text-[11px] text-slate-800">
            {secret}
          </code>
        </div>
      ) : client?.public ? (
        <InlineAlert tone="info" title="公开客户端">
          公开客户端使用 PKCE，不签发 client_secret，无需保存密钥。
        </InlineAlert>
      ) : (
        <InlineAlert tone="warning" title="未返回客户端密钥">
          服务端没有返回明文密钥。请关闭后重新轮换密钥以获取新的
          client_secret。
        </InlineAlert>
      )}
    </Dialog>
  )
}

function ScopePicker({
  selected,
  onToggle,
  idPrefix,
}: {
  selected: Set<string>
  onToggle: (scope: string) => void
  idPrefix: string
}) {
  return (
    <div className="grid gap-1 rounded-md border border-slate-200 p-2 sm:grid-cols-2">
      {OIDC_SCOPES.map((scope) => (
        <Checkbox
          key={scope.value}
          id={`${idPrefix}-${scope.value}`}
          checked={selected.has(scope.value)}
          disabled={scope.value === 'openid'}
          onChange={() => onToggle(scope.value)}
          label={
            <span>
              <span className="font-mono">{scope.label}</span>
              <span className="ml-1 text-[11px] text-slate-400">
                {scope.hint}
              </span>
            </span>
          }
        />
      ))}
    </div>
  )
}

export function AdminApplicationsPage() {
  const { can, authorization, sessionGeneration } = useAuth()
  const canRead = can('oidc.client.read')
  const canWrite = can('oidc.client.update')
  const canWriteRef = useRef(canWrite)
  canWriteRef.current = canWrite

  const clientsQuery = useQuery({
    queryKey: ['admin', 'oidc-clients'],
    queryFn: () => api.oidc.listClients(),
    enabled: canRead,
    retry: false,
  })
  const clients = clientsQuery.data?.items ?? []

  const [credential, setCredential] =
    useState<OIDCClientCredentialReply | null>(null)

  // Create
  const [createOpen, setCreateOpen] = useState(false)
  const [createName, setCreateName] = useState('')
  const [serviceOwner, setServiceOwner] = useState('')
  const [redirectURIs, setRedirectURIs] = useState('')
  const [postLogoutURIs, setPostLogoutURIs] = useState('')
  const [createScopes, setCreateScopes] = useState<Set<string>>(
    new Set(['openid']),
  )
  const [isPublic, setIsPublic] = useState(false)
  const [requirePKCE, setRequirePKCE] = useState(true)
  const [accessTTL, setAccessTTL] = useState(DEFAULT_ACCESS_TTL)
  const [refreshTTL, setRefreshTTL] = useState(DEFAULT_REFRESH_TTL)
  const [createReason, setCreateReason] = useState('')

  const resetCreate = () => {
    setCreateName('')
    setServiceOwner('')
    setRedirectURIs('')
    setPostLogoutURIs('')
    setCreateScopes(new Set(['openid']))
    setIsPublic(false)
    setRequirePKCE(true)
    setAccessTTL(DEFAULT_ACCESS_TTL)
    setRefreshTTL(DEFAULT_REFRESH_TTL)
    setCreateReason('')
  }

  const createAccessError = ttlError(
    accessTTL,
    ACCESS_TTL_MIN,
    ACCESS_TTL_MAX,
  )
  const createRefreshError = ttlError(
    refreshTTL,
    REFRESH_TTL_MIN,
    REFRESH_TTL_MAX,
  )
  const createRedirects = redirectList(redirectURIs)
  const createValid =
    createName.trim().length > 0 &&
    serviceOwner.trim().length > 0 &&
    createRedirects.length > 0 &&
    createScopes.has('openid') &&
    !createAccessError &&
    !createRefreshError &&
    createReason.trim().length >= 2

  const createClient = useApiMutation({
    gcTime: 0,
    mutationFn: () =>
      api.oidc.createClient({
        name: createName.trim(),
        service_owner: serviceOwner.trim(),
        redirect_uris: createRedirects,
        post_logout_redirect_uris: redirectList(postLogoutURIs),
        scopes: [...createScopes],
        public: isPublic,
        require_pkce: isPublic ? true : requirePKCE,
        access_token_ttl_seconds: Number(accessTTL),
        refresh_token_ttl_seconds: Number(refreshTTL),
        expected_policy_revision: authorization?.policy_revision,
        reason: createReason.trim(),
      }),
    successMessage: 'OIDC 应用已创建',
    successDescription: '请立即保存客户端密钥，关闭后无法再次查看。',
    invalidate: [['admin', 'oidc-clients']],
    onSuccess: (data) => {
      createClient.reset()
      if (!canWriteRef.current) return
      setCreateOpen(false)
      resetCreate()
      setCredential(data)
    },
  })

  // Update
  const [editTarget, setEditTarget] = useState<OIDCClient | null>(null)
  const [editName, setEditName] = useState('')
  const [editRedirectURIs, setEditRedirectURIs] = useState('')
  const [editPostLogoutURIs, setEditPostLogoutURIs] = useState('')
  const [editScopes, setEditScopes] = useState<Set<string>>(new Set())
  const editPublic = Boolean(editTarget?.public)
  const [editPKCE, setEditPKCE] = useState(true)
  const [editAccessTTL, setEditAccessTTL] = useState(DEFAULT_ACCESS_TTL)
  const [editRefreshTTL, setEditRefreshTTL] = useState(DEFAULT_REFRESH_TTL)
  const [editReason, setEditReason] = useState('')

  const openEdit = (client: OIDCClient) => {
    setEditTarget(client)
    setEditName(client.name ?? '')
    setEditRedirectURIs((client.redirect_uris ?? []).join('\n'))
    setEditPostLogoutURIs((client.post_logout_redirect_uris ?? []).join('\n'))
    setEditScopes(scopeSet(client.scopes))
    setEditPKCE(client.require_pkce ?? Boolean(client.public))
    setEditAccessTTL(
      String(client.access_token_ttl_seconds ?? DEFAULT_ACCESS_TTL),
    )
    setEditRefreshTTL(
      String(client.refresh_token_ttl_seconds ?? DEFAULT_REFRESH_TTL),
    )
    setEditReason('')
  }

  const editAccessError = ttlError(
    editAccessTTL,
    ACCESS_TTL_MIN,
    ACCESS_TTL_MAX,
  )
  const editRefreshError = ttlError(
    editRefreshTTL,
    REFRESH_TTL_MIN,
    REFRESH_TTL_MAX,
  )
  const editRedirects = redirectList(editRedirectURIs)
  const editValid =
    editName.trim().length > 0 &&
    editRedirects.length > 0 &&
    editScopes.has('openid') &&
    !editAccessError &&
    !editRefreshError &&
    editReason.trim().length >= 2

  const updateClient = useApiMutation({
    mutationFn: () => {
      if (!editTarget) throw new Error('缺少 OIDC 应用')
      return api.oidc.updateClient(editTarget.id ?? '', {
        id: editTarget.id,
        name: editName.trim(),
        redirect_uris: editRedirects,
        // Repeated fields have no presence on the wire; always send the
        // stored list so an unrelated edit cannot erase the logout whitelist.
        post_logout_redirect_uris: redirectList(editPostLogoutURIs),
        scopes: [...editScopes],
        public: editPublic,
        require_pkce: editPublic ? true : editPKCE,
        access_token_ttl_seconds: Number(editAccessTTL),
        refresh_token_ttl_seconds: Number(editRefreshTTL),
        expected_revision: editTarget.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: editReason.trim(),
      })
    },
    successMessage: 'OIDC 应用已更新',
    invalidate: [['admin', 'oidc-clients']],
    onSuccess: () => setEditTarget(null),
  })

  // Rotate secret
  const [rotateTarget, setRotateTarget] = useState<OIDCClient | null>(null)
  const rotateSecret = useApiMutation({
    gcTime: 0,
    mutationFn: (input: { client: OIDCClient; reason: string }) =>
      api.oidc.rotateSecret(input.client.id ?? '', {
        id: input.client.id,
        expected_revision: input.client.revision,
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: '客户端密钥已轮换',
    successDescription: '旧密钥立即失效，请保存新密钥。',
    invalidate: [['admin', 'oidc-clients']],
    onSuccess: (data) => {
      rotateSecret.reset()
      if (!canWriteRef.current) return
      setRotateTarget(null)
      setCredential(data)
    },
  })

  // Disable
  const [disableTarget, setDisableTarget] = useState<OIDCClient | null>(null)
  const disableClient = useApiMutation({
    mutationFn: (input: { client: OIDCClient; reason: string }) =>
      api.oidc.disableClient(input.client.id ?? '', {
        id: input.client.id,
        expected_revision: input.client.revision,
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: 'OIDC 应用已停用',
    invalidate: [['admin', 'oidc-clients']],
    onSuccess: () => setDisableTarget(null),
  })

  useEffect(() => {
    setCredential(null)
    setCreateOpen(false)
    setEditTarget(null)
    setRotateTarget(null)
    setDisableTarget(null)
    createClient.reset()
    rotateSecret.reset()
  }, [sessionGeneration, canWrite, createClient.reset, rotateSecret.reset])

  return (
    <div className="space-y-4">
      <PageTitle title="OIDC 应用" />
      <PageHeader
        eyebrow="Applications"
        title="OIDC 应用"
        description="管理 OIDC Provider 客户端：重定向地址、scope、PKCE 与 token 有效期。所有写操作需要填写原因并完成近期安全验证。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => void clientsQuery.refetch()}
            loading={clientsQuery.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
        }
      />

      <Card>
        <CardHeader
          title="OIDC 应用"
          description="客户端密钥只在创建或轮换时展示一次，不会保存在浏览器存储中。"
          actions={
            canWrite ? (
              <Button
                size="sm"
                variant="primary"
                onClick={() => {
                  resetCreate()
                  setCreateOpen(true)
                }}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                创建应用
              </Button>
            ) : (
              <Badge tone="neutral">只读</Badge>
            )
          }
        />
        <QueryBoundary query={clientsQuery} loadingLabel="读取 OIDC 应用…">
          {clients.length === 0 ? (
            <EmptyState
              title="暂无 OIDC 应用"
              description="创建应用后即可获得 client_id 与一次性 client_secret，用于接入 OIDC Provider。"
              icon={AppWindow}
            />
          ) : (
            <Table minWidth="min-w-[1360px]">
              <THead>
                <TR>
                  <TH>应用</TH>
                  <TH>服务归属</TH>
                  <TH>状态</TH>
                  <TH>重定向 URI</TH>
                  <TH>Scope</TH>
                  <TH>类型</TH>
                  <TH>PKCE</TH>
                  <TH>Access / Refresh TTL</TH>
                  <TH>Revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {clients.map((client) => (
                  <TR key={client.id}>
                    <TD>
                      <div className="text-xs font-medium text-slate-800">
                        {client.name || '—'}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">
                        {client.client_id || '—'}
                      </div>
                    </TD>
                    <TD className="text-[11px] text-slate-600">
                      {client.service_owner || '—'}
                    </TD>
                    <TD>
                      <StatusBadge
                        status={client.status}
                        label={
                          client.status === 'active' ? '启用中' : '已停用'
                        }
                      />
                    </TD>
                    <TD>
                      <div className="max-w-[260px] space-y-0.5">
                        {(client.redirect_uris ?? []).length ? (
                          (client.redirect_uris ?? []).map((uri) => (
                            <div
                              key={uri}
                              className="break-all font-mono text-[10px] text-slate-600"
                            >
                              {uri}
                            </div>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-400">—</span>
                        )}
                      </div>
                    </TD>
                    <TD>
                      <div className="flex max-w-[160px] flex-wrap gap-1">
                        {(client.scopes ?? []).length ? (
                          (client.scopes ?? []).map((scope) => (
                            <Badge key={scope} tone="info">
                              {scope}
                            </Badge>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-400">—</span>
                        )}
                      </div>
                    </TD>
                    <TD>
                      {client.public ? (
                        <Badge tone="violet">公开</Badge>
                      ) : (
                        <Badge tone="outline">机密</Badge>
                      )}
                    </TD>
                    <TD>
                      {client.require_pkce ? (
                        <Badge tone="success">必需</Badge>
                      ) : (
                        <Badge tone="neutral">可选</Badge>
                      )}
                    </TD>
                    <TD className="whitespace-nowrap text-[11px] tabular-nums text-slate-600">
                      {client.access_token_ttl_seconds ?? DEFAULT_ACCESS_TTL}s /{' '}
                      {client.refresh_token_ttl_seconds ?? DEFAULT_REFRESH_TTL}s
                    </TD>
                    <TD className="font-mono text-[10px] text-slate-500">
                      {client.revision ?? '—'}
                    </TD>
                    <TD className="text-right">
                      {canWrite && client.status === 'active' ? (
                        <div className="flex flex-wrap justify-end gap-1">
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() => openEdit(client)}
                            icon={<Pencil className="h-3 w-3" />}
                          >
                            编辑
                          </Button>
                          {client.public ? null : (
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => setRotateTarget(client)}
                              icon={<RefreshCw className="h-3 w-3" />}
                            >
                              轮换密钥
                            </Button>
                          )}
                          <Button
                            size="xs"
                            variant="ghost"
                            onClick={() => setDisableTarget(client)}
                            icon={<Ban className="h-3 w-3" />}
                          >
                            停用
                          </Button>
                        </div>
                      ) : null}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <OIDCEndpointsCard />

      {/* Create */}
      <Dialog
        open={createOpen}
        onClose={() => {
          if (!createClient.isPending) setCreateOpen(false)
        }}
        title="创建 OIDC 应用"
        description="创建成功后服务端只返回一次 client_secret，请立即保存。"
        size="xl"
        bodyClassName="space-y-3"
        dismissible={!createClient.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setCreateOpen(false)
                resetCreate()
              }}
              disabled={createClient.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => createClient.mutate(undefined)}
              loading={createClient.isPending}
              disabled={!createValid}
              icon={<AppWindow className="h-3.5 w-3.5" />}
            >
              创建应用
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="名称" htmlFor="oidc-create-name" required>
            <Input
              id="oidc-create-name"
              value={createName}
              onChange={(event) => setCreateName(event.target.value)}
              placeholder="例如 计费控制台"
            />
          </Field>
          <Field label="服务归属" htmlFor="oidc-create-owner" required>
            <Input
              id="oidc-create-owner"
              value={serviceOwner}
              onChange={(event) => setServiceOwner(event.target.value)}
              placeholder="例如 计费团队 / billing"
            />
          </Field>
        </div>

        <Field
          label="重定向 URI"
          htmlFor="oidc-create-redirects"
          required
          hint="每行一个。必须为 HTTPS（localhost 可用 HTTP）且不能包含 fragment。"
        >
          <Textarea
            id="oidc-create-redirects"
            value={redirectURIs}
            onChange={(event) => setRedirectURIs(event.target.value)}
            rows={3}
            placeholder={'https://app.example.com/callback\nhttp://localhost:3000/callback'}
          />
        </Field>

        <Field
          label="登出回调 URI"
          htmlFor="oidc-create-post-logout"
          hint="RP-initiated logout 的返回地址，每行一个，最多 10 个；必须精确匹配。留空表示不向应用回跳。"
        >
          <Textarea
            id="oidc-create-post-logout"
            value={postLogoutURIs}
            onChange={(event) => setPostLogoutURIs(event.target.value)}
            rows={2}
            placeholder="https://app.example.com/logged-out"
          />
        </Field>

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            Scope <span className="text-rose-500">*</span>
          </div>
          <ScopePicker
            selected={createScopes}
            onToggle={(scope) =>
              setCreateScopes((current) => toggleInSet(current, scope, scope === 'openid'))
            }
            idPrefix="oidc-create-scope"
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="客户端类型"
            hint={
              isPublic
                ? '公开客户端（无 client_secret），强制使用 PKCE。'
                : '机密客户端，创建时签发一次性 client_secret。'
            }
          >
            <Switch
              checked={isPublic}
              onCheckedChange={(next) => {
                setIsPublic(next)
                if (next) setRequirePKCE(true)
              }}
              label={isPublic ? '公开客户端' : '机密客户端'}
            />
          </Field>
          <Field label="PKCE" hint="公开客户端必须启用 PKCE（S256）。">
            <Checkbox
              checked={isPublic ? true : requirePKCE}
              disabled={isPublic}
              onChange={(event) => setRequirePKCE(event.target.checked)}
              label="要求 PKCE code_challenge"
            />
          </Field>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Access Token TTL（秒）"
            htmlFor="oidc-create-access-ttl"
            required
            error={createAccessError}
            hint={`默认 ${DEFAULT_ACCESS_TTL} 秒，允许 ${ACCESS_TTL_MIN}–${ACCESS_TTL_MAX} 秒。`}
          >
            <Input
              id="oidc-create-access-ttl"
              type="number"
              min={ACCESS_TTL_MIN}
              max={ACCESS_TTL_MAX}
              value={accessTTL}
              onChange={(event) => setAccessTTL(event.target.value)}
              invalid={Boolean(createAccessError)}
            />
          </Field>
          <Field
            label="Refresh Token TTL（秒）"
            htmlFor="oidc-create-refresh-ttl"
            required
            error={createRefreshError}
            hint={`默认 ${DEFAULT_REFRESH_TTL} 秒，允许 ${REFRESH_TTL_MIN}–${REFRESH_TTL_MAX} 秒。`}
          >
            <Input
              id="oidc-create-refresh-ttl"
              type="number"
              min={REFRESH_TTL_MIN}
              max={REFRESH_TTL_MAX}
              value={refreshTTL}
              onChange={(event) => setRefreshTTL(event.target.value)}
              invalid={Boolean(createRefreshError)}
            />
          </Field>
        </div>

        <Field
          label="操作原因"
          htmlFor="oidc-create-reason"
          required
          hint="至少 2 个字符，会写入审计日志。"
        >
          <Textarea
            id="oidc-create-reason"
            value={createReason}
            onChange={(event) => setCreateReason(event.target.value)}
            rows={2}
            placeholder="例如：计费控制台接入 OIDC，工单 APP-1024"
          />
        </Field>
        {createClient.isError ? (
          <InlineAlert tone="danger" title="创建失败">
            {errorMessage(createClient.error)}
          </InlineAlert>
        ) : null}
      </Dialog>

      {/* Update */}
      <Dialog
        open={editTarget !== null}
        onClose={() => {
          if (!updateClient.isPending) setEditTarget(null)
        }}
        title="更新 OIDC 应用"
        description="服务归属与客户端类型不可修改；提交时携带当前版本，其余配置整体覆盖。"
        size="xl"
        bodyClassName="space-y-3"
        dismissible={!updateClient.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
              disabled={updateClient.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => updateClient.mutate(undefined)}
              loading={updateClient.isPending}
              disabled={!editValid}
            >
              保存更新
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="名称"
            htmlFor="oidc-edit-name"
            required
          >
            <Input
              id="oidc-edit-name"
              value={editName}
              onChange={(event) => setEditName(event.target.value)}
            />
          </Field>
          <Field
            label="服务归属"
            htmlFor="oidc-edit-owner"
            hint="由后端维护，更新接口不接受归属变更。"
          >
            <Input
              id="oidc-edit-owner"
              value={editTarget?.service_owner ?? ''}
              readOnly
              disabled
            />
          </Field>
        </div>
        <div className="text-[11px] text-slate-500">
          client_id：
          <span className="font-mono">{editTarget?.client_id ?? '—'}</span>
          {' · '}当前 revision：
          <span className="font-mono">{editTarget?.revision ?? '—'}</span>
        </div>

        <Field
          label="重定向 URI"
          htmlFor="oidc-edit-redirects"
          required
          hint="每行一个。必须为 HTTPS（localhost 可用 HTTP）且不能包含 fragment。"
        >
          <Textarea
            id="oidc-edit-redirects"
            value={editRedirectURIs}
            onChange={(event) => setEditRedirectURIs(event.target.value)}
            rows={3}
          />
        </Field>

        <Field
          label="登出回调 URI"
          htmlFor="oidc-edit-post-logout"
          hint="RP-initiated logout 的返回地址，每行一个，最多 10 个；必须精确匹配。留空表示不向应用回跳。"
        >
          <Textarea
            id="oidc-edit-post-logout"
            value={editPostLogoutURIs}
            onChange={(event) => setEditPostLogoutURIs(event.target.value)}
            rows={2}
          />
        </Field>

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            Scope <span className="text-rose-500">*</span>
          </div>
          <ScopePicker
            selected={editScopes}
            onToggle={(scope) =>
              setEditScopes((current) => toggleInSet(current, scope, scope === 'openid'))
            }
            idPrefix="oidc-edit-scope"
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="客户端类型"
            hint={
              editPublic
                ? '公开客户端（无 client_secret），强制使用 PKCE。'
                : '机密客户端。'
            }
          >
            <Badge tone={editPublic ? 'violet' : 'outline'}>
              {editPublic ? '公开客户端' : '机密客户端'}
            </Badge>
          </Field>
          <Field label="PKCE" hint="公开客户端必须启用 PKCE（S256）。">
            <Checkbox
              checked={editPublic ? true : editPKCE}
              disabled={editPublic}
              onChange={(event) => setEditPKCE(event.target.checked)}
              label="要求 PKCE code_challenge"
            />
          </Field>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Access Token TTL（秒）"
            htmlFor="oidc-edit-access-ttl"
            required
            error={editAccessError}
            hint={`默认 ${DEFAULT_ACCESS_TTL} 秒，允许 ${ACCESS_TTL_MIN}–${ACCESS_TTL_MAX} 秒。`}
          >
            <Input
              id="oidc-edit-access-ttl"
              type="number"
              min={ACCESS_TTL_MIN}
              max={ACCESS_TTL_MAX}
              value={editAccessTTL}
              onChange={(event) => setEditAccessTTL(event.target.value)}
              invalid={Boolean(editAccessError)}
            />
          </Field>
          <Field
            label="Refresh Token TTL（秒）"
            htmlFor="oidc-edit-refresh-ttl"
            required
            error={editRefreshError}
            hint={`默认 ${DEFAULT_REFRESH_TTL} 秒，允许 ${REFRESH_TTL_MIN}–${REFRESH_TTL_MAX} 秒。`}
          >
            <Input
              id="oidc-edit-refresh-ttl"
              type="number"
              min={REFRESH_TTL_MIN}
              max={REFRESH_TTL_MAX}
              value={editRefreshTTL}
              onChange={(event) => setEditRefreshTTL(event.target.value)}
              invalid={Boolean(editRefreshError)}
            />
          </Field>
        </div>

        <Field
          label="操作原因"
          htmlFor="oidc-edit-reason"
          required
          hint="至少 2 个字符，会写入审计日志。"
        >
          <Textarea
            id="oidc-edit-reason"
            value={editReason}
            onChange={(event) => setEditReason(event.target.value)}
            rows={2}
          />
        </Field>
        {updateClient.isError ? (
          <InlineAlert tone="danger" title="更新失败">
            {errorMessage(updateClient.error)}
          </InlineAlert>
        ) : null}
      </Dialog>

      <ClientSecretDialog
        credential={credential}
        onClose={() => setCredential(null)}
      />

      <ReasonDialog
        open={rotateTarget !== null}
        onClose={() => setRotateTarget(null)}
        onConfirm={(reason) => {
          if (rotateTarget) {
            rotateSecret.mutate({ client: rotateTarget, reason })
          }
        }}
        title="轮换客户端密钥"
        description="旧 client_secret 会立即失效，新密钥只展示一次。"
        confirmLabel="确认轮换"
        tone="danger"
        busy={rotateSecret.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          应用 {rotateTarget?.name} · {rotateTarget?.client_id}
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={disableTarget !== null}
        onClose={() => setDisableTarget(null)}
        onConfirm={(reason) => {
          if (disableTarget) {
            disableClient.mutate({ client: disableTarget, reason })
          }
        }}
        title="停用 OIDC 应用"
        description="停用后该 client_id 将无法再发起授权或换取 token。"
        confirmLabel="确认停用"
        tone="danger"
        busy={disableClient.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          应用 {disableTarget?.name} · {disableTarget?.client_id}
        </div>
      </ReasonDialog>
    </div>
  )
}
