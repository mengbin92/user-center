import {
  Ban,
  Copy,
  Pencil,
  Plus,
  Plug,
  RefreshCw,
  Webhook,
} from 'lucide-react'
import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardHeader,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Checkbox, Field, Input, Select, Textarea } from '../../components/input'
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
import { Tabs } from '../../components/tabs'
import { useToast } from '../../components/toast'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { formatDateTime, splitList, toRfc3339 } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type {
  EventDelivery,
  IntegrationClient,
  IntegrationClientCredentialReply,
} from '../../lib/types'

const INTEGRATION_METHODS = [
  'ValidateSession',
  'ValidateSubject',
  'GetUser',
  'BatchGetUsers',
  'GetSessionAuthorization',
  'GetResourceAuthorization',
  'RevokeSession',
] as const

type IntegrationTab = 'clients' | 'deliveries'

function shortMethod(method: string): string {
  const parts = method.split('/')
  return parts[parts.length - 1] || method
}

function normalizeMethods(methods?: string[]): Set<string> {
  return new Set((methods ?? []).map(shortMethod))
}

function deliveryTone(status?: string) {
  if (status === 'delivered') return 'success' as const
  if (status === 'retrying') return 'warning' as const
  if (status === 'pending') return 'info' as const
  return 'neutral' as const
}

function deliveryLabel(status?: string): string {
  if (status === 'delivered') return '已投递'
  if (status === 'retrying') return '重试中'
  if (status === 'pending') return '待投递'
  return status || '未知'
}

export function AdminIntegrationsPage() {
  const { can } = useAuth()
  const toast = useToast()
  const canReadClients = can('integration.client.read')
  const canWriteClients = can('integration.client.update')
  const canReadDeliveries = can('integration.delivery.read')
  const canRetryDeliveries = can('integration.delivery.update')

  const [tab, setTab] = useState<IntegrationTab>(
    canReadClients ? 'clients' : 'deliveries',
  )

  // Clients
  const clientsQuery = useQuery({
    queryKey: ['admin', 'integration-clients'],
    queryFn: () => api.integrations.listClients(),
    enabled: canReadClients,
    retry: false,
  })
  const clients = clientsQuery.data?.items ?? []

  const [credential, setCredential] =
    useState<IntegrationClientCredentialReply | null>(null)

  const [createOpen, setCreateOpen] = useState(false)
  const [code, setCode] = useState('')
  const [serviceOwner, setServiceOwner] = useState('')
  const [selectedMethods, setSelectedMethods] = useState<Set<string>>(
    new Set(['ValidateSession']),
  )
  const [eventSubscriptions, setEventSubscriptions] = useState('')
  const [callbackUrl, setCallbackUrl] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [createReason, setCreateReason] = useState('')

  const resetCreate = () => {
    setCode('')
    setServiceOwner('')
    setSelectedMethods(new Set(['ValidateSession']))
    setEventSubscriptions('')
    setCallbackUrl('')
    setExpiresAt('')
    setCreateReason('')
  }

  const createClient = useApiMutation({
    mutationFn: () =>
      api.integrations.createClient({
        code: code.trim(),
        service_owner: serviceOwner.trim(),
        allowed_methods: [...selectedMethods],
        event_subscriptions: splitList(eventSubscriptions),
        callback_url: callbackUrl.trim() || undefined,
        expires_at: toRfc3339(expiresAt),
        reason: createReason.trim(),
      }),
    successMessage: '接入客户端已创建',
    successDescription: '请立即保存一次性凭据，关闭后无法再次查看。',
    invalidate: [['admin', 'integration-clients']],
    onSuccess: (data) => {
      setCreateOpen(false)
      resetCreate()
      setCredential(data)
    },
  })

  const [editTarget, setEditTarget] = useState<IntegrationClient | null>(null)
  const [editMethods, setEditMethods] = useState<Set<string>>(new Set())
  const [editEvents, setEditEvents] = useState('')
  const [editCallback, setEditCallback] = useState('')
  const [editReason, setEditReason] = useState('')

  const openEdit = (client: IntegrationClient) => {
    setEditTarget(client)
    setEditMethods(normalizeMethods(client.allowed_methods))
    setEditEvents((client.event_subscriptions ?? []).join(', '))
    setEditCallback(client.callback_url ?? '')
    setEditReason('')
  }

  const updateClient = useApiMutation({
    mutationFn: () => {
      if (!editTarget) throw new Error('缺少接入客户端')
      return api.integrations.updateClient(editTarget.id ?? '', {
        id: editTarget.id,
        allowed_methods: [...editMethods],
        event_subscriptions: splitList(editEvents),
        callback_url: editCallback.trim(),
        expected_revision: editTarget.revision ?? '0',
        reason: editReason.trim(),
      })
    },
    successMessage: '接入客户端已更新',
    invalidate: [['admin', 'integration-clients']],
    onSuccess: () => setEditTarget(null),
  })

  const [rotateTarget, setRotateTarget] = useState<IntegrationClient | null>(
    null,
  )
  const rotateCredential = useApiMutation({
    mutationFn: (input: { client: IntegrationClient; reason: string }) =>
      api.integrations.rotateCredential(input.client.id ?? '', {
        id: input.client.id,
        expected_revision: input.client.revision,
        reason: input.reason,
      }),
    successMessage: '凭据已轮换',
    successDescription: '旧凭据立即失效，请保存新凭据。',
    invalidate: [['admin', 'integration-clients']],
    onSuccess: (data) => {
      setRotateTarget(null)
      setCredential(data)
    },
  })

  const [disableTarget, setDisableTarget] =
    useState<IntegrationClient | null>(null)
  const disableClient = useApiMutation({
    mutationFn: (input: { client: IntegrationClient; reason: string }) =>
      api.integrations.disableClient(input.client.id ?? '', {
        id: input.client.id,
        expected_revision: input.client.revision,
        reason: input.reason,
      }),
    successMessage: '接入客户端已停用',
    invalidate: [['admin', 'integration-clients']],
    onSuccess: () => setDisableTarget(null),
  })

  const toggleMethod = (method: string) => {
    setSelectedMethods((current) => {
      const next = new Set(current)
      if (next.has(method)) next.delete(method)
      else next.add(method)
      return next
    })
  }

  const toggleEditMethod = (method: string) => {
    setEditMethods((current) => {
      const next = new Set(current)
      if (next.has(method)) next.delete(method)
      else next.add(method)
      return next
    })
  }

  // Deliveries
  const [deliveryStatus, setDeliveryStatus] = useState('')
  const [deliveryTokens, setDeliveryTokens] = useState<string[]>([''])
  const deliveryToken = deliveryTokens[deliveryTokens.length - 1] ?? ''
  const deliveriesQuery = useQuery({
    queryKey: [
      'admin',
      'event-deliveries',
      { status: deliveryStatus, pageToken: deliveryToken },
    ],
    queryFn: () =>
      api.integrations.listEventDeliveries({
        status: deliveryStatus || undefined,
        page_size: 20,
        page_token: deliveryToken || undefined,
      }),
    enabled: tab === 'deliveries' && canReadDeliveries,
    retry: false,
    placeholderData: keepPreviousData,
  })
  const deliveries = deliveriesQuery.data?.items ?? []
  const nextDeliveryToken = deliveriesQuery.data?.meta?.next_page_token
  const [retryTarget, setRetryTarget] = useState<EventDelivery | null>(null)
  const retryDelivery = useApiMutation({
    mutationFn: (input: { delivery: EventDelivery; reason: string }) =>
      api.integrations.retryEventDelivery(
        input.delivery.event_id ?? '',
        input.delivery.subscriber_id ?? '',
        {
          event_id: input.delivery.event_id,
          subscriber_id: input.delivery.subscriber_id,
          reason: input.reason,
        },
      ),
    successMessage: '已加入重试队列',
    invalidate: [['admin', 'event-deliveries']],
    onSuccess: () => setRetryTarget(null),
  })

  const copyCredential = async () => {
    if (!credential?.credential) return
    try {
      await navigator.clipboard.writeText(credential.credential)
      toast.success('凭据已复制', '请立即保存到安全的密钥管理系统中。')
    } catch {
      toast.error('复制失败', '请手动选择并复制凭据。')
    }
  }

  const tabs = [
    ...(canReadClients
      ? [{ key: 'clients', label: '接入客户端' }]
      : []),
    ...(canReadDeliveries
      ? [{ key: 'deliveries', label: '事件投递' }]
      : []),
  ]

  const createValid =
    code.trim().length > 0 &&
    serviceOwner.trim().length > 0 &&
    selectedMethods.size > 0 &&
    createReason.trim().length >= 2
  const editValid =
    editMethods.size > 0 && editReason.trim().length >= 2

  return (
    <div className="space-y-4">
      <PageTitle title="接入服务" />
      <PageHeader
        eyebrow="Integration"
        title="接入服务"
        description="管理可调用内部 gRPC API、订阅 Outbox 事件并接收 webhook 的服务客户端。所有写操作需要近期安全验证。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              if (tab === 'clients') void clientsQuery.refetch()
              else void deliveriesQuery.refetch()
            }}
            loading={
              tab === 'clients'
                ? clientsQuery.isFetching
                : deliveriesQuery.isFetching
            }
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
        }
      />

      {tabs.length > 1 ? (
        <Card>
          <div className="px-3 pt-2">
            <Tabs
              tabs={tabs}
              value={tab}
              onChange={(key) => setTab(key as IntegrationTab)}
            />
          </div>
        </Card>
      ) : null}

      {tab === 'clients' ? (
        <Card>
          <CardHeader
            title="接入客户端"
            description="一次性凭据只在创建或轮换时展示，不会保存在浏览器存储中。"
            actions={
              canWriteClients ? (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    resetCreate()
                    setCreateOpen(true)
                  }}
                  icon={<Plus className="h-3.5 w-3.5" />}
                >
                  创建客户端
                </Button>
              ) : (
                <Badge tone="neutral">只读</Badge>
              )
            }
          />
          <QueryBoundary query={clientsQuery} loadingLabel="读取接入客户端…">
            {clients.length === 0 ? (
              <EmptyState
                title="暂无接入客户端"
                description="创建后即可签发一次性凭据，用于服务间 gRPC 鉴权与事件订阅。"
                icon={Plug}
              />
            ) : (
              <Table minWidth="min-w-[1180px]">
                <THead>
                  <TR>
                    <TH>客户端</TH>
                    <TH>归属</TH>
                    <TH>状态</TH>
                    <TH>允许方法</TH>
                    <TH>事件订阅</TH>
                    <TH>回调地址</TH>
                    <TH>凭据版本</TH>
                    <TH>过期时间</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {clients.map((client) => (
                    <TR key={client.id}>
                      <TD>
                        <div className="text-xs font-medium text-slate-800">
                          {client.code}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {client.client_id} · rev {client.revision}
                        </div>
                      </TD>
                      <TD className="text-[11px] text-slate-600">
                        {client.service_owner || '—'}
                      </TD>
                      <TD>
                        {client.status === 'active' ? (
                          <Badge tone="success" dot>
                            启用中
                          </Badge>
                        ) : (
                          <Badge tone="neutral" dot>
                            已停用
                          </Badge>
                        )}
                      </TD>
                      <TD>
                        <div className="flex max-w-[220px] flex-wrap gap-1">
                          {(client.allowed_methods ?? []).slice(0, 4).map((method) => (
                            <Badge key={method} tone="outline">
                              {shortMethod(method)}
                            </Badge>
                          ))}
                          {(client.allowed_methods?.length ?? 0) > 4 ? (
                            <Badge tone="neutral">
                              +{(client.allowed_methods?.length ?? 0) - 4}
                            </Badge>
                          ) : null}
                        </div>
                      </TD>
                      <TD>
                        <div className="flex max-w-[180px] flex-wrap gap-1">
                          {(client.event_subscriptions ?? []).length ? (
                            (client.event_subscriptions ?? []).map((event) => (
                              <Badge key={event} tone="info">
                                {event}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-[11px] text-slate-400">—</span>
                          )}
                        </div>
                      </TD>
                      <TD className="max-w-[180px] truncate font-mono text-[10px] text-slate-500">
                        {client.callback_url || '—'}
                      </TD>
                      <TD className="text-[11px] text-slate-600">
                        v{client.credential_version ?? 1}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {client.expires_at
                          ? formatDateTime(client.expires_at)
                          : '永久'}
                      </TD>
                      <TD className="text-right">
                        {canWriteClients && client.status === 'active' ? (
                          <div className="flex flex-wrap justify-end gap-1">
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => openEdit(client)}
                              icon={<Pencil className="h-3 w-3" />}
                            >
                              编辑
                            </Button>
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => setRotateTarget(client)}
                              icon={<RefreshCw className="h-3 w-3" />}
                            >
                              轮换
                            </Button>
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
      ) : null}

      {tab === 'deliveries' ? (
        <Card>
          <CardHeader
            title="事件投递"
            description="Outbox 事件向订阅客户端投递的状态；失败投递可带原因重试。"
            actions={
              <Select
                className="h-8 w-32 text-xs"
                value={deliveryStatus}
                onChange={(event) => {
                  setDeliveryStatus(event.target.value)
                  setDeliveryTokens([''])
                }}
                aria-label="投递状态筛选"
              >
                <option value="">全部状态</option>
                <option value="pending">待投递</option>
                <option value="retrying">重试中</option>
                <option value="delivered">已投递</option>
              </Select>
            }
          />
          <QueryBoundary query={deliveriesQuery} loadingLabel="读取事件投递…">
            {deliveries.length === 0 ? (
              <EmptyState
                title="暂无事件投递"
                description="接入客户端订阅事件并配置回调地址后，Outbox 会在此记录投递状态。"
                icon={Webhook}
              />
            ) : (
              <>
                <Table minWidth="min-w-[980px]">
                  <THead>
                    <TR>
                      <TH>事件</TH>
                      <TH>订阅客户端</TH>
                      <TH>状态</TH>
                      <TH>尝试次数</TH>
                      <TH>下次重试</TH>
                      <TH>最近错误</TH>
                      <TH className="text-right">操作</TH>
                    </TR>
                  </THead>
                  <TBody>
                    {deliveries.map((delivery) => (
                      <TR
                        key={`${delivery.event_id}-${delivery.subscriber_id}`}
                      >
                        <TD>
                          <div className="font-mono text-[10px] text-slate-800">
                            {delivery.event_id}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {delivery.event_type || '—'}
                          </div>
                        </TD>
                        <TD className="font-mono text-[10px] text-slate-600">
                          {delivery.subscriber_id}
                        </TD>
                        <TD>
                          <Badge tone={deliveryTone(delivery.status)} dot>
                            {deliveryLabel(delivery.status)}
                          </Badge>
                        </TD>
                        <TD className="text-[11px] tabular-nums text-slate-600">
                          {delivery.attempts ?? 0}
                        </TD>
                        <TD className="whitespace-nowrap text-[11px] text-slate-500">
                          {formatDateTime(delivery.next_retry_at)}
                        </TD>
                        <TD className="max-w-[240px] truncate text-[10px] text-rose-600">
                          {delivery.last_error || '—'}
                        </TD>
                        <TD className="text-right">
                          {canRetryDeliveries ? (
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => setRetryTarget(delivery)}
                              icon={<RefreshCw className="h-3 w-3" />}
                            >
                              重试
                            </Button>
                          ) : null}
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
                <Pagination
                  total={deliveriesQuery.data?.meta?.total_size}
                  pageIndex={deliveryTokens.length}
                  hasNext={Boolean(nextDeliveryToken)}
                  onPrev={() =>
                    setDeliveryTokens((current) =>
                      current.length > 1 ? current.slice(0, -1) : current,
                    )
                  }
                  onNext={() => {
                    if (nextDeliveryToken) {
                      setDeliveryTokens((current) => [
                        ...current,
                        nextDeliveryToken,
                      ])
                    }
                  }}
                  onRefresh={() => void deliveriesQuery.refetch()}
                  loading={deliveriesQuery.isFetching}
                />
              </>
            )}
          </QueryBoundary>
        </Card>
      ) : null}

      {/* Create client */}
      <Dialog
        open={createOpen}
        onClose={() => {
          if (!createClient.isPending) setCreateOpen(false)
        }}
        title="创建接入客户端"
        description="创建成功后服务端只返回一次明文凭据，请立即保存。"
        size="lg"
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
              icon={<Plug className="h-3.5 w-3.5" />}
            >
              创建并签发凭据
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="客户端代码" htmlFor="integration-code" required>
            <Input
              id="integration-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="例如 billing-service"
            />
          </Field>
          <Field label="服务归属" htmlFor="integration-owner" required>
            <Input
              id="integration-owner"
              value={serviceOwner}
              onChange={(event) => setServiceOwner(event.target.value)}
              placeholder="例如 计费团队 / billing"
            />
          </Field>
        </div>

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            允许的 gRPC 方法 <span className="text-rose-500">*</span>
          </div>
          <div className="grid gap-1 rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {INTEGRATION_METHODS.map((method) => (
              <Checkbox
                key={method}
                checked={selectedMethods.has(method)}
                onChange={() => toggleMethod(method)}
                label={method}
              />
            ))}
          </div>
        </div>

        <Field
          label="事件订阅"
          htmlFor="integration-events"
          hint="逗号或换行分隔，例如 user.created,user.status.changed；* 表示全部。"
        >
          <Input
            id="integration-events"
            value={eventSubscriptions}
            onChange={(event) => setEventSubscriptions(event.target.value)}
            placeholder="user.created, user.profile.updated"
          />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="回调地址" htmlFor="integration-callback">
            <Input
              id="integration-callback"
              type="url"
              value={callbackUrl}
              onChange={(event) => setCallbackUrl(event.target.value)}
              placeholder="https://example.com/webhooks/user-center"
            />
          </Field>
          <Field
            label="过期时间"
            htmlFor="integration-expires"
            hint="留空表示永久有效"
          >
            <Input
              id="integration-expires"
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </Field>
        </div>
        <Field
          label="操作原因"
          htmlFor="integration-create-reason"
          required
          hint="至少 2 个字符，会写入审计日志。"
        >
          <Textarea
            id="integration-create-reason"
            value={createReason}
            onChange={(event) => setCreateReason(event.target.value)}
            rows={2}
            placeholder="例如：计费服务接入用户查询，工单 INT-88"
          />
        </Field>
        {createClient.isError ? (
          <InlineAlert tone="danger" title="创建失败">
            {errorMessage(createClient.error)}
          </InlineAlert>
        ) : null}
      </Dialog>

      {/* Edit client */}
      <Dialog
        open={editTarget !== null}
        onClose={() => {
          if (!updateClient.isPending) setEditTarget(null)
        }}
        title="更新接入客户端"
        description="提交时携带当前 revision；允许方法、事件订阅与回调地址会整体覆盖。"
        size="lg"
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
        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-700">
            允许的 gRPC 方法 <span className="text-rose-500">*</span>
          </div>
          <div className="grid gap-1 rounded-md border border-slate-200 p-2 sm:grid-cols-2">
            {INTEGRATION_METHODS.map((method) => (
              <Checkbox
                key={method}
                checked={editMethods.has(method)}
                onChange={() => toggleEditMethod(method)}
                label={method}
              />
            ))}
          </div>
        </div>
        <Field label="事件订阅" htmlFor="integration-edit-events">
          <Input
            id="integration-edit-events"
            value={editEvents}
            onChange={(event) => setEditEvents(event.target.value)}
            placeholder="user.created, user.profile.updated"
          />
        </Field>
        <Field label="回调地址" htmlFor="integration-edit-callback">
          <Input
            id="integration-edit-callback"
            type="url"
            value={editCallback}
            onChange={(event) => setEditCallback(event.target.value)}
            placeholder="https://example.com/webhooks/user-center"
          />
        </Field>
        <Field
          label="操作原因"
          htmlFor="integration-edit-reason"
          required
          hint="至少 2 个字符，会写入审计日志。"
        >
          <Textarea
            id="integration-edit-reason"
            value={editReason}
            onChange={(event) => setEditReason(event.target.value)}
            rows={2}
          />
        </Field>
        <div className="text-[11px] text-slate-500">
          当前 revision：
          <span className="font-mono">{editTarget?.revision ?? '—'}</span>
        </div>
        {updateClient.isError ? (
          <InlineAlert tone="danger" title="更新失败">
            {errorMessage(updateClient.error)}
          </InlineAlert>
        ) : null}
      </Dialog>

      {/* One-time credential */}
      <Dialog
        open={credential !== null}
        onClose={() => setCredential(null)}
        title="请立即保存接入凭据"
        description="明文凭据仅在本次响应中返回一次，关闭后无法再次查看，也不会写入浏览器存储。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void copyCredential()}
              icon={<Copy className="h-3.5 w-3.5" />}
            >
              复制凭据
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setCredential(null)}
            >
              我已保存
            </Button>
          </>
        }
      >
        <InlineAlert tone="warning" title="一次性凭据">
          请立即保存到密钥管理系统。关闭此对话框后平台无法恢复明文凭据，只能重新轮换。
        </InlineAlert>
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
          <div className="text-[11px] text-slate-500">客户端</div>
          <div className="text-xs font-medium text-slate-800">
            {credential?.client?.code || '—'} ·{' '}
            <span className="font-mono">
              {credential?.client?.client_id || '—'}
            </span>
          </div>
        </div>
        <div className="rounded-md border border-amber-200 bg-amber-50 p-3">
          <div className="text-[11px] font-medium text-amber-800">凭据</div>
          <code className="mt-1 block break-all rounded bg-white/80 px-2 py-1.5 font-mono text-[11px] text-slate-800">
            {credential?.credential || '—'}
          </code>
        </div>
      </Dialog>

      <ReasonDialog
        open={rotateTarget !== null}
        onClose={() => setRotateTarget(null)}
        onConfirm={(rotateReason) => {
          if (rotateTarget) {
            rotateCredential.mutate({
              client: rotateTarget,
              reason: rotateReason,
            })
          }
        }}
        title="轮换接入凭据"
        description="旧凭据会立即失效，新凭据只展示一次。"
        confirmLabel="确认轮换"
        tone="danger"
        busy={rotateCredential.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          客户端 {rotateTarget?.code} · {rotateTarget?.client_id}
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={disableTarget !== null}
        onClose={() => setDisableTarget(null)}
        onConfirm={(disableReason) => {
          if (disableTarget) {
            disableClient.mutate({
              client: disableTarget,
              reason: disableReason,
            })
          }
        }}
        title="停用接入客户端"
        description="停用后该客户端不能再调用 gRPC API，也不再接收事件投递。"
        confirmLabel="确认停用"
        tone="danger"
        busy={disableClient.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          客户端 {disableTarget?.code} · {disableTarget?.client_id}
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={retryTarget !== null}
        onClose={() => setRetryTarget(null)}
        onConfirm={(retryReason) => {
          if (retryTarget) {
            retryDelivery.mutate({
              delivery: retryTarget,
              reason: retryReason,
            })
          }
        }}
        title="重试事件投递"
        description="会把该投递状态重置为待投递，并在下一轮调度中重新发送。"
        confirmLabel="确认重试"
        busy={retryDelivery.isPending}
      >
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
          事件 {retryTarget?.event_id} · 订阅方 {retryTarget?.subscriber_id}
        </div>
      </ReasonDialog>
    </div>
  )
}
