import { Database, Play, Plus, RotateCcw } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, EmptyState, InlineAlert } from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select, Textarea } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { useApiMutation } from '../../lib/mutations'
import type { DirectorySource } from '../../lib/types'

// Platform-administrator view of enterprise directory connectors. Like the
// SCIM token panel it is rendered only for platform administrators: the API
// rejects everyone else.

const DEFAULT_CONFIG = JSON.stringify({
  url: '',
  interval_seconds: 300,
  deletion_policy: 'disable',
  conflict_policy: 'source_wins',
}, null, 2)

type Action =
  | { kind: 'create' }
  | { kind: 'sync'; source: DirectorySource }
  | { kind: 'rotate'; source: DirectorySource }

export function OrganizationDirectorySync({ orgId }: { orgId: string }) {
  const { hasAdmin } = useAuth()
  const sourcesQuery = useQuery({
    queryKey: ['admin', 'directory-sources', orgId],
    queryFn: () => api.admin.listDirectorySources(orgId),
    enabled: hasAdmin,
    retry: false,
  })
  const runsQuery = useQuery({
    queryKey: ['admin', 'directory-runs', orgId],
    queryFn: async () => {
      const sources = sourcesQuery.data?.items ?? []
      if (sources.length === 0 || !sources[0].id) return { items: [] }
      return api.admin.listDirectorySyncRuns(sources[0].id)
    },
    enabled: hasAdmin && (sourcesQuery.data?.items?.length ?? 0) > 0,
    retry: false,
  })
  const [creating, setCreating] = useState(false)
  const [action, setAction] = useState<Action | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [kind, setKind] = useState('jsonfeed')
  const [name, setName] = useState('')
  const [config, setConfig] = useState(DEFAULT_CONFIG)
  const [secret, setSecret] = useState('')
  const [mode, setMode] = useState('delta')

  const invalidate = [['admin', 'directory-sources', orgId], ['admin', 'directory-runs', orgId]]
  const createMutation = useApiMutation({
    mutationFn: (payload: { reason: string }) =>
      api.admin.createDirectorySource({
        organization_id: orgId, kind, name, config_json: config,
        secret, reason: payload.reason,
      }),
    successMessage: '目录源已创建',
    invalidate,
    onSuccess: () => { setCreating(false); setAction(null) },
  })
  const syncMutation = useApiMutation({
    mutationFn: (payload: { reason: string; sourceId: string; syncMode: string }) =>
      api.admin.triggerDirectorySync(payload.sourceId, {
        id: payload.sourceId, mode: payload.syncMode, reason: payload.reason,
      }),
    successMessage: '同步已执行',
    invalidate,
    onSuccess: (run) => {
      setAction(null)
      setNotice(`状态 ${run?.status ?? '未知'}：读取 ${run?.fetched ?? 0}，新建 ${run?.created_count ?? 0}，停用 ${run?.disabled_count ?? 0}，失败 ${run?.failed_count ?? 0}`)
    },
  })
  const rotateMutation = useApiMutation({
    mutationFn: (payload: { reason: string; sourceId: string; expectedRevision: string }) =>
      api.admin.rotateDirectorySourceSecret(payload.sourceId, {
        secret, expected_revision: payload.expectedRevision, reason: payload.reason,
      }),
    successMessage: '目录凭据已轮换',
    invalidate,
    onSuccess: () => { setAction(null); setSecret('') },
  })

  if (!hasAdmin) return null

  const busy = createMutation.isPending || syncMutation.isPending || rotateMutation.isPending
  const items = sourcesQuery.data?.items ?? []

  const run = (reason: string) => {
    if (!action) return
    let task: Promise<unknown>
    if (action.kind === 'create') {
      task = createMutation.mutateAsync({ reason })
    } else if (action.kind === 'sync') {
      task = syncMutation.mutateAsync({
        reason, sourceId: action.source.id ?? '', syncMode: mode,
      })
    } else {
      task = rotateMutation.mutateAsync({
        reason, sourceId: action.source.id ?? '',
        expectedRevision: action.source.revision ?? '0',
      })
    }
    void task.catch((e) => setError(errorMessage(e)))
  }

  return (
    <Card>
      <CardHeader
        title="企业目录同步"
        description="从 LDAP / AD 或 JSON 目录网关拉取用户，按 externalId 对账并供给到本组织。凭据加密存储且永不在读取中回显。"
        actions={
          <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />}
            onClick={() => { setError(null); setCreating(true) }}>
            新建目录源
          </Button>
        }
      />
      <CardContent className="space-y-3">
        {notice ? <InlineAlert tone="info">{notice}</InlineAlert> : null}
        <QueryBoundary query={sourcesQuery} loadingLabel="读取目录源…">
          {items.length === 0 ? (
            <EmptyState title="尚未配置目录源" description="支持 ldap / ldaps 与 jsonfeed 两类连接器。" />
          ) : (
            <Table>
              <THead>
                <TR><TH>名称</TH><TH>类型</TH><TH>状态</TH><TH>增量游标</TH><TH /></TR>
              </THead>
              <TBody>
                {items.map((source) => (
                  <TR key={source.id}>
                    <TD>{source.name}</TD>
                    <TD>{source.kind}</TD>
                    <TD>{source.status === 'active' ? '启用' : '暂停'}</TD>
                    <TD className="max-w-[160px] truncate">{source.cursor || '—'}</TD>
                    <TD>
                      <div className="flex gap-1">
                        <Button size="sm" variant="ghost" icon={<Play className="h-3.5 w-3.5" />}
                          onClick={() => { setError(null); setMode('delta'); setAction({ kind: 'sync', source }) }}>
                          同步
                        </Button>
                        <Button size="sm" variant="ghost" icon={<RotateCcw className="h-3.5 w-3.5" />}
                          onClick={() => { setError(null); setSecret(''); setAction({ kind: 'rotate', source }) }}>
                          轮换凭据
                        </Button>
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
        {runsQuery.data?.items?.length ? (
          <div className="rounded border border-slate-200 p-3 text-xs text-slate-600">
            <div className="font-medium text-slate-700">最近一次同步</div>
            <div>
              {runsQuery.data.items[0].mode} · {runsQuery.data.items[0].status} ·
              读取 {runsQuery.data.items[0].fetched ?? 0} ·
              新建 {runsQuery.data.items[0].created_count ?? 0} ·
              停用 {runsQuery.data.items[0].disabled_count ?? 0} ·
              失败 {runsQuery.data.items[0].failed_count ?? 0}
            </div>
          </div>
        ) : null}
      </CardContent>

      <Dialog open={creating} onClose={() => setCreating(false)} title="新建目录源">
        <div className="space-y-3">
          <Field label="类型" htmlFor="dir-kind">
            <Select id="dir-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="jsonfeed">JSON 目录网关</option>
              <option value="ldap">LDAP / Active Directory</option>
            </Select>
          </Field>
          <Field label="名称" htmlFor="dir-name" required>
            <Input id="dir-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="corp-ad" />
          </Field>
          <Field label="连接配置（JSON）" htmlFor="dir-config" hint="只放非敏感配置：url、base_dn、bind_dn、过滤器、属性映射、interval_seconds、策略">
            <Textarea id="dir-config" rows={6} value={config} onChange={(e) => setConfig(e.target.value)} />
          </Field>
          <Field label="外部凭据" htmlFor="dir-secret" hint="绑定密码或 API token，加密入库，创建后不可再查看">
            <Input id="dir-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setCreating(false)}>取消</Button>
            <Button variant="primary" disabled={!name.trim()} icon={<Database className="h-3.5 w-3.5" />}
              onClick={() => setAction({ kind: 'create' })}>
              下一步
            </Button>
          </div>
        </div>
      </Dialog>

      <ReasonDialog
        open={action !== null}
        onClose={() => setAction(null)}
        onConfirm={run}
        title={action?.kind === 'create' ? '创建目录源' : action?.kind === 'rotate' ? '轮换目录凭据' : '执行目录同步'}
        description={action?.kind === 'rotate'
          ? '新凭据会加密覆盖旧值，变更理由写入平台审计。'
          : '变更理由会写入平台审计；同步结果会生成一条包含逐对象结果的运行记录。'}
        confirmLabel="确认"
        busy={busy}
        error={error}
      >
        {action?.kind === 'sync' ? (
          <Field label="同步方式" htmlFor="dir-mode">
            <Select id="dir-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="delta">增量（按游标）</option>
              <option value="full">全量（含对账）</option>
              <option value="dry_run">预演（不写入）</option>
            </Select>
          </Field>
        ) : null}
        {action?.kind === 'rotate' ? (
          <Field label="新凭据" htmlFor="dir-new-secret">
            <Input id="dir-new-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
        ) : null}
      </ReasonDialog>
    </Card>
  )
}
