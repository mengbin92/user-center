import { KeyRound, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, EmptyState, InlineAlert } from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { errorMessage } from '../../lib/errors'
import { useApiMutation } from '../../lib/mutations'
import type { SCIMToken } from '../../lib/types'

// Platform-administrator view of the SCIM credentials for one organization.
// It is rendered inside the organization settings page but only for platform
// administrators: the endpoints reject everyone else, and showing a form that
// can only fail is worse than not showing it.

type Pending = { kind: 'create' | 'rotate' | 'disable'; token?: SCIMToken }

export function OrganizationSCIMTokens({ orgId }: { orgId: string }) {
  const { hasAdmin } = useAuth()
  const tokensQuery = useQuery({
    queryKey: ['admin', 'scim-tokens', orgId],
    queryFn: () => api.admin.listSCIMTokens(orgId),
    enabled: hasAdmin,
    retry: false,
  })
  const [secret, setSecret] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [pending, setPending] = useState<Pending | null>(null)
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)

  const invalidate = [['admin', 'scim-tokens', orgId]]
  const createMutation = useApiMutation({
    mutationFn: (payload: { reason: string; name: string }) =>
      api.admin.createSCIMToken({
        organization_id: orgId, name: payload.name, reason: payload.reason,
      }),
    successMessage: 'SCIM 凭据已创建',
    invalidate,
    onSuccess: (reply) => {
      setCreating(false)
      setPending(null)
      setSecret(reply?.token_value ?? null)
    },
  })
  const rotateMutation = useApiMutation({
    mutationFn: (payload: { reason: string; token: SCIMToken }) =>
      api.admin.rotateSCIMToken(payload.token.id ?? '', {
        id: payload.token.id, expected_revision: payload.token.revision, reason: payload.reason,
      }),
    successMessage: 'SCIM 凭据已轮换',
    invalidate,
    onSuccess: (reply) => {
      setPending(null)
      setSecret(reply?.token_value ?? null)
    },
  })
  const disableMutation = useApiMutation({
    mutationFn: (payload: { reason: string; token: SCIMToken }) =>
      api.admin.disableSCIMToken(payload.token.id ?? '', {
        id: payload.token.id, expected_revision: payload.token.revision, reason: payload.reason,
      }),
    successMessage: 'SCIM 凭据已停用',
    invalidate,
    onSuccess: () => setPending(null),
  })

  if (!hasAdmin) return null

  const busy = createMutation.isPending || rotateMutation.isPending || disableMutation.isPending
  const items = tokensQuery.data?.items ?? []

  const run = (reason: string) => {
    if (!pending) return
    const action =
      pending.kind === 'create'
        ? createMutation.mutateAsync({ reason, name })
        : pending.kind === 'rotate' && pending.token
          ? rotateMutation.mutateAsync({ reason, token: pending.token })
          : pending.token
            ? disableMutation.mutateAsync({ reason, token: pending.token })
            : Promise.resolve()
    void action.catch((e) => setError(errorMessage(e)))
  }

  return (
    <Card>
      <CardHeader
        title="SCIM 2.0 用户供给"
        description="为身份提供方签发绑定本组织的 Bearer 凭据。凭据只显示一次，服务端仅保存摘要。"
        actions={
          <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />}
            onClick={() => { setError(null); setName(''); setCreating(true) }}>
            新建凭据
          </Button>
        }
      />
      <CardContent className="space-y-3">
        <InlineAlert tone="info">
          IdP 端点：<code>/scim/v2/Users</code> 与 <code>/scim/v2/Groups</code>。每个凭据只能读写本组织的用户与组。
        </InlineAlert>
        <QueryBoundary query={tokensQuery} loadingLabel="读取 SCIM 凭据…">
          {items.length === 0 ? (
            <EmptyState title="尚未签发凭据" description="签发后可在本组织的 IdP 中配置用户与组同步。" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>状态</TH>
                  <TH>凭据版本</TH>
                  <TH>最近使用</TH>
                  <TH />
                </TR>
              </THead>
              <TBody>
                {items.map((token) => (
                  <TR key={token.id}>
                    <TD>{token.name}</TD>
                    <TD>{token.status === 'active' ? '生效中' : '已停用'}</TD>
                    <TD>v{token.credential_version ?? '1'}</TD>
                    <TD>{token.last_used_at ? token.last_used_at.slice(0, 10) : '从未'}</TD>
                    <TD>
                      <div className="flex gap-1">
                        <Button size="sm" variant="ghost" icon={<RefreshCw className="h-3.5 w-3.5" />}
                          onClick={() => { setError(null); setPending({ kind: 'rotate', token }) }}>
                          轮换
                        </Button>
                        {token.status === 'active' ? (
                          <Button size="sm" variant="ghost" icon={<Trash2 className="h-3.5 w-3.5" />}
                            onClick={() => { setError(null); setPending({ kind: 'disable', token }) }}>
                            停用
                          </Button>
                        ) : null}
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </CardContent>

      <Dialog open={creating} onClose={() => setCreating(false)} title="签发 SCIM 凭据">
        <div className="space-y-3">
          <Field label="凭据名称" htmlFor="scim-token-name" hint="例如 IdP 名称或用途，便于轮换时辨认" required>
            <Input id="scim-token-name" value={name} placeholder="Okta production"
              onChange={(e) => setName(e.target.value)} />
          </Field>
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setCreating(false)}>取消</Button>
            <Button variant="primary" disabled={!name.trim()}
              icon={<KeyRound className="h-3.5 w-3.5" />}
              onClick={() => { setCreating(false); setPending({ kind: 'create' }) }}>
              下一步
            </Button>
          </div>
        </div>
      </Dialog>

      <ReasonDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={run}
        title={pending?.kind === 'rotate' ? '轮换 SCIM 凭据' : pending?.kind === 'disable' ? '停用 SCIM 凭据' : '签发 SCIM 凭据'}
        description={pending?.kind === 'disable'
          ? '停用后该 IdP 的所有供给请求会立即被拒绝；已供给的用户与组保留。'
          : '操作理由会写入平台审计；新凭据只显示一次。'}
        confirmLabel={pending?.kind === 'disable' ? '停用' : '确认'}
        tone={pending?.kind === 'disable' ? 'danger' : undefined}
        busy={busy}
      />

      <Dialog open={secret !== null} onClose={() => setSecret(null)} title="请立即保存凭据">
        <div className="space-y-3">
          <InlineAlert tone="info">
            这是唯一一次显示完整凭据。关闭后无法再次查看，只能轮换。
          </InlineAlert>
          <code className="block break-all rounded bg-slate-100 p-3 text-xs text-slate-800">{secret}</code>
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => setSecret(null)}>我已保存</Button>
          </div>
        </div>
      </Dialog>
    </Card>
  )
}
