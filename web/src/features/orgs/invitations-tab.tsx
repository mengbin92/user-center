import { MailPlus, RefreshCw, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import { Card, CardHeader, EmptyState, InlineAlert } from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { OrganizationInvitation } from '../../lib/types'

export function OrganizationInvitationsTab({
  orgId,
  active,
}: {
  orgId: string
  active: boolean
}) {
  const [createOpen, setCreateOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('member')
  const [reason, setReason] = useState('')
  const [target, setTarget] = useState<OrganizationInvitation | null>(null)
  const [error, setError] = useState('')

  const invitations = useQuery({
    queryKey: ['orgs', orgId, 'invitations'],
    queryFn: () => api.orgs.listInvitations(orgId),
    enabled: active,
    retry: false,
  })

  const create = useApiMutation({
    mutationFn: () =>
      api.orgs.createInvitation(orgId, {
        id: orgId,
        email,
        role,
        reason,
      }),
    successMessage: '邀请已发送',
    successDescription: '邀请链接只会发送到收件邮箱，默认 72 小时内有效。',
    invalidate: [['orgs', orgId, 'invitations']],
    onSuccess: () => {
      setCreateOpen(false)
      setEmail('')
      setReason('')
    },
    onError: (cause) => setError(cause.message),
  })

  const revoke = useApiMutation({
    mutationFn: (item: OrganizationInvitation) =>
      api.orgs.revokeInvitation(
        orgId,
        item.id ?? '',
        '管理员撤销邀请',
        item.revision ?? '1',
      ),
    successMessage: '邀请已撤销',
    invalidate: [['orgs', orgId, 'invitations']],
    onSuccess: () => setTarget(null),
  })

  const items = invitations.data?.items ?? []

  return (
    <div className="space-y-4">
      <InlineAlert tone="info" title="按邮箱邀请">
        被邀请人需要先用同一邮箱注册或登录，再凭邮件中的一次性链接接受邀请。邀请令牌只以哈希形式保存在服务端。
      </InlineAlert>

      <Card>
        <CardHeader
          title="组织邀请"
          description="待接受邀请默认 72 小时有效；重复邀请同一邮箱会作废旧令牌。"
          actions={
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => void invitations.refetch()}
              >
                <RefreshCw className="h-3.5 w-3.5" />
                刷新
              </Button>
              <Button
                size="sm"
                variant="primary"
                onClick={() => setCreateOpen(true)}
              >
                <MailPlus className="h-3.5 w-3.5" />
                发起邀请
              </Button>
            </div>
          }
        />
        <QueryBoundary query={invitations}>
          {items.length === 0 ? (
            <EmptyState title="还没有邀请记录" description="发起邀请后可在面板中查看状态并撤销。" />
          ) : (
            <Table minWidth="min-w-[760px]">
              <THead>
                <TR>
                  <TH>邮箱</TH>
                  <TH>角色</TH>
                  <TH>状态</TH>
                  <TH>过期时间</TH>
                  <TH>创建时间</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {items.map((item) => (
                  <TR key={item.id}>
                    <TD className="font-mono text-[11px]">{item.email}</TD>
                    <TD><Badge tone="info">{item.role}</Badge></TD>
                    <TD><StatusBadge status={item.status ?? ''} /></TD>
                    <TD className="text-xs text-slate-500">{formatDateTime(item.expires_at)}</TD>
                    <TD className="text-xs text-slate-500">{formatDateTime(item.created_at)}</TD>
                    <TD className="text-right">
                      <Button
                        size="xs"
                        variant="ghost"
                        disabled={item.status !== 'pending'}
                        onClick={() => setTarget(item)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        撤销
                      </Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="邀请成员"
        description="邀请链接将发送到该邮箱；服务端只保存令牌哈希。"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>取消</Button>
            <Button
              variant="primary"
              loading={create.isPending}
              disabled={!email.trim() || reason.trim().length < 2}
              onClick={() => void create.mutateAsync()}
            >
              发送邀请
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <Field label="收件邮箱">
            <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@example.com" />
          </Field>
          <Field label="组织角色">
            <Select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="member">member（普通成员）</option>
              <option value="admin">admin（组织管理员）</option>
              <option value="owner">owner（组织所有者）</option>
            </Select>
          </Field>
          <Field label="原因">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="用于审计留痕" />
          </Field>
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
        </div>
      </Dialog>

      <Dialog
        open={Boolean(target)}
        onClose={() => setTarget(null)}
        title="撤销邀请"
        description={`撤销后 ${target?.email ?? ''} 的邀请链接立即失效。`}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setTarget(null)}>取消</Button>
            <Button
              variant="danger"
              loading={revoke.isPending}
              onClick={() => target && void revoke.mutateAsync(target)}
            >
              确认撤销
            </Button>
          </div>
        }
      >
        <p className="text-xs text-slate-500">该操作会写入租户审计。</p>
      </Dialog>
    </div>
  )
}
