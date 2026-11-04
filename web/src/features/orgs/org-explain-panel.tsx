import { Search } from 'lucide-react'
import { useState } from 'react'

import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
} from '../../components/card'
import { Field, Input } from '../../components/input'
import { api } from '../../lib/api'
import { useApiMutation } from '../../lib/mutations'
import type { ExplainOrgAuthorizationReply } from '../../lib/types'

export function OrgExplainPanel({ orgId }: { orgId: string }) {
  const [userId, setUserId] = useState('')
  const [operation, setOperation] = useState('organization.department.manage')
  const [reply, setReply] = useState<ExplainOrgAuthorizationReply | null>(null)

  const explain = useApiMutation({
    mutationFn: () =>
      api.orgs.explainAuthorization(orgId, {
        user_id: userId.trim(),
        operation: operation.trim(),
      }),
    onSuccess: (data) => setReply(data),
  })

  const sources = reply?.sources ?? []

  return (
    <Card>
      <CardHeader
        title="授权决策解释"
        description="在本组织上下文内解释某成员对某操作为何允许或拒绝；只加载本租户的角色与授权事实。"
      />
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-40">
            <Field label="成员用户 ID">
              <Input
                value={userId}
                onChange={(event) => setUserId(event.target.value)}
                placeholder="十进制用户 ID"
              />
            </Field>
          </div>
          <div className="w-72">
            <Field label="操作">
              <Input
                value={operation}
                onChange={(event) => setOperation(event.target.value)}
                placeholder="organization.member.manage"
              />
            </Field>
          </div>
          <Button
            variant="secondary"
            loading={explain.isPending}
            disabled={!userId.trim() || !operation.trim()}
            onClick={() => void explain.mutateAsync()}
          >
            <Search className="h-3.5 w-3.5" />
            解释
          </Button>
        </div>

        {reply ? (
          <div className="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={reply.allowed ? 'success' : 'danger'}>
                {reply.allowed ? '允许' : '拒绝'}
              </Badge>
              <span className="font-mono text-slate-700">{reply.reason}</span>
              <span className="text-slate-400">{reply.context}</span>
            </div>
            <p className="text-slate-600">
              范围：{reply.scope || '—'} · 有效期：{reply.valid_until || '—'} ·
              policy revision：{reply.policy_revision || '—'}
            </p>
            {reply.missing?.length ? (
              <InlineAlert tone="warning">缺失项：{reply.missing.join('、')}</InlineAlert>
            ) : null}
            {sources.length ? (
              <ul className="space-y-1">
                {sources.map((source, index) => (
                  <li key={index} className="font-mono text-[11px] text-slate-600">
                    {source.effect} · {source.operation} · {source.role_code} ·
                    分配 {source.assignment_id} · 生效 {source.active ? '是' : '否'}
                    {source.expires_at ? ` · 至 ${source.expires_at}` : ''}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-500">没有命中本组织的角色授权。</p>
            )}
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}
