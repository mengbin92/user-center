import {
  Laptop,
  LogOut,
  MonitorSmartphone,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  EmptyState,
} from '../../components/card'
import { ConfirmDialog } from '../../components/dialog'
import { QueryBoundary } from '../../components/query-state'
import {
  Pagination,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { SessionInfo } from '../../lib/types'

export function SessionsPage() {
  const { signOut } = useAuth()
  const [target, setTarget] = useState<SessionInfo | null>(null)
  const [revokeOthersOpen, setRevokeOthersOpen] = useState(false)

  const sessionsQuery = useQuery({
    queryKey: ['me', 'sessions'],
    queryFn: () => api.me.sessions(),
    retry: false,
  })

  const revokeSession = useApiMutation({
    mutationFn: (session: SessionInfo) =>
      api.me.revokeSession(session.id ?? ''),
    successMessage: '会话已撤销',
    invalidate: [['me', 'sessions']],
    refreshAuth: false,
    onSuccess: async (_data, session) => {
      setTarget(null)
      if (session.current) {
        await signOut()
      }
    },
  })

  const revokeOthers = useApiMutation({
    mutationFn: () => api.me.revokeOtherSessions(),
    successMessage: '其他会话已全部撤销',
    invalidate: [['me', 'sessions']],
    onSuccess: () => setRevokeOthersOpen(false),
  })

  const sessions = sessionsQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="会话管理" />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            会话管理
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            查看当前账号的有效登录会话，并撤销可疑设备。
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => void sessionsQuery.refetch()}
            loading={sessionsQuery.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
          <Button
            size="sm"
            variant="danger"
            onClick={() => setRevokeOthersOpen(true)}
            disabled={sessions.length <= 1}
            icon={<ShieldAlert className="h-3.5 w-3.5" />}
          >
            撤销其他会话
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader
          title="有效会话"
          description="当前会话撤销后会立即退出登录。"
          actions={
            <Badge tone="info">
              {sessions.length} 个有效会话
            </Badge>
          }
        />
        <QueryBoundary query={sessionsQuery} loadingLabel="读取会话…">
          {sessions.length === 0 ? (
            <CardContent>
              <EmptyState
                title="没有有效会话"
                description="如果这不是预期情况，请重新登录。"
                icon={MonitorSmartphone}
              />
            </CardContent>
          ) : (
            <>
              <Table minWidth="min-w-[860px]">
                <THead>
                  <TR>
                    <TH>设备</TH>
                    <TH>来源 IP</TH>
                    <TH>状态</TH>
                    <TH>签发时间</TH>
                    <TH>最近活跃</TH>
                    <TH>过期时间</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {sessions.map((session) => (
                    <TR key={session.id}>
                      <TD>
                        <div className="flex items-center gap-2">
                          <span className="grid h-7 w-7 place-items-center rounded-md bg-slate-100 text-slate-500">
                            <Laptop className="h-3.5 w-3.5" />
                          </span>
                          <div className="min-w-0">
                            <div className="max-w-[240px] truncate text-xs font-medium text-slate-800">
                              {session.device || '未知设备'}
                            </div>
                            <div className="text-[10px] text-slate-400">
                              {session.application_code || 'user-center'}
                            </div>
                          </div>
                        </div>
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-600">
                        {session.ip_masked || '—'}
                      </TD>
                      <TD>
                        {session.current ? (
                          <Badge tone="success" dot>
                            当前会话
                          </Badge>
                        ) : (
                          <Badge tone="neutral">其他设备</Badge>
                        )}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(session.issued_at)}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(session.last_seen_at)}
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(session.expires_at)}
                      </TD>
                      <TD className="text-right">
                        <Button
                          size="xs"
                          variant="ghost"
                          onClick={() => setTarget(session)}
                          icon={
                            session.current ? (
                              <LogOut className="h-3 w-3" />
                            ) : (
                              <ShieldAlert className="h-3 w-3" />
                            )
                          }
                        >
                          {session.current ? '退出' : '撤销'}
                        </Button>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <Pagination
                total={sessions.length}
                pageIndex={1}
                hasNext={false}
                onPrev={() => undefined}
                onNext={() => undefined}
              />
            </>
          )}
        </QueryBoundary>
      </Card>

      <ConfirmDialog
        open={target !== null}
        onClose={() => setTarget(null)}
        onConfirm={() => {
          if (target) revokeSession.mutate(target)
        }}
        title={target?.current ? '退出当前会话？' : '撤销该会话？'}
        description={
          target?.current
            ? '当前会话会立即失效，需要重新登录。'
            : '该设备需要重新登录才能继续访问。'
        }
        confirmLabel={target?.current ? '退出登录' : '撤销会话'}
        tone="danger"
        loading={revokeSession.isPending}
      >
        <div className="space-y-1 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs">
          <div>设备：{target?.device || '未知设备'}</div>
          <div className="font-mono text-[11px] text-slate-500">
            {target?.ip_masked || '—'} · {target?.id}
          </div>
        </div>
      </ConfirmDialog>

      <ConfirmDialog
        open={revokeOthersOpen}
        onClose={() => setRevokeOthersOpen(false)}
        onConfirm={() => revokeOthers.mutate(undefined)}
        title="撤销其他所有会话？"
        description="除当前设备外，其他设备上的登录会立即失效。"
        confirmLabel="全部撤销"
        tone="danger"
        loading={revokeOthers.isPending}
      />
    </div>
  )
}
