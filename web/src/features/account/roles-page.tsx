import { KeyRound, RefreshCw, Save } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
} from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { useApiMutation } from '../../lib/mutations'

export function SessionRolesPage() {
  const { refresh } = useAuth()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [revision, setRevision] = useState<string | null>(null)

  const rolesQuery = useQuery({
    queryKey: ['me', 'session-roles'],
    queryFn: () => api.me.sessionRoles(),
    retry: false,
  })

  const roles = rolesQuery.data?.items ?? []

  useEffect(() => {
    if (!rolesQuery.data) return
    setSelected(
      new Set(
        (rolesQuery.data.items ?? [])
          .filter((role) => role.active)
          .map((role) => role.id ?? ''),
      ),
    )
    setRevision(rolesQuery.data.revision ?? null)
  }, [rolesQuery.data])

  const initialActive = useMemo(
    () =>
      new Set(
        roles.filter((role) => role.active).map((role) => role.id ?? ''),
      ),
    [roles],
  )

  const dirty =
    selected.size !== initialActive.size ||
    [...selected].some((id) => !initialActive.has(id))

  const saveRoles = useApiMutation({
    mutationFn: () =>
      api.me.putSessionRoles({
        role_ids: [...selected],
        expected_revision: revision ?? '',
      }),
    successMessage: '会话角色已切换',
    successDescription: '当前会话的权限投影已按新角色重新计算。',
    invalidate: [['me', 'session-roles']],
    refreshAuth: true,
  })

  const toggle = (id: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      <PageTitle title="会话角色" />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            会话角色
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            选择当前会话启用的角色。该操作只影响本会话，不改变长期授权分配。
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => void rolesQuery.refetch()}
            loading={rolesQuery.isFetching}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新
          </Button>
          <Button
            size="sm"
            variant="primary"
            onClick={() => saveRoles.mutate(undefined)}
            loading={saveRoles.isPending}
            disabled={!dirty || !revision}
            icon={<Save className="h-3.5 w-3.5" />}
          >
            保存切换
          </Button>
        </div>
      </div>

      <InlineAlert tone="info" title="最小权限原则">
        只启用当前任务需要的角色。注销或重新登录后，会话角色会恢复为服务端默认选择。
      </InlineAlert>

      <Card>
        <CardHeader
          title="可切换角色"
          description="仅显示已分配且处于启用状态的角色。"
          actions={
            <div className="flex gap-1">
              <Button
                size="xs"
                variant="ghost"
                onClick={() =>
                  setSelected(new Set(roles.map((role) => role.id ?? '')))
                }
              >
                全选
              </Button>
              <Button
                size="xs"
                variant="ghost"
                onClick={() => setSelected(new Set())}
              >
                清空
              </Button>
            </div>
          }
        />
        <QueryBoundary query={rolesQuery} loadingLabel="读取会话角色…">
          {roles.length === 0 ? (
            <CardContent>
              <div className="py-6 text-center text-xs text-slate-500">
                当前账号没有可切换的角色。
              </div>
            </CardContent>
          ) : (
            <CardContent className="space-y-2">
              {roles.map((role) => {
                const id = role.id ?? ''
                const checked = selected.has(id)
                return (
                  <label
                    key={id}
                    className="flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-200 px-3 py-2.5 hover:bg-slate-50"
                  >
                    <div className="flex items-center gap-2.5">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-slate-300 accent-indigo-600"
                        checked={checked}
                        onChange={() => toggle(id)}
                      />
                      <span className="grid h-8 w-8 place-items-center rounded-md bg-indigo-50 text-indigo-600">
                        <KeyRound className="h-4 w-4" />
                      </span>
                      <span>
                        <span className="flex items-center gap-1.5 text-xs font-medium text-slate-800">
                          {role.name || role.code}
                          {role.builtin ? (
                            <Badge tone="neutral">内置</Badge>
                          ) : null}
                        </span>
                        <span className="block font-mono text-[10px] text-slate-500">
                          {role.code} · id={id}
                        </span>
                      </span>
                    </div>
                    {role.active ? (
                      <Badge tone="success" dot>
                        当前启用
                      </Badge>
                    ) : (
                      <Badge tone="outline">未启用</Badge>
                    )}
                  </label>
                )
              })}
            </CardContent>
          )}
        </QueryBoundary>
      </Card>

      {selected.size === 0 ? (
        <InlineAlert tone="warning" title="未选择任何角色">
          保存后当前会话将没有任何角色，管理端与受限功能会立即不可用。请确认这是预期操作。
        </InlineAlert>
      ) : null}

      <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-[11px] text-slate-500">
        <span>
          已选择 {selected.size} / {roles.length} 个角色 · 会话 revision{' '}
          <span className="font-mono">{revision ?? '—'}</span>
        </span>
        <Button
          size="xs"
          variant="ghost"
          onClick={() => void refresh(true)}
          title="重新拉取权限投影"
        >
          刷新权限投影
        </Button>
      </div>
    </div>
  )
}
