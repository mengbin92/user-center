import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Badge } from '../../components/badge'
import { api } from '../../lib/api'
import { formatScope, prettyJson } from '../../lib/format'
import type { Permission, Role } from '../../lib/types'

export function useAllRoles() {
  return useQuery({
    queryKey: ['admin', 'iam', 'roles', 'all'],
    queryFn: () => api.iam.listRoles(),
    staleTime: 30_000,
    retry: false,
  })
}

export function usePermissionCatalog() {
  return useQuery({
    queryKey: ['admin', 'iam', 'permissions', 'all'],
    queryFn: () => api.iam.listPermissions(),
    staleTime: 30_000,
    retry: false,
  })
}

export function roleById(roles: Role[] | undefined, id?: string): Role | undefined {
  return roles?.find((role) => role.id === id)
}

export function InfoGrid({
  items,
  className,
}: {
  items: Array<{ label: string; value: ReactNode; mono?: boolean }>
  className?: string
}) {
  return (
    <dl
      className={
        className ??
        'grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3'
      }
    >
      {items.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-[11px] text-slate-500">{item.label}</dt>
          <dd
            className={
              item.mono
                ? 'mt-0.5 truncate font-mono text-xs text-slate-800'
                : 'mt-0.5 truncate text-xs font-medium text-slate-800'
            }
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function JsonBlock({ value }: { value?: string | null }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-[10.5px] leading-5 text-slate-100">
      {prettyJson(value)}
    </pre>
  )
}

export function ScopeBadge({
  scope,
}: {
  scope?: { all?: boolean; self?: boolean; user_ids?: string[] } | null
}) {
  if (scope?.all) return <Badge tone="info">全部数据</Badge>
  if (scope?.self) return <Badge tone="violet">仅本人</Badge>
  if (scope?.user_ids?.length)
    return <Badge tone="warning">指定用户 {scope.user_ids.length}</Badge>
  return <Badge tone="neutral">未指定</Badge>
}

export function GrantScopeText({
  scope,
}: {
  scope?: { all?: boolean; self?: boolean; user_ids?: string[] } | null
}) {
  return <span className="text-[11px] text-slate-600">{formatScope(scope)}</span>
}

export function PermissionSelectOptions({
  permissions,
}: {
  permissions?: Permission[]
}) {
  const groups = new Map<string, Permission[]>()
  for (const permission of permissions ?? []) {
    const category = permission.category || '未分类'
    const list = groups.get(category) ?? []
    list.push(permission)
    groups.set(category, list)
  }
  return (
    <>
      {[...groups.entries()].map(([category, items]) => (
        <optgroup key={category} label={category}>
          {items.map((permission) => (
            <option key={permission.id} value={permission.code}>
              {permission.name} · {permission.code}
            </option>
          ))}
        </optgroup>
      ))}
    </>
  )
}
