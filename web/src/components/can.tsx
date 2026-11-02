import type { ReactNode } from 'react'

import { useAuth } from '../lib/auth'

export function Can({
  permission,
  anyOf,
  fallback = null,
  children,
}: {
  permission?: string
  anyOf?: string[]
  fallback?: ReactNode
  children: ReactNode
}) {
  const { can, canAny } = useAuth()
  const allowed = permission
    ? can(permission)
    : anyOf
      ? canAny(anyOf)
      : true
  return <>{allowed ? children : fallback}</>
}
