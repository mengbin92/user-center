import type { Department, Organization } from '../../lib/types'

export type OrganizationRole = 'owner' | 'admin' | 'member' | 'platform'

export const ORGANIZATION_ROLE_LABELS: Record<string, string> = {
  owner: '拥有者',
  admin: '管理员',
  member: '成员',
  platform: '平台管理员',
}

export function organizationRoleLabel(role?: string | null): string {
  if (!role) return '—'
  return ORGANIZATION_ROLE_LABELS[role] ?? role
}

export function organizationStatusLabel(status?: string | null): string {
  if (status === 'active') return '运行中'
  if (status === 'archived') return '已归档'
  return status || '—'
}

/**
 * Platform administrators see every organization with role "platform"; they
 * act as owner for UI visibility purposes. The server remains authoritative.
 */
export function isOrganizationOwnerLike(role?: string | null): boolean {
  return role === 'owner' || role === 'platform'
}

export function isOrganizationManager(role?: string | null): boolean {
  return role === 'owner' || role === 'admin' || role === 'platform'
}

export function canArchiveOrganization(role?: string | null): boolean {
  return isOrganizationOwnerLike(role)
}

export function canLeaveOrganization(role?: string | null): boolean {
  return role === 'owner' || role === 'admin' || role === 'member'
}

export function canManageDepartments(role?: string | null): boolean {
  return isOrganizationManager(role)
}

/**
 * Admin members may only touch plain members: the server rejects edits to
 * owners/admins, and they may never grant the owner role. Owner/platform may
 * edit anyone.
 */
export function canEditMember(
  actorRole?: string | null,
  targetRole?: string | null,
): boolean {
  if (!isOrganizationManager(actorRole)) return false
  if (isOrganizationOwnerLike(actorRole)) return true
  return targetRole === 'member'
}

export function canRemoveMember(
  actorRole?: string | null,
  targetRole?: string | null,
): boolean {
  return canEditMember(actorRole, targetRole)
}

export function canGrantRole(
  actorRole?: string | null,
  role?: string | null,
): boolean {
  if (!isOrganizationManager(actorRole)) return false
  if (isOrganizationOwnerLike(actorRole)) {
    return role === 'owner' || role === 'admin' || role === 'member'
  }
  return role === 'admin' || role === 'member'
}

export function grantableRoles(actorRole?: string | null): OrganizationRole[] {
  if (!isOrganizationManager(actorRole)) return []
  if (isOrganizationOwnerLike(actorRole)) return ['owner', 'admin', 'member']
  return ['admin', 'member']
}

export function organizationIsActive(org?: Organization | null): boolean {
  return org?.status !== 'archived'
}

export function organizationIdFromPath(pathname: string): string | null {
  const match = /^\/orgs\/([^/]+)\/?$/.exec(pathname)
  if (!match) return null
  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

export type DepartmentRow = {
  department: Department
  depth: number
}

/** Flattens a department forest into stable, parent-before-child rows. */
export function departmentRows(items: Department[]): DepartmentRow[] {
  const ids = new Set(items.map((item) => item.id).filter(Boolean) as string[])
  const children = new Map<string, Department[]>()
  const roots: Department[] = []
  for (const item of items) {
    const parent = item.parent_id || ''
    if (!parent || !ids.has(parent)) {
      roots.push(item)
      continue
    }
    const list = children.get(parent) ?? []
    list.push(item)
    children.set(parent, list)
  }

  const rows: DepartmentRow[] = []
  const visited = new Set<string>()
  const walk = (item: Department, depth: number) => {
    const id = item.id ?? ''
    if (id && visited.has(id)) return
    if (id) visited.add(id)
    rows.push({ department: item, depth })
    for (const child of children.get(id) ?? []) walk(child, depth + 1)
  }
  for (const root of roots) walk(root, 0)
  // Defensive: expose departments trapped in a cycle rather than hiding them.
  for (const item of items) {
    if (!item.id || !visited.has(item.id)) walk(item, 0)
  }
  return rows
}

export function departmentName(
  departments: Department[] | undefined,
  id?: string | null,
): string {
  // The API serializes a missing parent as "0".
  if (!id || id === '0') return '—'
  return departments?.find((item) => item.id === id)?.name || `#${id}`
}
