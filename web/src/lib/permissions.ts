import type { PermissionSummary } from './types'

export type AccessState = {
  permissions: Set<string>
  menuKeys: Set<string>
}

export type MenuAccessRule = {
  menuKey?: string
  anyOf?: string[]
}

export function buildPermissionSet(
  permissions?: PermissionSummary[] | null,
): Set<string> {
  const set = new Set<string>()
  for (const permission of permissions ?? []) {
    if (!permission.operation) continue
    if (permission.effect !== 'allow') continue
    set.add(permission.operation)
  }
  return set
}

export function buildMenuKeySet(keys?: string[] | null): Set<string> {
  return new Set((keys ?? []).filter(Boolean))
}

export function hasPermission(
  permissions: Set<string>,
  operation: string,
): boolean {
  if (!operation) return true
  return permissions.has(operation)
}

export function hasAnyPermission(
  permissions: Set<string>,
  operations: string[],
): boolean {
  if (operations.length === 0) return true
  return operations.some((operation) => permissions.has(operation))
}

export function canAccessMenu(
  rule: MenuAccessRule,
  access: AccessState,
): boolean {
  if (rule.menuKey && access.menuKeys.has(rule.menuKey)) return true
  if (rule.anyOf && rule.anyOf.length > 0) {
    return rule.anyOf.some((operation) => access.permissions.has(operation))
  }
  return false
}

export const ADMIN_PERMISSIONS = [
  'identity.user.list',
  'identity.user.read',
  'identity.user.export',
  'iam.role.read',
  'iam.permission.read',
  'iam.assignment.read',
  'iam.delegation.read',
  'iam.constraint.read',
  'iam.menu.read',
  'iam.authorization.explain',
  'audit.read',
  'audit.export',
  'settings.auth.read',
  'settings.email.read',
  'integration.client.read',
  'integration.delivery.read',
  'oidc.client.read',
  'organization.admin.read',
]

export function hasAdminAccess(permissions: Set<string>): boolean {
  return ADMIN_PERMISSIONS.some((operation) => permissions.has(operation))
}
