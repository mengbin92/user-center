import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../../app/router'
import { ConflictProvider } from '../../components/conflict'
import { StepUpProvider } from '../../components/step-up'
import { ToastProvider } from '../../components/toast'
import { api } from '../../lib/api'
import { AuthContext, type AuthContextValue } from '../../lib/auth'
import {
  buildMenuKeySet,
  buildPermissionSet,
  canAccessMenu,
  hasAdminAccess,
  hasPermission,
} from '../../lib/permissions'
import {
  canArchiveOrganization,
  canEditMember,
  canGrantRole,
  canRemoveMember,
} from './org-utils'

vi.mock('../../lib/api', () => ({
  api: {
    me: { security: vi.fn() },
    admin: { listOrganizations: vi.fn() },
    orgs: { listMine: vi.fn() },
  },
}))

function authValue(
  permissions: Parameters<typeof buildPermissionSet>[0],
  menuKeys: string[] = [],
): AuthContextValue {
  const permissionSet = buildPermissionSet(permissions)
  return {
    status: 'authenticated',
    sessionGeneration: 0,
    getSessionGeneration: () => 0,
    user: null,
    authorization: null,
    permissions: permissionSet,
    menuKeys: buildMenuKeySet(menuKeys),
    can: (operation) => hasPermission(permissionSet, operation),
    canAny: (operations) =>
      operations.some((operation) => permissionSet.has(operation)),
    hasAdmin: hasAdminAccess(permissionSet),
    bootError: null,
    refresh: async () => undefined,
    signIn: async () => undefined,
    signOut: async () => undefined,
  }
}

function renderRoute(value: AuthContextValue, path: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <AuthContext.Provider value={value}>
          <StepUpProvider>
            <ConflictProvider>
              <MemoryRouter initialEntries={[path]}>
                <AppRoutes />
              </MemoryRouter>
            </ConflictProvider>
          </StepUpProvider>
        </AuthContext.Provider>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

function renderAdminOrganizations(value: AuthContextValue) {
  return renderRoute(value, '/admin/organizations')
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.me.security).mockResolvedValue({})
  vi.mocked(api.admin.listOrganizations).mockResolvedValue({ items: [] })
  vi.mocked(api.orgs.listMine).mockResolvedValue({ items: [] })
})

describe('organization route and permission gating', () => {
  it('blocks /admin/organizations without organization.admin.read', async () => {
    renderAdminOrganizations(
      authValue([
        { operation: 'identity.user.list', effect: 'allow', scope: 'all' },
      ]),
    )

    expect(await screen.findByText('无权访问此页面')).toBeInTheDocument()
    expect(
      screen.getByText('需要权限：organization.admin.read'),
    ).toBeInTheDocument()
    expect(api.admin.listOrganizations).not.toHaveBeenCalled()
  })

  it('renders /admin/organizations with organization.admin.read', async () => {
    renderAdminOrganizations(
      authValue([
        {
          operation: 'organization.admin.read',
          effect: 'allow',
          scope: 'all',
        },
      ]),
    )

    expect(await screen.findByText('没有匹配的组织')).toBeInTheDocument()
    expect(api.admin.listOrganizations).toHaveBeenCalled()
  })

  it('treats organization.admin.read as admin access and honors its menu key', () => {
    const permissionSet = buildPermissionSet([
      {
        operation: 'organization.admin.read',
        effect: 'allow',
        scope: 'all',
      },
    ])
    expect(hasAdminAccess(permissionSet)).toBe(true)
    expect(
      canAccessMenu(
        {
          menuKey: 'admin/organizations',
          anyOf: ['organization.admin.read'],
        },
        {
          permissions: buildPermissionSet([]),
          menuKeys: buildMenuKeySet(['admin/organizations']),
        },
      ),
    ).toBe(true)
  })

  it('renders /orgs for any authenticated user without admin permissions', async () => {
    renderRoute(authValue([]), '/orgs')

    expect(await screen.findByText('我的组织')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: '切换组织' }),
    ).toBeInTheDocument()
    expect(api.orgs.listMine).toHaveBeenCalled()
  })
})

describe('organization member role UI rules', () => {
  it('lets admins edit plain members but never owners or other admins', () => {
    expect(canEditMember('admin', 'member')).toBe(true)
    expect(canEditMember('admin', 'admin')).toBe(false)
    expect(canEditMember('admin', 'owner')).toBe(false)
    expect(canEditMember('owner', 'owner')).toBe(true)
    expect(canEditMember('platform', 'admin')).toBe(true)
    expect(canRemoveMember('admin', 'member')).toBe(true)
    expect(canRemoveMember('admin', 'admin')).toBe(false)
  })

  it('only lets owners/platform grant the owner role', () => {
    expect(canGrantRole('admin', 'owner')).toBe(false)
    expect(canGrantRole('admin', 'admin')).toBe(true)
    expect(canGrantRole('owner', 'owner')).toBe(true)
    expect(canGrantRole('platform', 'owner')).toBe(true)
    expect(canGrantRole('member', 'member')).toBe(false)
  })

  it('only shows archive to owner/platform', () => {
    expect(canArchiveOrganization('owner')).toBe(true)
    expect(canArchiveOrganization('platform')).toBe(true)
    expect(canArchiveOrganization('admin')).toBe(false)
    expect(canArchiveOrganization('member')).toBe(false)
  })
})
