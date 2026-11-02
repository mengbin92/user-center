import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'

import { Can } from '../components/can'
import { RequirePermission } from '../app/guards'
import { AuthContext, type AuthContextValue } from '../lib/auth'
import {
  buildMenuKeySet,
  buildPermissionSet,
  canAccessMenu,
  hasPermission,
} from '../lib/permissions'

function authValue(permissions: Parameters<typeof buildPermissionSet>[0]): AuthContextValue {
  const permissionSet = buildPermissionSet(permissions)
  return {
    status: 'authenticated',
    user: null,
    authorization: null,
    permissions: permissionSet,
    menuKeys: buildMenuKeySet(['account', 'admin']),
    can: (operation) => hasPermission(permissionSet, operation),
    canAny: (operations) => operations.some((operation) => permissionSet.has(operation)),
    hasAdmin: true,
    bootError: null,
    refresh: async () => undefined,
    signIn: async () => undefined,
    signOut: async () => undefined,
  }
}

describe('permission gating', () => {
  it('renders children only for an allowed operation', () => {
    const value = authValue([
      { operation: 'identity.user.list', effect: 'allow', scope: 'all' },
    ])
    render(
      <AuthContext.Provider value={value}>
        <Can permission="identity.user.list">
          <span>用户管理内容</span>
        </Can>
        <Can permission="iam.role.read">
          <span>角色管理内容</span>
        </Can>
      </AuthContext.Provider>,
    )

    expect(screen.getByText('用户管理内容')).toBeInTheDocument()
    expect(screen.queryByText('角色管理内容')).not.toBeInTheDocument()
  })

  it('treats deny as no permission and supports menu-key visibility', () => {
    const permissionSet = buildPermissionSet([
      { operation: 'identity.user.list', effect: 'deny', scope: 'all' },
      { operation: 'audit.read', effect: 'allow', scope: 'all' },
    ])

    expect(permissionSet.has('identity.user.list')).toBe(false)
    expect(permissionSet.has('audit.read')).toBe(true)
    expect(
      canAccessMenu(
        { menuKey: 'admin/users', anyOf: ['identity.user.list'] },
        {
          permissions: permissionSet,
          menuKeys: buildMenuKeySet(['admin', 'admin/users']),
        },
      ),
    ).toBe(true)
  })

  it('shows the fallback when no permission matches', () => {
    const value = authValue([])
    render(
      <AuthContext.Provider value={value}>
        <Can permission="identity.user.create" fallback={<span>无权限提示</span>}>
          <span>创建表单</span>
        </Can>
      </AuthContext.Provider>,
    )

    expect(screen.getByText('无权限提示')).toBeInTheDocument()
    expect(screen.queryByText('创建表单')).not.toBeInTheDocument()
  })

  it('blocks the delegations page without iam.delegation.read', () => {
    const value = authValue([
      { operation: 'audit.read', effect: 'allow', scope: 'all' },
    ])
    render(
      <MemoryRouter>
        <AuthContext.Provider value={value}>
          <RequirePermission permission="iam.delegation.read">
            <span>委派管理内容</span>
          </RequirePermission>
        </AuthContext.Provider>
      </MemoryRouter>,
    )

    expect(screen.queryByText('委派管理内容')).not.toBeInTheDocument()
    expect(
      screen.getByText('需要权限：iam.delegation.read'),
    ).toBeInTheDocument()
  })

  it('supports the admin/iam/delegations menu key even without a permission projection', () => {
    expect(
      canAccessMenu(
        { menuKey: 'admin/iam/delegations' },
        {
          permissions: buildPermissionSet([]),
          menuKeys: buildMenuKeySet(['admin/iam/delegations']),
        },
      ),
    ).toBe(true)
  })
})
