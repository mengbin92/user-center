import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { RequirePermission } from '../../app/guards'
import { ToastProvider } from '../../components/toast'
import {
  AuthContext,
  type AuthContextValue,
} from '../../lib/auth'
import {
  buildMenuKeySet,
  buildPermissionSet,
  canAccessMenu,
  hasPermission,
} from '../../lib/permissions'
import type { PermissionSummary } from '../../lib/types'
import { ClientSecretDialog } from './applications-page'

function authValue(
  permissions: PermissionSummary[],
  menuKeys: string[] = ['account', 'admin', 'admin/applications'],
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
    hasAdmin: true,
    bootError: null,
    refresh: async () => undefined,
    signIn: async () => undefined,
    signOut: async () => undefined,
  }
}

function renderSecretDialog(
  credential: Parameters<typeof ClientSecretDialog>[0]['credential'],
  onClose = vi.fn(),
) {
  return render(
    <ToastProvider>
      <ClientSecretDialog credential={credential} onClose={onClose} />
    </ToastProvider>,
  )
}

beforeEach(() => {
  window.localStorage.clear()
  window.sessionStorage.clear()
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  })
})

describe('OIDC applications admin page', () => {
  it('shows the client secret exactly once and never writes it to storage', async () => {
    const onClose = vi.fn()
    const { rerender } = renderSecretDialog(
      {
        client: {
          id: '42',
          client_id: 'oidc_abc',
          name: '计费控制台',
          revision: '3',
        },
        client_secret: 'uc_once_secret_value',
      },
      onClose,
    )

    expect(screen.getByText('请立即保存客户端密钥')).toBeInTheDocument()
    expect(screen.getAllByText('uc_once_secret_value')).toHaveLength(1)
    expect(window.localStorage).toHaveLength(0)
    expect(window.sessionStorage).toHaveLength(0)

    fireEvent.click(
      screen.getByRole('button', { name: '复制客户端密钥' }),
    )
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        'uc_once_secret_value',
      ),
    )

    rerender(
      <ToastProvider>
        <ClientSecretDialog credential={null} onClose={onClose} />
      </ToastProvider>,
    )
    expect(screen.queryByText('uc_once_secret_value')).not.toBeInTheDocument()
    expect(window.localStorage).toHaveLength(0)
    expect(window.sessionStorage).toHaveLength(0)
  })

  it('gates the applications route and nav entry on oidc.client.read', () => {
    const { rerender } = render(
      <MemoryRouter>
        <AuthContext.Provider value={authValue([])}>
          <RequirePermission permission="oidc.client.read">
            <span>OIDC 应用内容</span>
          </RequirePermission>
        </AuthContext.Provider>
      </MemoryRouter>,
    )
    expect(screen.queryByText('OIDC 应用内容')).not.toBeInTheDocument()
    expect(
      screen.getByText('需要权限：oidc.client.read'),
    ).toBeInTheDocument()

    rerender(
      <MemoryRouter>
        <AuthContext.Provider
          value={authValue([
            { operation: 'oidc.client.read', effect: 'allow', scope: 'all' },
          ])}
        >
          <RequirePermission permission="oidc.client.read">
            <span>OIDC 应用内容</span>
          </RequirePermission>
        </AuthContext.Provider>
      </MemoryRouter>,
    )
    expect(screen.getByText('OIDC 应用内容')).toBeInTheDocument()

    expect(
      canAccessMenu(
        { menuKey: 'admin/applications', anyOf: ['oidc.client.read'] },
        {
          permissions: buildPermissionSet([]),
          menuKeys: buildMenuKeySet(['admin/applications']),
        },
      ),
    ).toBe(true)
    expect(
      canAccessMenu(
        { menuKey: 'admin/applications', anyOf: ['oidc.client.read'] },
        {
          permissions: buildPermissionSet([]),
          menuKeys: buildMenuKeySet([]),
        },
      ),
    ).toBe(false)
  })
})
