import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { RequirePermission } from '../../app/guards'
import { ConflictProvider } from '../../components/conflict'
import { StepUpProvider } from '../../components/step-up'
import { ToastProvider } from '../../components/toast'
import { api } from '../../lib/api'
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
import type { OIDCClient, PermissionSummary } from '../../lib/types'
import { AdminApplicationsPage, ClientSecretDialog } from './applications-page'

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
    authorization: { policy_revision: '9007199254740993' },
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
  vi.restoreAllMocks()
  window.localStorage.clear()
  window.sessionStorage.clear()
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  })
})

const client: OIDCClient = {
  id: '42', client_id: 'oidc_abc', name: '计费控制台', service_owner: 'billing',
  revision: '9007199254740995', status: 'active', public: false, require_pkce: true,
  redirect_uris: ['https://app.example.com/callback?values=a,b'], scopes: ['openid'],
  post_logout_redirect_uris: ['https://app.example.com/logged-out'],
  access_token_ttl_seconds: 900, refresh_token_ttl_seconds: 86400,
}
const permissions: PermissionSummary[] = [
  { operation: 'oidc.client.read', effect: 'allow', scope: 'all' },
  { operation: 'oidc.client.update', effect: 'allow', scope: 'all' },
]

function renderPage() {
  vi.spyOn(api.oidc, 'listClients').mockResolvedValue({ items: [client] })
  vi.spyOn(api.oidc, 'discovery').mockResolvedValue({
    issuer: 'https://identity.example.com',
    authorization_endpoint: 'https://identity.example.com/oidc/authorize',
    token_endpoint: 'https://identity.example.com/oidc/token',
    userinfo_endpoint: 'https://identity.example.com/oidc/userinfo',
    jwks_uri: 'https://identity.example.com/oidc/jwks',
  })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = (auth = authValue(permissions)) => (
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <AuthContext.Provider value={auth}>
          <ToastProvider><ConflictProvider><StepUpProvider>
            <AdminApplicationsPage />
          </StepUpProvider></ConflictProvider></ToastProvider>
        </AuthContext.Provider>
      </QueryClientProvider>
    </MemoryRouter>
  )
  return { ...render(view()), queryClient, view }
}

describe('OIDC management preconditions and secret lifetime', () => {
  it('preserves registered URI commas and includes the policy revision on create', async () => {
    const create = vi.spyOn(api.oidc, 'createClient').mockResolvedValue({ client, client_secret: 'once_create' })
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))
    const dialog = screen.getByRole('dialog', { name: '创建 OIDC 应用' })
    fireEvent.change(within(dialog).getByLabelText(/名称/), { target: { value: '新应用' } })
    fireEvent.change(within(dialog).getByLabelText(/服务归属/), { target: { value: 'billing' } })
    fireEvent.change(within(dialog).getByLabelText(/重定向 URI/), { target: { value: 'https://app.example.com/callback?values=a,b' } })
    fireEvent.change(within(dialog).getByLabelText(/登出回调 URI/), { target: { value: 'https://app.example.com/logged-out' } })
    fireEvent.change(within(dialog).getByLabelText(/操作原因/), { target: { value: '按工单接入' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '创建应用' }))
    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
      expected_policy_revision: '9007199254740993',
      redirect_uris: ['https://app.example.com/callback?values=a,b'],
      post_logout_redirect_uris: ['https://app.example.com/logged-out'],
    })))
  })

  it('edits the name while keeping the client type immutable and sends both revisions', async () => {
    const update = vi.spyOn(api.oidc, 'updateClient').mockResolvedValue(client)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = screen.getByRole('dialog', { name: '更新 OIDC 应用' })
    const name = within(dialog).getByLabelText(/名称/)
    expect(name).toBeEnabled()
    expect(within(dialog).queryByRole('switch')).not.toBeInTheDocument()
    expect(within(dialog).getByText('机密客户端')).toBeInTheDocument()
    fireEvent.change(name, { target: { value: '新名称' } })
    fireEvent.change(within(dialog).getByLabelText(/操作原因/), { target: { value: '按工单更新' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '保存更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith('42', expect.objectContaining({
      name: '新名称', expected_revision: '9007199254740995',
      expected_policy_revision: '9007199254740993',
      redirect_uris: ['https://app.example.com/callback?values=a,b'],
      post_logout_redirect_uris: ['https://app.example.com/logged-out'],
    })))
  })

  it('sends revisions when rotating and removes the once-only secret from the mutation cache', async () => {
    const rotate = vi.spyOn(api.oidc, 'rotateSecret').mockResolvedValue({ client, client_secret: 'once_rotate' })
    const { queryClient } = renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '轮换密钥' }))
    const dialog = screen.getByRole('dialog', { name: '轮换客户端密钥' })
    fireEvent.change(within(dialog).getByLabelText(/操作原因/), { target: { value: '定期轮换' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认轮换' }))
    await waitFor(() => expect(rotate).toHaveBeenCalledWith('42', {
      id: '42', reason: '定期轮换', expected_revision: '9007199254740995',
      expected_policy_revision: '9007199254740993',
    }))
    expect(await screen.findByText('once_rotate')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '我已保存' }))
    await waitFor(() => expect(queryClient.getMutationCache().getAll().every((mutation) =>
      !JSON.stringify(mutation.state.data ?? null).includes('once_rotate'),
    )).toBe(true))
  })

  it('sends revisions when disabling a client', async () => {
    const disable = vi.spyOn(api.oidc, 'disableClient').mockResolvedValue({ ...client, status: 'disabled' })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '停用' }))
    const dialog = screen.getByRole('dialog', { name: '停用 OIDC 应用' })
    fireEvent.change(within(dialog).getByLabelText(/操作原因/), { target: { value: '应用下线' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认停用' }))
    await waitFor(() => expect(disable).toHaveBeenCalledWith('42', {
      id: '42', reason: '应用下线', expected_revision: '9007199254740995',
      expected_policy_revision: '9007199254740993',
    }))
  })

  it('discards a displayed secret when write authority is removed', async () => {
    vi.spyOn(api.oidc, 'rotateSecret').mockResolvedValue({ client, client_secret: 'old_authority_secret' })
    const { rerender, view } = renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '轮换密钥' }))
    const dialog = screen.getByRole('dialog', { name: '轮换客户端密钥' })
    fireEvent.change(within(dialog).getByLabelText(/操作原因/), { target: { value: '定期轮换' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认轮换' }))
    expect(await screen.findByText('old_authority_secret')).toBeInTheDocument()
    rerender(view(authValue(permissions.slice(0, 1))))
    await waitFor(() => expect(screen.queryByText('old_authority_secret')).not.toBeInTheDocument())
  })
})

describe('OIDC applications admin page', () => {
  it('does not ask a public client to save a nonexistent secret', () => {
    renderSecretDialog({ client: { public: true, name: '公开应用', client_id: 'oidc_public' } })
    expect(screen.getByRole('dialog', { name: '公开应用已创建' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '复制客户端密钥' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '完成' })).toBeInTheDocument()
  })

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
