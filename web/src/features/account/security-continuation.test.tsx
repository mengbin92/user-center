import { act, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../../lib/api'
import { SecurityPage } from './security-page'

vi.mock('../../lib/auth', () => ({ useAuth: () => ({ user: null, getSessionGeneration: () => 0, refresh: vi.fn() }) }))
vi.mock('../../components/step-up', () => ({ useStepUp: () => ({ requestStepUp: vi.fn() }) }))
vi.mock('../../components/conflict', () => ({ useConflict: () => ({ showConflict: vi.fn() }) }))
vi.mock('../../components/toast', () => ({ useToast: () => ({ success: vi.fn(), error: vi.fn() }) }))
vi.mock('../../lib/api', () => ({ api: {
  auth: { context: vi.fn() },
  me: { security: vi.fn(), externalIdentities: vi.fn() },
} }))

beforeEach(() => {
  vi.mocked(api.auth.context).mockResolvedValue({ providers: [], password_min_length: 10 })
  vi.mocked(api.me.externalIdentities).mockResolvedValue({ items: [] })
  vi.mocked(api.me.security).mockResolvedValue({ password_available: true, password_change_required: true, mfa_required: true, mfa_enabled: false })
})

function mount(next: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/account/security?next=${encodeURIComponent(next)}`]}>
        <SecurityPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return client
}

describe('OIDC continuation after mandatory security setup', () => {
  it('offers a document link only after password and MFA requirements are satisfied', async () => {
    const next = '/oidc/authorize?client_id=example&state=opaque'
    const client = mount(next)
    expect(await screen.findByText('应用授权待继续')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '继续应用授权' })).not.toBeInTheDocument()
    act(() => client.setQueryData(['me', 'security'], { password_available: true, password_change_required: false, mfa_required: true, mfa_enabled: false }))
    expect(screen.queryByRole('link', { name: '继续应用授权' })).not.toBeInTheDocument()
    act(() => client.setQueryData(['me', 'security'], { password_available: true, password_change_required: false, mfa_required: true, mfa_enabled: true }))
    expect(await screen.findByRole('link', { name: '继续应用授权' })).toHaveAttribute('href', next)
  })

  it('does not offer an external continuation', () => {
    mount('//evil.example.com')
    expect(screen.queryByText('应用授权待继续')).not.toBeInTheDocument()
  })
})
