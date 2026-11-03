import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../../lib/api'
import { ToastProvider } from '../../components/toast'
import { SecurityPage } from './security-page'

vi.mock('../../lib/auth', () => ({ useAuth: () => ({ user: { id: '1', email_verified: true } }) }))
vi.mock('../../lib/security', () => ({ useSecurityStatus: () => ({ data: { password_available: false, mfa_enabled: false }, isSuccess: true, isPending: false, isError: false }) }))
vi.mock('../../lib/mutations', () => ({ useApiMutation: (options: { mutationFn: (...args: unknown[]) => unknown }) => ({ mutate: (...args: unknown[]) => options.mutationFn(...args), isPending: false, isError: false }) }))
vi.mock('../../lib/api', () => ({ api: {
  auth: { context: vi.fn() },
  me: { externalIdentities: vi.fn(), setupMfa: vi.fn() },
} }))

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.auth.context).mockResolvedValue({ providers: ['github', 'google'] })
  vi.mocked(api.me.externalIdentities).mockResolvedValue({ items: [{ id: '1', provider: 'github' }] })
  vi.mocked(api.me.setupMfa).mockResolvedValue({})
})

describe('OAuth-only security setup', () => {
  it('offers verification only for bound identities and permits MFA setup without an invented password', async () => {
    render(<QueryClientProvider client={new QueryClient()}><ToastProvider><MemoryRouter><SecurityPage /></MemoryRouter></ToastProvider></QueryClientProvider>)
    expect(await screen.findByText('重新验证 GitHub')).toHaveAttribute('href', '/api/v1/auth/providers/github/start?mode=verify')
    expect(screen.queryByText('重新验证 Google')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('当前密码')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '启用 MFA' }))
    fireEvent.click(screen.getByRole('button', { name: '生成密钥' }))
    await waitFor(() => expect(api.me.setupMfa).toHaveBeenCalledWith({ current_password: '' }))
  })
})
