import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ToastProvider } from '../../components/toast'
import { LoginPage } from './login-page'

const signIn = vi.fn().mockResolvedValue(undefined)
const beginPasskeyLogin = vi.fn()
const completePasskeyLogin = vi.fn()
const getLoginAssertion = vi.fn()

vi.mock('../../lib/auth', () => ({
  useAuth: () => ({ status: 'unauthenticated', hasAdmin: false, signIn }),
}))
vi.mock('../../lib/api', () => ({
  api: {
    auth: {
      context: async () => ({ providers: [] }),
      login: vi.fn(),
      completeMfa: vi.fn(),
      beginPasskeyLogin: (...args: unknown[]) => beginPasskeyLogin(...args),
      completePasskeyLogin: (...args: unknown[]) => completePasskeyLogin(...args),
    },
  },
}))
vi.mock('../../lib/webauthn', () => ({
  passkeySupported: () => true,
  getLoginAssertion: (...args: unknown[]) => getLoginAssertion(...args),
}))

function mount() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/account" element={<span>账号中心</span>} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.clearAllMocks()
})

// Passwordless passkey login replaces username + password with one assertion.
// The MFA-pending reply must move to the TOTP screen without minting a session,
// and the browser-side assertion is bound to the server-issued ceremony.
describe('passkey passwordless login', () => {
  it('signs in with an assertion', async () => {
    beginPasskeyLogin.mockResolvedValue({
      challenge_id: 'c1',
      challenge: 'challenge-1',
      rp_id: 'localhost',
      allow_credential_ids: ['cred-1'],
      expires_at: '2026-11-13T02:00:00Z',
    })
    getLoginAssertion.mockResolvedValue({
      challenge_id: 'c1',
      credential_id: 'cred-1',
      authenticator_data: 'auth-data',
      client_data_json: 'client-data',
      signature: 'signature',
    })
    completePasskeyLogin.mockResolvedValue({ status: 'authenticated' })
    mount()

    fireEvent.change(screen.getByLabelText(/用户名或邮箱/), {
      target: { value: 'alice' },
    })
    fireEvent.click(screen.getByRole('button', { name: /使用通行密钥/ }))

    await waitFor(() =>
      expect(beginPasskeyLogin).toHaveBeenCalledWith({ username: 'alice' }),
    )
    await waitFor(() =>
      expect(getLoginAssertion).toHaveBeenCalledWith(
        'challenge-1',
        'localhost',
        ['cred-1'],
        'c1',
      ),
    )
    await waitFor(() =>
      expect(completePasskeyLogin).toHaveBeenCalledWith(
        expect.objectContaining({
          challenge_id: 'c1',
          credential_id: 'cred-1',
          remember: false,
        }),
      ),
    )
    await waitFor(() => expect(signIn).toHaveBeenCalledTimes(1))
  })

  it('moves to the TOTP step without a session when MFA is still owed', async () => {
    beginPasskeyLogin.mockResolvedValue({
      challenge_id: 'c2',
      challenge: 'challenge-2',
      rp_id: 'localhost',
      allow_credential_ids: ['cred-1'],
    })
    getLoginAssertion.mockResolvedValue({
      challenge_id: 'c2',
      credential_id: 'cred-1',
      authenticator_data: 'auth-data',
      client_data_json: 'client-data',
      signature: 'signature',
    })
    completePasskeyLogin.mockResolvedValue({
      status: 'mfa_required',
      challenge_id: 'mfa-1',
      challenge_expires_at: '2026-11-13T02:00:00Z',
    })
    mount()

    fireEvent.change(screen.getByLabelText(/用户名或邮箱/), {
      target: { value: 'alice' },
    })
    fireEvent.click(screen.getByRole('button', { name: /使用通行密钥/ }))

    expect(
      await screen.findByLabelText(/动态验证码或恢复码/),
    ).toBeInTheDocument()
    expect(signIn).not.toHaveBeenCalled()
  })

  it('requires an identifier before starting the ceremony', async () => {
    mount()

    fireEvent.click(screen.getByRole('button', { name: /使用通行密钥/ }))

    expect(
      await screen.findByText(/请先输入用户名或邮箱/),
    ).toBeInTheDocument()
    expect(beginPasskeyLogin).not.toHaveBeenCalled()
  })
})
