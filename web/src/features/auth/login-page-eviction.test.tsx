import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ToastProvider } from '../../components/toast'
import { LoginPage } from './login-page'

const signIn = vi.fn().mockResolvedValue(undefined)
const login = vi.fn()
const completeMfa = vi.fn()

vi.mock('../../lib/auth', () => ({
  useAuth: () => ({ status: 'unauthenticated', hasAdmin: false, signIn }),
}))
vi.mock('../../lib/api', () => ({
  api: {
    auth: {
      context: async () => ({ providers: [] }),
      login: (...args: unknown[]) => login(...args),
      completeMfa: (...args: unknown[]) => completeMfa(...args),
    },
  },
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

// The session cap reclaims older sessions on every issuance path. The toast used
// to live only in the password branch, so a user who completed an MFA challenge
// (or a passkey assertion) found another device logged out with no explanation
// and reasonably assumed the account had been compromised.
describe('recycled session feedback', () => {
  it('is shown when the password login reclaims sessions', async () => {
    login.mockResolvedValue({ status: 'authenticated', recycled_sessions: 2 })
    mount()

    fireEvent.change(screen.getByLabelText(/用户名或邮箱/), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText(/^密码/), { target: { value: 'Secret-12345' } })
    fireEvent.click(screen.getByRole('button', { name: /登录/ }))

    expect(await screen.findByText('已退出其他设备')).toBeInTheDocument()
    expect(screen.getByText(/已自动退出 2 个/)).toBeInTheDocument()
  })

  it('is shown when the MFA challenge completion reclaims sessions', async () => {
    login.mockResolvedValue({ status: 'mfa_required', challenge_id: 'ch-1' })
    completeMfa.mockResolvedValue({ status: 'authenticated', recycled_sessions: 1 })
    mount()

    fireEvent.change(screen.getByLabelText(/用户名或邮箱/), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText(/^密码/), { target: { value: 'Secret-12345' } })
    fireEvent.click(screen.getByRole('button', { name: /登录/ }))

    const codeInput = await screen.findByLabelText(/动态验证码或恢复码/)
    fireEvent.change(codeInput, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: '验证并登录' }))

    await waitFor(() => expect(completeMfa).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('已退出其他设备')).toBeInTheDocument()
    expect(screen.getByText(/已自动退出 1 个/)).toBeInTheDocument()
  })
})
