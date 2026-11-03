import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../lib/api'
import { ApiError } from '../lib/errors'
import { StepUpProvider, useStepUp } from './step-up'
import { ToastProvider } from './toast'

vi.mock('../lib/auth', () => ({ useAuth: () => ({ sessionGeneration: 0, getSessionGeneration: () => 0 }) }))
vi.mock('../lib/api', () => ({ api: { me: { security: vi.fn(), verifySecurity: vi.fn() } } }))

const completed = vi.fn()
function Trigger() {
  const { requestStepUp } = useStepUp()
  return <button onClick={() => { void requestStepUp().then(completed) }}>发起敏感操作</button>
}
function mount() {
  render(<QueryClientProvider client={new QueryClient()}><ToastProvider><MemoryRouter><StepUpProvider><Trigger /></StepUpProvider></MemoryRouter></ToastProvider></QueryClientProvider>)
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.me.security).mockResolvedValue({ password_available: false, mfa_enabled: true })
})

describe('OAuth-only step-up', () => {
  it('uses the recent bound-provider proof with MFA without asking for a nonexistent password', async () => {
    vi.mocked(api.me.verifySecurity).mockResolvedValue({ verified: true, expires_at: '2026-11-03T01:00:00Z' })
    mount()
    fireEvent.click(screen.getByText('发起敏感操作'))
    expect(await screen.findByText('使用已绑定的第三方身份验证')).toBeInTheDocument()
    expect(screen.queryByLabelText('当前密码')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/动态验证码 \/ 恢复码/), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: '验证并继续' }))
    await waitFor(() => expect(api.me.verifySecurity).toHaveBeenCalledWith({ current_password: '', code: '123456' }))
    await waitFor(() => expect(completed).toHaveBeenCalledWith(true))
  })

  it('keeps a rejected or expired provider proof from authorizing the pending action', async () => {
    vi.mocked(api.me.verifySecurity).mockRejectedValue(new ApiError({ status: 403, reason: 'STEP_UP_REQUIRED', message: '请重新验证已绑定身份' }))
    mount()
    fireEvent.click(screen.getByText('发起敏感操作'))
    await screen.findByText('使用已绑定的第三方身份验证')
    fireEvent.change(screen.getByLabelText(/动态验证码 \/ 恢复码/), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: '验证并继续' }))
    expect(await screen.findByText('请重新验证已绑定身份')).toBeInTheDocument()
    expect(completed).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '取消' }))
    await waitFor(() => expect(completed).toHaveBeenCalledWith(false))
  })
})
