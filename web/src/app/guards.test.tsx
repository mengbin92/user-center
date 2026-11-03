import type { ReactNode } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import { ApiError } from '../lib/errors'
import { RequireAdmin } from './guards'

vi.mock('../lib/api', () => ({ api: { me: { security: vi.fn() } } }))
vi.mock('../lib/auth', () => ({ useAuth: () => ({ hasAdmin: true }) }))

function mount(children: ReactNode) {
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/admin']}><Routes>
    <Route path="/admin" element={<RequireAdmin>{children}</RequireAdmin>} />
    <Route path="/account/security" element={<span>安全中心绑定流程</span>} />
  </Routes></MemoryRouter></QueryClientProvider>)
}

beforeEach(() => { vi.resetAllMocks() })

describe('admin security gate', () => {
  it('does not render management content when security status cannot be loaded', async () => {
    vi.mocked(api.me.security).mockRejectedValue(new ApiError({ status: 503, reason: 'DEPENDENCY_UNAVAILABLE', message: '安全状态暂不可用' }))
    mount(<span>敏感管理内容</span>)
    await waitFor(() => expect(screen.getByText('安全状态暂不可用')).toBeInTheDocument())
    expect(screen.queryByText('敏感管理内容')).not.toBeInTheDocument()
  })

  it('routes administrators who require MFA enrollment to the security center', async () => {
    vi.mocked(api.me.security).mockResolvedValue({ mfa_required: true, mfa_enabled: false })
    mount(<span>敏感管理内容</span>)
    expect(await screen.findByText('安全中心绑定流程')).toBeInTheDocument()
    expect(screen.queryByText('敏感管理内容')).not.toBeInTheDocument()
  })
})
