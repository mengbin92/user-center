import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ToastProvider } from '../../components/toast'
import { LoginPage } from './login-page'

const mocks = vi.hoisted(() => ({ replace: vi.fn() }))
vi.mock('../../lib/auth', () => ({ useAuth: () => ({ status: 'authenticated', hasAdmin: false, signIn: vi.fn() }) }))
vi.mock('../../lib/api', () => ({ api: { auth: { context: async () => ({ providers: [] }) } } }))

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function mount(next: string) {
  const actualWindow = window
  vi.stubGlobal('window', new Proxy(actualWindow, {
    get: (target, property) => property === 'location' ? { replace: mocks.replace } : Reflect.get(target, property),
  }))
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/login?next=${encodeURIComponent(next)}`]}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/account" element={<span>账号中心</span>} />
          <Route path="/oidc/authorize" element={<span>错误的 SPA 授权路由</span>} />
        </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('post-login OIDC continuation', () => {
  it('resumes the server authorization endpoint with a document navigation', async () => {
    const next = '/oidc/authorize?client_id=example&state=opaque'
    mount(next)
    await waitFor(() => expect(mocks.replace).toHaveBeenCalledWith(next))
    expect(screen.getByText('正在继续应用授权…')).toBeInTheDocument()
    expect(screen.queryByText('错误的 SPA 授权路由')).not.toBeInTheDocument()
  })

  it('keeps ordinary app navigation in the router', async () => {
    mount('/account')
    expect(await screen.findByText('账号中心')).toBeInTheDocument()
    expect(mocks.replace).not.toHaveBeenCalled()
  })

  it('rejects an external continuation', async () => {
    mount('//evil.example.com')
    expect(await screen.findByText('账号中心')).toBeInTheDocument()
    expect(mocks.replace).not.toHaveBeenCalled()
  })
})
