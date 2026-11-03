import { StrictMode } from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'
import { AuthProvider, useAuth, type AuthContextValue } from './auth'
import { ApiError } from './errors'
import { ToastProvider } from '../components/toast'
import type { User } from './types'

vi.mock('./api', () => ({ api: { me: { get: vi.fn(), authorization: vi.fn() }, auth: { logout: vi.fn() } } }))

class TestChannel {
  static instances: TestChannel[] = []
  onmessage: ((event: MessageEvent) => void) | null = null
  postMessage = vi.fn()
  close = vi.fn()
  constructor() { TestChannel.instances.push(this) }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

let auth: AuthContextValue
function Probe() { auth = useAuth(); return <span>{auth.status}</span> }

function mount(strict = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const tree = <QueryClientProvider client={client}><ToastProvider><MemoryRouter><AuthProvider><Probe /></AuthProvider></MemoryRouter></ToastProvider></QueryClientProvider>
  render(strict ? <StrictMode>{tree}</StrictMode> : tree)
  return client
}

beforeEach(() => {
  vi.resetAllMocks()
  TestChannel.instances = []
  vi.stubGlobal('BroadcastChannel', TestChannel)
  vi.mocked(api.me.get).mockResolvedValue({ id: '1', username: 'alice' })
  vi.mocked(api.me.authorization).mockResolvedValue({ policy_revision: '1', permissions: [{ operation: 'identity.user.list', effect: 'allow' }] })
  vi.mocked(api.auth.logout).mockResolvedValue(undefined)
})

describe('authentication lifecycle', () => {
  it('boots in React StrictMode without accepting an obsolete bootstrap', async () => {
    mount(true)
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    expect(auth.user?.id).toBe('1')
  })

  it('does not restore a logged-out account from a late refresh response', async () => {
    const client = mount()
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    const pending = deferred<User>()
    vi.mocked(api.me.get).mockReturnValueOnce(pending.promise)
    let refresh!: Promise<void>
    act(() => { refresh = auth.refresh() })
    client.setQueryData(['admin', 'users'], [{ email: 'private@example.com' }])
    await act(async () => { await auth.signOut() })
    await act(async () => { pending.resolve({ id: '1' }); await refresh })
    expect(auth.status).toBe('anonymous')
    expect(auth.user).toBeNull()
    expect(auth.permissions.size).toBe(0)
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })

  it('reports a failed server logout and keeps the existing session available for retry', async () => {
    mount()
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    vi.mocked(api.auth.logout).mockRejectedValueOnce(new ApiError({ status: 503, reason: 'DEPENDENCY_UNAVAILABLE', message: '数据库不可用' }))
    await act(async () => { await auth.signOut() })
    expect(auth.status).toBe('authenticated')
    expect(auth.user?.id).toBe('1')
    expect(screen.getByText('退出失败')).toBeInTheDocument()
    expect(screen.getByText(/当前会话尚未撤销/)).toBeInTheDocument()
    expect(TestChannel.instances.at(-1)!.postMessage).not.toHaveBeenCalledWith({ type: 'logout' })
    await act(async () => { await auth.signOut() })
    expect(auth.status).toBe('anonymous')
  })

  it('clears stale permissions and protected caches when a quiet refresh fails', async () => {
    const client = mount()
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    client.setQueryData(['admin', 'users'], [{ id: '2' }])
    vi.mocked(api.me.authorization).mockRejectedValueOnce(new ApiError({ status: 503, reason: 'AUTHORIZATION_UNAVAILABLE', message: '权限服务不可用' }))
    await act(async () => { await auth.refresh(true) })
    expect(auth.status).toBe('error')
    expect(auth.can('identity.user.list')).toBe(false)
    expect(auth.bootError).toBe('权限服务不可用')
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })

  it('invalidates cached resources when the authorization projection changes', async () => {
    const client = mount()
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    client.setQueryData(['admin', 'users'], [{ id: '2' }])
    vi.mocked(api.me.authorization).mockResolvedValueOnce({ policy_revision: '2', permissions: [] })
    await act(async () => { await auth.refresh() })
    expect(auth.status).toBe('authenticated')
    expect(auth.permissions.size).toBe(0)
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })

  it('clears state on another tab logout and rejects in-flight reads', async () => {
    const client = mount()
    await waitFor(() => expect(auth.status).toBe('authenticated'))
    const originalGeneration = auth.getSessionGeneration()
    const pending = deferred<User>()
    vi.mocked(api.me.get).mockReturnValueOnce(pending.promise)
    let refresh!: Promise<void>
    act(() => { refresh = auth.refresh() })
    client.setQueryData(['me'], { id: '1' })
    act(() => { TestChannel.instances.at(-1)!.onmessage!({ data: { type: 'logout' } } as MessageEvent) })
    await act(async () => { pending.resolve({ id: '1' }); await refresh })
    expect(auth.status).toBe('anonymous')
    expect(auth.getSessionGeneration()).toBeGreaterThan(originalGeneration)
    expect(client.getQueryCache().getAll()).toHaveLength(0)
  })
})
