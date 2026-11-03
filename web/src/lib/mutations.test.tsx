import type { ReactNode } from 'react'
import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './errors'
import { useApiMutation } from './mutations'

const mocks = vi.hoisted(() => ({ generation: 0, requestStepUp: vi.fn(), success: vi.fn(), error: vi.fn(), refresh: vi.fn() }))
vi.mock('./auth', () => ({ useAuth: () => ({ getSessionGeneration: () => mocks.generation, refresh: mocks.refresh }) }))
vi.mock('../components/step-up', () => ({ useStepUp: () => ({ requestStepUp: mocks.requestStepUp }) }))
vi.mock('../components/conflict', () => ({ useConflict: () => ({ showConflict: vi.fn() }) }))
vi.mock('../components/toast', () => ({ useToast: () => ({ success: mocks.success, error: mocks.error, warning: vi.fn(), info: vi.fn() }) }))

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}
const stepUpRequired = () => new ApiError({ status: 403, reason: 'STEP_UP_REQUIRED' })

beforeEach(() => { vi.resetAllMocks(); mocks.generation = 0 })

describe('controlled step-up retry', () => {
  it('does not replay an operation under a different login session', async () => {
    let verify!: (value: boolean) => void
    mocks.requestStepUp.mockReturnValue(new Promise<boolean>((resolve) => { verify = resolve }))
    const mutationFn = vi.fn().mockRejectedValueOnce(stepUpRequired()).mockResolvedValue('done')
    const { result } = renderHook(() => useApiMutation({ mutationFn }), { wrapper })
    act(() => result.current.mutate(undefined))
    await waitFor(() => expect(mocks.requestStepUp).toHaveBeenCalledOnce())
    mocks.generation += 1
    await act(async () => { verify(true) })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(mutationFn).toHaveBeenCalledOnce()
    expect(result.current.error).toMatchObject({ reason: 'SESSION_CHANGED' })
  })

  it('retries at most once even when the server requests step-up again', async () => {
    mocks.requestStepUp.mockResolvedValue(true)
    const mutationFn = vi.fn().mockRejectedValue(stepUpRequired())
    const { result } = renderHook(() => useApiMutation({ mutationFn }), { wrapper })
    act(() => result.current.mutate(undefined))
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(mutationFn).toHaveBeenCalledTimes(2)
    expect(mocks.requestStepUp).toHaveBeenCalledOnce()
  })

  it('does not run success callbacks for results from an old session', async () => {
    let complete!: (value: string) => void
    const mutationFn = vi.fn().mockReturnValue(new Promise<string>((resolve) => { complete = resolve }))
    const onSuccess = vi.fn()
    const { result } = renderHook(() => useApiMutation({ mutationFn, onSuccess, successMessage: '完成' }), { wrapper })
    act(() => result.current.mutate(undefined))
    await waitFor(() => expect(mutationFn).toHaveBeenCalledOnce())
    mocks.generation += 1
    await act(async () => { complete('done') })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(onSuccess).not.toHaveBeenCalled()
    expect(mocks.success).not.toHaveBeenCalled()
  })
})
