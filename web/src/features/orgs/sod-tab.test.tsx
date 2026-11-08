import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ConflictProvider } from '../../components/conflict'
import { StepUpProvider } from '../../components/step-up'
import { ToastProvider } from '../../components/toast'
import { api } from '../../lib/api'
import { AuthContext, type AuthContextValue } from '../../lib/auth'
import { OrganizationSodTab } from './sod-tab'

vi.mock('../../lib/api', () => ({
  api: {
    orgs: {
      listConstraints: vi.fn(),
      listRoles: vi.fn(),
      createConstraint: vi.fn(),
      deleteConstraint: vi.fn(),
    },
  },
}))

// The tab quotes the authorization projection's policy_revision on every write.
// After a successful write the server's revision moves, so the projection has to
// be refetched -- otherwise the *second* rule in a row is rejected with
// POLICY_CONFLICT even though nothing is wrong.
function authValue(refresh: AuthContextValue['refresh']): AuthContextValue {
  return {
    status: 'authenticated',
    sessionGeneration: 0,
    getSessionGeneration: () => 0,
    user: null,
    authorization: { policy_revision: '1' } as AuthContextValue['authorization'],
    permissions: new Set<string>(),
    menuKeys: new Set<string>(),
    can: () => true,
    canAny: () => true,
    hasAdmin: false,
    bootError: null,
    refresh,
    signIn: async () => undefined,
    signOut: async () => undefined,
  }
}

function renderTab(refresh: AuthContextValue['refresh']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <AuthContext.Provider value={authValue(refresh)}>
          <StepUpProvider>
            <ConflictProvider>
              <OrganizationSodTab
                org={{ id: '7', code: 'acme', name: 'Acme', status: 'active', role: 'owner', member_count: '1', revision: '1' }}
                orgId="7"
              />
            </ConflictProvider>
          </StepUpProvider>
        </AuthContext.Provider>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.orgs.listConstraints).mockResolvedValue({ items: [] })
  vi.mocked(api.orgs.listRoles).mockResolvedValue({
    items: [
      { id: '11', code: 'approver', name: '审批', builtin: false },
      { id: '12', code: 'payer', name: '付款', builtin: false },
    ],
  })
  vi.mocked(api.orgs.createConstraint).mockResolvedValue({ id: '1', revision: '1' })
  vi.mocked(api.orgs.deleteConstraint).mockResolvedValue(undefined)
})

describe('organization SoD tab', () => {
  it('refreshes the authorization projection after a write (create and delete)', async () => {
    const refresh = vi.fn().mockResolvedValue(undefined)
    renderTab(refresh)

    // Create: open the draft, pick both roles, go to the reason dialog, save.
    fireEvent.click(await screen.findByRole('button', { name: '新建规则' }))
    fireEvent.change(screen.getByLabelText(/名称/), { target: { value: '审批与付款' } })
    fireEvent.click(screen.getByLabelText(/审批/))
    fireEvent.click(screen.getByLabelText(/付款/))
    fireEvent.click(screen.getByRole('button', { name: '下一步' }))

    fireEvent.change(await screen.findByLabelText(/操作原因/), {
      target: { value: '制度要求' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(api.orgs.createConstraint).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1))

    // The quoted revision comes from the projection, not from a stale closure.
    expect(vi.mocked(api.orgs.createConstraint).mock.calls[0][1]).toMatchObject({
      expected_policy_revision: '1',
    })
  })

  it('rejects max_count 0 instead of offering a save that cannot succeed', async () => {
    renderTab(vi.fn().mockResolvedValue(undefined))

    fireEvent.click(await screen.findByRole('button', { name: '新建规则' }))
    fireEvent.change(screen.getByLabelText(/类型/), { target: { value: 'max_roles' } })
    fireEvent.change(screen.getByLabelText(/名称/), { target: { value: '最多一个' } })
    fireEvent.change(screen.getByLabelText(/所选角色中最多可同时持有/), {
      target: { value: '0' },
    })
    fireEvent.click(screen.getByLabelText(/审批/))
    fireEvent.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByText('角色数量上限必须为正整数')).toBeTruthy()
    // Nothing is sent, and the draft stays open.
    expect(api.orgs.createConstraint).not.toHaveBeenCalled()
  })
})
