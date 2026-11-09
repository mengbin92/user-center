import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ConflictProvider } from '../../components/conflict'
import { StepUpProvider } from '../../components/step-up'
import { ToastProvider } from '../../components/toast'
import { api } from '../../lib/api'
import { AuthContext, type AuthContextValue } from '../../lib/auth'
import { OrganizationDelegations } from './sod-delegations'

vi.mock('../../lib/api', () => ({
  api: {
    orgs: {
      listDelegations: vi.fn(),
      listRoles: vi.fn(),
      listMembers: vi.fn(),
      createDelegation: vi.fn(),
      updateDelegation: vi.fn(),
      revokeDelegation: vi.fn(),
    },
  },
}))

function authValue(): AuthContextValue {
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
    refresh: async () => undefined,
    signIn: async () => undefined,
    signOut: async () => undefined,
  }
}

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <AuthContext.Provider value={authValue()}>
          <StepUpProvider>
            <ConflictProvider>
              <OrganizationDelegations
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
  vi.mocked(api.orgs.listDelegations).mockResolvedValue({
    items: [
      {
        id: '9', manager_role_id: '11', target_role_id: '12',
        actions: ['assign'], revision: '2', revoked: false,
      },
    ],
  })
  vi.mocked(api.orgs.listRoles).mockResolvedValue({
    items: [
      { id: '11', code: 'mgr', name: '管理角色', builtin: false },
      { id: '12', code: 'aud', name: '审计角色', builtin: false, grants: [{ operation: 'organization.audit.read', effect: 'allow', scope: { all: true } }] },
    ],
  })
  vi.mocked(api.orgs.listMembers).mockResolvedValue({
    items: [
      { user_id: '21', username: 'alice', display_name: 'Alice' },
      { user_id: '22', username: 'bob', display_name: 'Bob' },
    ],
  })
  vi.mocked(api.orgs.createDelegation).mockResolvedValue({ id: '10', revision: '1' })
  vi.mocked(api.orgs.revokeDelegation).mockResolvedValue({ id: '9', revision: '3', revoked: true })
})

describe('organization delegation panel', () => {
  it('lists delegations with role names', async () => {
    renderPanel()
    // "管理角色" appears twice: the column header and the resolved role cell.
    const manager = await screen.findAllByText('管理角色')
    expect(manager.length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('审计角色')).toBeTruthy()
    expect(api.orgs.listDelegations).toHaveBeenCalledWith('7')
  })

  it('creates a delegation with the target role grants as the ceiling', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: '新建委派' }))

    fireEvent.change(screen.getByLabelText('管理角色'), { target: { value: '11' } })
    fireEvent.change(screen.getByLabelText('目标角色'), { target: { value: '12' } })
    fireEvent.click(screen.getByRole('button', { name: '下一步' }))

    fireEvent.change(await screen.findByLabelText(/操作原因/), {
      target: { value: '把审计角色分配权交给管理角色' },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建' }))

    await waitFor(() => expect(api.orgs.createDelegation).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.orgs.createDelegation).mock.calls[0][1]).toMatchObject({
      manager_role_id: '11',
      target_role_id: '12',
      actions: ['assign'],
      // Derived from the target role, never typed by the operator.
      grant_ceiling: [{ operation: 'organization.audit.read', scope: { all: true } }],
      expected_policy_revision: '1',
    })
  })

  it('bounds the delegation to specific members when asked', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: '新建委派' }))
    fireEvent.change(screen.getByLabelText('管理角色'), { target: { value: '11' } })
    fireEvent.change(screen.getByLabelText('目标角色'), { target: { value: '12' } })

    fireEvent.click(screen.getByLabelText('指定成员'))
    fireEvent.click(await screen.findByLabelText(/Alice/))
    fireEvent.click(screen.getByRole('button', { name: '下一步' }))

    fireEvent.change(await screen.findByLabelText(/操作原因/), {
      target: { value: '仅授权给 Alice' },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建' }))

    await waitFor(() => expect(api.orgs.createDelegation).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.orgs.createDelegation).mock.calls[0][1]).toMatchObject({
      target_user_scope: { user_ids: ['21'] },
    })
  })

  it('revokes through the reason dialog', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: '撤销' }))
    fireEvent.change(await screen.findByLabelText(/操作原因/), {
      target: { value: '职责调整' },
    })
    const buttons = screen.getAllByRole('button', { name: '撤销' })
    fireEvent.click(buttons[buttons.length - 1])

    await waitFor(() => expect(api.orgs.revokeDelegation).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.orgs.revokeDelegation).mock.calls[0][1]).toBe('9')
    expect(vi.mocked(api.orgs.revokeDelegation).mock.calls[0][2]).toMatchObject({
      expected_revision: '2',
      expected_policy_revision: '1',
    })
  })
})
