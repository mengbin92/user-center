import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '../../lib/api'
import { AdminAuditDetailPage } from './audit-detail-page'

function StateProbe() {
  const location = useLocation()
  const filters = (location.state as { auditFilters?: Record<string, unknown> } | null)?.auditFilters
  return <div data-testid="filter-state">{filters ? JSON.stringify(filters) : 'none'}</div>
}

function renderDetail(
  path = '/admin/audits/event-1',
  state?: { auditFilters?: Record<string, unknown> },
) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[{ pathname: path, state }]}>
        <Routes>
          <Route path="/admin/audits/:id" element={<AdminAuditDetailPage />} />
          <Route path="/admin/audits" element={<><div>审计列表</div><StateProbe /></>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AdminAuditDetailPage', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('renders the full context of one audit event', async () => {
    vi.spyOn(api.audits, 'get').mockResolvedValue({
      id: 'event-1',
      action: 'identity.user.archive',
      actor_user_id: '7',
      actor_service_id: '',
      actor_session_id: 'session-1',
      target: '42',
      before: '{"status":"enabled"}',
      after: '{"status":"archived"}',
      diff: '{"status":["enabled","archived"]}',
      result: 'success',
      reason: '离职归档',
      request_id: 'req-1',
      authorization_versions: '{"policy":3}',
      occurred_at: '2026-11-05T02:00:00Z',
    })
    renderDetail()
    await waitFor(() =>
      expect(screen.getAllByText('identity.user.archive').length).toBeGreaterThan(0),
    )
    expect(screen.getByText('离职归档')).toBeTruthy()
    expect(screen.getByText('req-1')).toBeTruthy()
    expect(screen.getByText('{"policy":3}')).toBeTruthy()
    expect(screen.getAllByText('diff').length).toBeGreaterThan(0)
  })

  it('returns to the list with the original filters intact', async () => {
    vi.spyOn(api.audits, 'get').mockResolvedValue({
      id: 'event-3', action: 'organization.create', diff: '{}', result: 'success',
      reason: 'create', occurred_at: '2026-11-05T02:00:00Z',
    })
    const filters = { action: 'organization.create', actorId: '7', tokens: [''] }
    renderDetail('/admin/audits/event-3', { auditFilters: filters })
    await waitFor(() =>
      expect(screen.getAllByText('organization.create').length).toBeGreaterThan(0),
    )
    fireEvent.click(screen.getByText('返回审计列表'))
    await waitFor(() => expect(screen.getByText('审计列表')).toBeTruthy())
    expect(screen.getByTestId('filter-state').textContent).toContain('organization.create')
    expect(screen.getByTestId('filter-state').textContent).toContain('"actorId":"7"')
  })

  it('degrades gracefully when diff is empty', async () => {
    vi.spyOn(api.audits, 'get').mockResolvedValue({
      id: 'event-2', action: 'organization.create', diff: '{}',
      result: 'success', reason: 'create', occurred_at: '2026-11-05T02:00:00Z',
    })
    renderDetail('/admin/audits/event-2')
    await waitFor(() =>
      expect(screen.getAllByText('organization.create').length).toBeGreaterThan(0),
    )
    expect(screen.getAllByText('（空）').length).toBeGreaterThan(0)
    expect(screen.getAllByText('该事件没有记录此字段。').length).toBeGreaterThan(0)
  })
})
