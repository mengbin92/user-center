import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { expect, it, vi } from 'vitest'

import { ResetPasswordPage } from './reset-password-page'

const resetPassword = vi.fn().mockResolvedValue(undefined)

vi.mock('../../lib/api', () => ({
  api: {
    auth: {
      context: async () => ({}),
      resetPassword: (body: unknown) => resetPassword(body),
    },
  },
}))

it.each(['#', '?'])('submits the credentials supplied in a %s email link', async (separator) => {
  resetPassword.mockClear()
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={[`/reset-password${separator}challenge=example-id&code=123456`]}>
        <ResetPasswordPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  fireEvent.change(screen.getByLabelText(/^新密码/), { target: { value: 'StrongPass-2026' } })
  fireEvent.change(screen.getByLabelText(/^确认新密码/), { target: { value: 'StrongPass-2026' } })
  fireEvent.click(screen.getByRole('button', { name: '重置密码' }))
  await waitFor(() => expect(resetPassword).toHaveBeenCalledWith({
    challenge_id: 'example-id', code: '123456', new_password: 'StrongPass-2026',
  }))
})
