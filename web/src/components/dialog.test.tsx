import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { Dialog } from './dialog'

describe('dialog focus', () => {
  it('keeps the active input focused when the caller rerenders with a new callback', async () => {
    const content = <><input aria-label="密码" /><input aria-label="验证码" /></>
    const { rerender } = render(<Dialog open onClose={() => undefined} title="验证">{content}</Dialog>)
    await waitFor(() => expect(screen.getByLabelText('密码')).toHaveFocus())
    screen.getByLabelText('验证码').focus()
    rerender(<Dialog open onClose={() => undefined} title="验证">{content}</Dialog>)
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 30)) })
    expect(screen.getByLabelText('验证码')).toHaveFocus()
  })

  it('traps keyboard focus and restores the triggering control on close', async () => {
    const trigger = document.createElement('button')
    document.body.append(trigger)
    trigger.focus()
    const close = vi.fn()
    const { rerender } = render(<Dialog open onClose={close} title="验证"><input aria-label="内容" /></Dialog>)
    await waitFor(() => expect(screen.getByLabelText('内容')).toHaveFocus())
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(screen.getByRole('button', { name: '关闭' })).toHaveFocus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(screen.getByLabelText('内容')).toHaveFocus()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(close).toHaveBeenCalledOnce()
    rerender(<Dialog open={false} onClose={close} title="验证" />)
    expect(trigger).toHaveFocus()
    trigger.remove()
  })

  it('lets only the topmost dialog handle keyboard events during step-up', async () => {
    const closeParent = vi.fn()
    const closeVerification = vi.fn()
    render(<>
      <Dialog open onClose={closeParent} title="创建应用"><input aria-label="名称" /></Dialog>
      <Dialog open onClose={closeVerification} title="安全验证"><input aria-label="密码" /><input aria-label="动态码" /></Dialog>
    </>)
    await waitFor(() => expect(screen.getByLabelText('密码')).toHaveFocus())
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(screen.getByLabelText('密码')).toHaveFocus()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(closeVerification).toHaveBeenCalledOnce()
    expect(closeParent).not.toHaveBeenCalled()
  })
})
