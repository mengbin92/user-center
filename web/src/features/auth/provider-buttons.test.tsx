import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { ProviderButtons } from './provider-buttons'

describe('provider buttons', () => {
  it('renders full-page links to the provider start endpoint for login', () => {
    render(<ProviderButtons providers={['github', 'google', 'mock']} />)

    const github = screen.getByTestId('provider-github')
    expect(github.tagName).toBe('A')
    expect(github).toHaveAttribute(
      'href',
      '/api/v1/auth/providers/github/start',
    )
    expect(github).toHaveTextContent('使用 GitHub 登录')

    expect(screen.getByTestId('provider-google')).toHaveAttribute(
      'href',
      '/api/v1/auth/providers/google/start',
    )
    expect(screen.getByTestId('provider-mock')).toHaveAttribute(
      'href',
      '/api/v1/auth/providers/mock/start',
    )
  })

  it('adds mode=bind for account binding flows', () => {
    render(
      <ProviderButtons providers={['github', 'google']} mode="bind" />,
    )

    expect(screen.getByTestId('provider-github')).toHaveAttribute(
      'href',
      '/api/v1/auth/providers/github/start?mode=bind',
    )
    expect(screen.getByTestId('provider-google')).toHaveTextContent(
      '绑定 Google',
    )
  })
})
