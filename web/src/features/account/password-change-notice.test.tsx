import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { PasswordChangeNotice } from './password-change-notice'

describe('PasswordChangeNotice', () => {
  it('shows a blocking notice while the initial password must be changed', () => {
    render(<PasswordChangeNotice required />)

    const notice = screen.getByTestId('password-change-notice')
    expect(notice).toHaveTextContent('必须先修改初始密码')
    expect(notice).toHaveTextContent('完成修改前无法进入管理控制台')
    expect(notice).toHaveTextContent('PASSWORD_CHANGE_REQUIRED')
  })

  it('renders nothing when a password change is not required', () => {
    render(<PasswordChangeNotice required={false} />)
    expect(
      screen.queryByTestId('password-change-notice'),
    ).not.toBeInTheDocument()
  })
})
