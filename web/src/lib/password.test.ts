import { describe, expect, it } from 'vitest'
import { passwordValidationError } from './password'

describe('password policy', () => {
  it('counts Unicode characters instead of UTF-8 bytes or UTF-16 code units', () => {
    expect(passwordValidationError('密码安全', 8)).toBe('密码至少需要 8 个字符')
    expect(passwordValidationError('😀😀😀😀', 8)).toBe('密码至少需要 8 个字符')
    expect(passwordValidationError('😀😀😀😀😀😀😀😀', 8)).toBeNull()
  })
  it('rejects bcrypt overflow and leading/trailing whitespace before submitting', () => {
    expect(passwordValidationError('密'.repeat(25), 8)).toBe('密码不能超过 72 个字节')
    expect(passwordValidationError('password ', 8)).toBe('密码首尾不能包含空白字符')
    expect(passwordValidationError('a'.repeat(72), 8)).toBeNull()
  })
})
