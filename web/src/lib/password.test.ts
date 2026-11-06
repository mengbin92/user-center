import { describe, expect, it } from 'vitest'
import { passwordClassCount, passwordValidationError } from './password'

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

  // The class count must match the server exactly, otherwise a password the UI
  // accepts gets rejected with PASSWORD_POLICY_VIOLATION after submit.
  it('counts character classes the same way the server does', () => {
    expect(passwordClassCount('abcdefgh')).toBe(1)
    expect(passwordClassCount('abcdefgh12')).toBe(2)
    expect(passwordClassCount('abcdefgh1!')).toBe(3)
    expect(passwordClassCount('Abcdefgh1!')).toBe(4)
    // Non-ASCII letters and digits carry no class of their own.
    expect(passwordClassCount('密码密码')).toBe(0)
    expect(passwordClassCount('密码密码1!')).toBe(2)
    // Whitespace is neither a symbol nor a class.
    expect(passwordClassCount('correct horse battery')).toBe(1)
  })

  it('enforces the composition rule only when the policy asks for it', () => {
    expect(passwordValidationError('abcdefghij', 8, 3)).toBe(
      '密码需至少包含 3 类字符（大写字母、小写字母、数字、符号）',
    )
    expect(passwordValidationError('abcdefgh1!', 8, 3)).toBeNull()
    // 0 disables composition entirely, which is the documented escape hatch.
    expect(passwordValidationError('abcdefghij', 8, 0)).toBeNull()
    // Values above four are clamped rather than rejecting everything.
    expect(passwordValidationError('Abcdefg1!', 8, 9)).toBeNull()
  })
})
