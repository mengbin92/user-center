/**
 * Mirrors the backend password policy in `internal/biz/helpers.go`.
 *
 * This copy exists so the rule is visible while typing instead of arriving as a
 * rejection after submit. It is not the authority: the server re-checks
 * everything, and a mismatch surfaces as PASSWORD_POLICY_VIOLATION.
 */

/** How many of {uppercase, lowercase, digit, symbol} the password contains. */
export function passwordClassCount(password: string): number {
  let mask = 0
  for (const ch of password) {
    if (ch >= 'A' && ch <= 'Z') mask |= 1
    else if (ch >= 'a' && ch <= 'z') mask |= 2
    else if (ch >= '0' && ch <= '9') mask |= 4
    else if (/\s/u.test(ch)) continue
    // Non-ASCII letters and digits carry no class of their own, matching the
    // server: a Chinese passphrase must not be judged differently by each side.
    else if (/[\p{L}\p{N}]/u.test(ch)) continue
    else mask |= 8
  }
  let count = 0
  for (let bit = mask; bit > 0; bit >>= 1) count += bit & 1
  return count
}

export const PASSWORD_CLASS_HINT = '大写字母、小写字母、数字、符号'

export function passwordValidationError(
  password: string,
  minimum: number,
  minClasses = 0,
): string | null {
  if (Array.from(password).length < Math.max(8, minimum)) {
    return `密码至少需要 ${Math.max(8, minimum)} 个字符`
  }
  if (new TextEncoder().encode(password).length > 72) {
    return '密码不能超过 72 个字节'
  }
  if (password.trim() !== password) return '密码首尾不能包含空白字符'
  if (minClasses > 0) {
    const required = Math.min(minClasses, 4)
    if (passwordClassCount(password) < required) {
      return `密码需至少包含 ${required} 类字符（${PASSWORD_CLASS_HINT}）`
    }
  }
  return null
}
