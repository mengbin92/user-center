/** Mirrors the public password policy: Unicode character minimum, bcrypt byte limit. */
export function passwordValidationError(password: string, minimum: number): string | null {
  if (Array.from(password).length < Math.max(8, minimum)) {
    return `密码至少需要 ${Math.max(8, minimum)} 个字符`
  }
  if (new TextEncoder().encode(password).length > 72) {
    return '密码不能超过 72 个字节'
  }
  if (password.trim() !== password) return '密码首尾不能包含空白字符'
  return null
}
