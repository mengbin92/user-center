export const PUBLIC_PATHS = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/terms',
  '/privacy',
] as const

export function isPublicPath(pathname: string): boolean {
  if (pathname.startsWith('/auth/callback/')) return true
  return PUBLIC_PATHS.some(
    (path) => pathname === path || pathname.startsWith(`${path}/`),
  )
}

export function safeNext(raw: string | null): string | null {
  if (!raw) return null
  if (!raw.startsWith('/') || raw.startsWith('//')) return null
  if (isPublicPath(raw.split('?')[0])) return null
  return raw
}

export function loginPath(next?: string): string {
  if (!next) return '/login'
  return `/login?next=${encodeURIComponent(next)}`
}
