import { Fingerprint } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'

import { cn } from '../../lib/cn'
import { Card } from '../../components/card'

export function AuthShell({
  title,
  subtitle,
  children,
  footer,
  wide = false,
}: {
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
  wide?: boolean
}) {
  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden bg-slate-100">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-indigo-100/70 via-slate-100 to-transparent"
      />
      <header className="relative mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-5 sm:px-6">
        <Link to="/login" className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-slate-900 text-white">
            <Fingerprint className="h-4 w-4" />
          </span>
          <span className="leading-tight">
            <span className="block text-sm font-semibold text-slate-900">
              用户中心
            </span>
            <span className="block text-[10px] text-slate-500">
              Account & Identity
            </span>
          </span>
        </Link>
        <nav className="flex items-center gap-3 text-[11px] text-slate-500">
          <Link to="/terms" className="hover:text-slate-800">
            服务条款
          </Link>
          <Link to="/privacy" className="hover:text-slate-800">
            隐私政策
          </Link>
        </nav>
      </header>

      <main className="relative flex flex-1 items-center justify-center px-4 py-4 sm:px-6">
        <div className={cn('w-full', wide ? 'max-w-3xl' : 'max-w-md')}>
          <div className="mb-4 text-center">
            <h1 className="text-xl font-semibold tracking-tight text-slate-900">
              {title}
            </h1>
            {subtitle ? (
              <p className="mt-1 text-xs text-slate-500">{subtitle}</p>
            ) : null}
          </div>
          <Card className="p-5 shadow-lg">{children}</Card>
          {footer ? (
            <div className="mt-4 text-center text-xs text-slate-500">
              {footer}
            </div>
          ) : null}
        </div>
      </main>

      <footer className="relative mx-auto w-full max-w-6xl px-4 pb-5 text-center text-[10px] text-slate-400 sm:px-6">
        会话使用 HttpOnly Cookie 保存，浏览器脚本无法读取登录令牌。
      </footer>
    </div>
  )
}
