import { Loader2, ShieldAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { useLocation } from 'react-router'
import { Navigate, Outlet } from 'react-router'

import { ErrorPanel, PermissionDenied } from '../components/query-state'
import { useAuth } from '../lib/auth'
import { loginPath } from '../lib/paths'
import { useSecurityStatus } from '../lib/security'

export function FullPageLoading({ label = '正在加载账号信息…' }: { label?: string }) {
  return (
    <div className="grid min-h-screen place-items-center bg-slate-100">
      <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-5 py-4 text-xs text-slate-500 shadow-panel">
        <Loader2 className="h-4 w-4 animate-spin text-indigo-500" />
        {label}
      </div>
    </div>
  )
}

export function RequireAuth() {
  const { status, bootError, refresh } = useAuth()
  const location = useLocation()

  if (status === 'loading') return <FullPageLoading />
  if (status === 'error') {
    return (
      <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
        <div className="w-full max-w-lg">
          <ErrorPanel
            error={new Error(bootError ?? '无法加载当前账号')}
            onRetry={() => void refresh(false)}
          />
        </div>
      </div>
    )
  }
  if (status === 'anonymous') {
    return (
      <Navigate
        to={loginPath(`${location.pathname}${location.search}`)}
        replace
      />
    )
  }
  return <Outlet />
}

export function RequireAdmin({ children }: { children: ReactNode }) {
  const { hasAdmin } = useAuth()
  const security = useSecurityStatus({ enabled: hasAdmin })
  if (!hasAdmin) {
    return (
      <PermissionDenied
        title="无法进入管理控制台"
        description="当前账号没有任一项管理端权限。可以返回账号中心，或联系管理员分配角色。"
        backTo="/account"
      />
    )
  }
  if (security.isPending) {
    return <FullPageLoading label="检查账号安全状态…" />
  }
  if (security.data?.password_change_required) {
    return (
      <Navigate
        to="/account/security?password_change_required=1"
        replace
      />
    )
  }
  return <>{children}</>
}

export function RequirePermission({
  permission,
  anyOf,
  children,
  title,
}: {
  permission?: string
  anyOf?: string[]
  children: ReactNode
  title?: string
}) {
  const { can, canAny } = useAuth()
  const allowed = permission
    ? can(permission)
    : anyOf
      ? canAny(anyOf)
      : true
  if (!allowed) {
    return (
      <PermissionDenied
        title={title}
        required={permission ?? anyOf?.join(' / ')}
        backTo="/admin"
      />
    )
  }
  return <>{children}</>
}

export function PageTitle({ title }: { title: string }) {
  useEffect(() => {
    const previous = document.title
    document.title = `${title} · 用户中心`
    return () => {
      document.title = previous
    }
  }, [title])
  return null
}

export function NotFoundPage() {
  return (
    <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
      <div className="flex flex-col items-center gap-3 rounded-xl border border-slate-200 bg-white px-8 py-12 text-center shadow-panel">
        <span className="rounded-full bg-slate-100 p-3 text-slate-500">
          <ShieldAlert className="h-5 w-5" />
        </span>
        <h1 className="text-lg font-semibold text-slate-900">页面不存在</h1>
        <p className="text-xs text-slate-500">请检查地址，或返回账号中心。</p>
        <a
          href="/account"
          className="mt-1 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500"
        >
          返回账号中心
        </a>
      </div>
    </div>
  )
}
