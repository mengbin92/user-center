import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  Building2,
  Fingerprint,
  KeyRound,
  LayoutDashboard,
  LogOut,
  MonitorSmartphone,
  ShieldCheck,
  UserRound,
} from 'lucide-react'
import { NavLink, Outlet, useLocation } from 'react-router'

import { cn } from '../lib/cn'
import { useAuth } from '../lib/auth'
import { useSecurityStatus } from '../lib/security'
import { Button } from '../components/button'
import { PasswordChangeNotice } from '../features/account/password-change-notice'
import { OrganizationSwitcher } from '../features/orgs/org-switcher'

type NavItem = {
  to: string
  label: string
  menuKey: string
  icon: LucideIcon
  end?: boolean
}

const NAV_ITEMS: NavItem[] = [
  { to: '/account', label: '个人资料', menuKey: 'account', icon: UserRound, end: true },
  {
    to: '/account/security',
    label: '安全中心',
    menuKey: 'account/security',
    icon: ShieldCheck,
  },
  {
    to: '/account/sessions',
    label: '会话管理',
    menuKey: 'account/sessions',
    icon: MonitorSmartphone,
  },
  {
    to: '/account/roles',
    label: '会话角色',
    menuKey: 'account/roles',
    icon: KeyRound,
  },
  {
    to: '/account/activity',
    label: '登录记录',
    menuKey: 'account/activity',
    icon: Activity,
  },
]

export function AccountLayout() {
  const { user, menuKeys, hasAdmin, signOut } = useAuth()
  const location = useLocation()
  const security = useSecurityStatus()
  const passwordChangeRequired =
    security.data?.password_change_required === true
  const showPasswordNotice =
    passwordChangeRequired && location.pathname !== '/account/security'

  const items = NAV_ITEMS.filter((item) => menuKeys.has(item.menuKey))

  return (
    <div className="flex min-h-screen flex-col bg-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-6">
            <NavLink to="/account" className="flex shrink-0 items-center gap-2">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-slate-900 text-white">
                <Fingerprint className="h-4 w-4" />
              </span>
              <span className="leading-tight">
                <span className="block text-sm font-semibold text-slate-900">
                  用户中心
                </span>
                <span className="block text-[10px] text-slate-500">账号门户</span>
              </span>
            </NavLink>
            <nav className="hidden items-center gap-0.5 md:flex">
              {items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                      isActive
                        ? 'bg-indigo-50 text-indigo-700'
                        : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                    )
                  }
                >
                  <item.icon className="h-3.5 w-3.5" />
                  {item.label}
                </NavLink>
              ))}
              <NavLink
                to="/orgs"
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                    isActive
                      ? 'bg-indigo-50 text-indigo-700'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                  )
                }
              >
                <Building2 className="h-3.5 w-3.5" />
                组织
              </NavLink>
            </nav>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <div className="hidden sm:block">
              <OrganizationSwitcher />
            </div>
            {hasAdmin && !passwordChangeRequired ? (
              <NavLink
                to="/admin"
                className="hidden items-center gap-1 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 sm:flex"
              >
                <LayoutDashboard className="h-3.5 w-3.5" />
                管理控制台
              </NavLink>
            ) : null}
            <div className="hidden max-w-40 truncate text-right text-xs leading-tight sm:block">
              <div className="font-medium text-slate-800">
                {user?.display_name || user?.username}
              </div>
              <div className="truncate text-[10px] text-slate-500">
                @{user?.username}
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => void signOut()}
              aria-label="退出登录"
              title="退出登录"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="border-t border-slate-100 md:hidden">
          <nav className="flex gap-1 overflow-x-auto px-3 py-1.5">
            {items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    'flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-medium',
                    isActive
                      ? 'bg-indigo-50 text-indigo-700'
                      : 'text-slate-600',
                  )
                }
              >
                <item.icon className="h-3 w-3" />
                {item.label}
              </NavLink>
            ))}
            <NavLink
              to="/orgs"
              className={({ isActive }) =>
                cn(
                  'flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-medium',
                  isActive ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600',
                )
              }
            >
              <Building2 className="h-3 w-3" />
              组织
            </NavLink>
            {hasAdmin && !passwordChangeRequired ? (
              <NavLink
                to="/admin"
                className="flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-medium text-slate-600"
              >
                <LayoutDashboard className="h-3 w-3" />
                管理控制台
              </NavLink>
            ) : null}
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-5 sm:px-6 sm:py-6">
        {showPasswordNotice ? (
          <div className="mb-4">
            <PasswordChangeNotice required showLink />
          </div>
        ) : null}
        <Outlet />
      </main>

      <footer className="border-t border-slate-200 bg-white/60">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-2 px-4 py-3 text-[11px] text-slate-500 sm:px-6">
          <span>用户中心 · 账号与身份治理</span>
          <div className="flex gap-3">
            <NavLink to="/terms" className="hover:text-slate-800">
              服务条款
            </NavLink>
            <NavLink to="/privacy" className="hover:text-slate-800">
              隐私政策
            </NavLink>
          </div>
        </div>
      </footer>
    </div>
  )
}
