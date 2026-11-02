import type { LucideIcon } from 'lucide-react'
import {
  BookOpenCheck,
  ChevronRight,
  ClipboardList,
  Columns3,
  Download,
  FileSearch,
  Fingerprint,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  ListTree,
  LogOut,
  Mail,
  Menu,
  Plug,
  Settings2,
  Share2,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router'

import { useAuth } from '../lib/auth'
import { cn } from '../lib/cn'
import { IconButton } from '../components/button'

type NavItem = {
  to: string
  label: string
  icon: LucideIcon
  menuKey?: string
  anyOf?: string[]
  end?: boolean
}

type NavGroup = {
  label: string
  items: NavItem[]
}

const GROUPS: NavGroup[] = [
  {
    label: '概览',
    items: [
      {
        to: '/admin',
        label: '控制台',
        icon: LayoutDashboard,
        menuKey: 'admin',
        anyOf: ['identity.user.list'],
        end: true,
      },
      {
        to: '/admin/users',
        label: '用户管理',
        icon: Users,
        menuKey: 'admin/users',
        anyOf: ['identity.user.list'],
      },
    ],
  },
  {
    label: '权限治理',
    items: [
      {
        to: '/admin/iam/roles',
        label: '角色管理',
        icon: ShieldCheck,
        menuKey: 'admin/iam/roles',
        anyOf: ['iam.role.read'],
      },
      {
        to: '/admin/iam/permissions',
        label: '权限目录',
        icon: ListTree,
        menuKey: 'admin/iam/permissions',
        anyOf: ['iam.permission.read'],
      },
      {
        to: '/admin/iam/assignments',
        label: '授权分配',
        icon: KeyRound,
        menuKey: 'admin/iam/assignments',
        anyOf: ['iam.assignment.read'],
      },
      {
        to: '/admin/iam/delegations',
        label: '委派管理',
        icon: Share2,
        menuKey: 'admin/iam/delegations',
        anyOf: ['iam.delegation.read'],
      },
      {
        to: '/admin/iam/constraints',
        label: '职责分离',
        icon: Columns3,
        anyOf: ['iam.constraint.read'],
      },
      {
        to: '/admin/iam/menus',
        label: '菜单投影',
        icon: Menu,
        anyOf: ['iam.menu.read'],
      },
      {
        to: '/admin/iam/explain',
        label: '授权诊断',
        icon: GitBranch,
        anyOf: ['iam.authorization.explain'],
      },
    ],
  },
  {
    label: '审计与数据',
    items: [
      {
        to: '/admin/audits',
        label: '审计日志',
        icon: ClipboardList,
        menuKey: 'admin/audits',
        anyOf: ['audit.read'],
      },
      {
        to: '/admin/exports',
        label: '导出任务',
        icon: Download,
        anyOf: ['identity.user.export', 'audit.export'],
      },
    ],
  },
  {
    label: '系统设置',
    items: [
      {
        to: '/admin/integrations',
        label: '接入服务',
        icon: Plug,
        menuKey: 'admin/integrations',
        anyOf: ['integration.client.read', 'integration.delivery.read'],
      },
      {
        to: '/admin/settings/auth',
        label: '认证配置',
        icon: Settings2,
        menuKey: 'admin/settings/auth',
        anyOf: ['settings.auth.read'],
      },
      {
        to: '/admin/settings/email',
        label: '邮件配置',
        icon: Mail,
        anyOf: ['settings.email.read'],
      },
    ],
  },
]

export function AdminLayout() {
  const { user, menuKeys, canAny, signOut } = useAuth()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    setMobileOpen(false)
  }, [location.pathname])

  useEffect(() => {
    if (!mobileOpen) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [mobileOpen])

  const groups = useMemo(
    () =>
      GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          const menuVisible = item.menuKey
            ? menuKeys.has(item.menuKey)
            : false
          return menuVisible || (item.anyOf ? canAny(item.anyOf) : false)
        }),
      })).filter((group) => group.items.length > 0),
    [menuKeys, canAny],
  )

  const sidebar = (
    <>
      <div className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-white/10 px-4">
        <NavLink to="/admin" className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-indigo-500 text-white">
            <Fingerprint className="h-4 w-4" />
          </span>
          <span className="leading-tight">
            <span className="block text-sm font-semibold text-white">
              用户中心
            </span>
            <span className="block text-[10px] text-slate-400">
              管理控制台
            </span>
          </span>
        </NavLink>
        <IconButton
          label="关闭菜单"
          onClick={() => setMobileOpen(false)}
          className="text-slate-400 hover:bg-white/10 hover:text-white lg:hidden"
        >
          <X className="h-4 w-4" />
        </IconButton>
      </div>

      <nav className="min-h-0 flex-1 space-y-4 overflow-y-auto px-2.5 py-3">
        {groups.map((group) => (
          <div key={group.label}>
            <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium transition-colors',
                      isActive
                        ? 'bg-white/10 text-white'
                        : 'text-slate-400 hover:bg-white/5 hover:text-slate-100',
                    )
                  }
                >
                  <item.icon className="h-3.5 w-3.5 shrink-0" />
                  <span className="flex-1 truncate">{item.label}</span>
                  <ChevronRight className="h-3 w-3 opacity-40" />
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="shrink-0 border-t border-white/10 p-3">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-slate-700 text-xs font-semibold text-white">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </span>
          <div className="min-w-0 flex-1 leading-tight">
            <div className="truncate text-xs font-medium text-white">
              {user?.display_name || user?.username}
            </div>
            <div className="truncate text-[10px] text-slate-400">
              @{user?.username}
            </div>
          </div>
        </div>
        <div className="mt-2 grid grid-cols-2 gap-1">
          <NavLink
            to="/account"
            className="flex items-center justify-center gap-1 rounded-md bg-white/5 px-2 py-1.5 text-[11px] text-slate-300 hover:bg-white/10 hover:text-white"
          >
            <BookOpenCheck className="h-3 w-3" />
            账号中心
          </NavLink>
          <button
            type="button"
            onClick={() => void signOut()}
            className="flex items-center justify-center gap-1 rounded-md bg-white/5 px-2 py-1.5 text-[11px] text-slate-300 hover:bg-white/10 hover:text-white"
          >
            <LogOut className="h-3 w-3" />
            退出
          </button>
        </div>
      </div>
    </>
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col bg-slate-900 lg:flex">
        {sidebar}
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="absolute inset-0 bg-slate-900/50 backdrop-blur-[1px]"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col bg-slate-900 shadow-2xl">
            {sidebar}
          </aside>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-12 items-center justify-between gap-2 border-b border-slate-200 bg-white/95 px-3 backdrop-blur lg:hidden">
          <div className="flex min-w-0 items-center gap-2">
            <IconButton
              label="打开菜单"
              onClick={() => setMobileOpen(true)}
              className="text-slate-600"
            >
              <Menu className="h-4 w-4" />
            </IconButton>
            <span className="truncate text-sm font-semibold text-slate-900">
              管理控制台
            </span>
          </div>
          <div className="flex items-center gap-1">
            <NavLink
              to="/account"
              className="rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
            >
              账号中心
            </NavLink>
            <IconButton
              label="退出登录"
              onClick={() => void signOut()}
              className="text-slate-500"
            >
              <LogOut className="h-4 w-4" />
            </IconButton>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1440px] flex-1 px-3 py-4 sm:px-4 lg:px-6 lg:py-5">
          <Outlet />
        </main>

        <footer className="border-t border-slate-200 bg-white/50 px-4 py-2.5 text-[10px] text-slate-400">
          <div className="mx-auto flex w-full max-w-[1440px] flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1">
              <FileSearch className="h-3 w-3" />
              所有高风险操作都会写入审计日志
            </span>
            <span>用户中心 · 管理控制台</span>
          </div>
        </footer>
      </div>
    </div>
  )
}
