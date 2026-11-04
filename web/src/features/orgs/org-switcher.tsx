import {
  Building2,
  Check,
  ChevronDown,
  Loader2,
  Plus,
  Settings2,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'

import { cn } from '../../lib/cn'
import { organizationIdFromPath } from './org-utils'
import {
  OrganizationRoleBadge,
  useMyOrganizations,
} from './org-shared'

export function OrganizationSwitcher() {
  const navigate = useNavigate()
  const location = useLocation()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const orgsQuery = useMyOrganizations()
  const items = orgsQuery.data?.items ?? []
  const activeId = organizationIdFromPath(location.pathname)
  const active = items.find((org) => org.id === activeId)

  useEffect(() => {
    setOpen(false)
  }, [location.pathname, location.search])

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const go = (path: string) => {
    setOpen(false)
    navigate(path)
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="切换组织"
        onClick={() => setOpen((current) => !current)}
        className="flex h-8 max-w-44 items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2.5 text-xs font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
      >
        <Building2 className="h-3.5 w-3.5 shrink-0 text-slate-500" />
        <span className="truncate">{active?.name ?? '组织切换'}</span>
        <ChevronDown
          className={cn(
            'h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform',
            open ? 'rotate-180' : undefined,
          )}
        />
      </button>

      {open ? (
        <div
          role="menu"
          className="absolute right-0 z-40 mt-1 w-72 overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xl"
        >
          <div className="flex items-center justify-between gap-2 border-b border-slate-100 px-3 py-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              我的组织
            </span>
            <button
              type="button"
              role="menuitem"
              onClick={() => go('/orgs')}
              className="text-[11px] font-medium text-indigo-700 hover:underline"
            >
              全部组织
            </button>
          </div>

          <div className="max-h-64 overflow-y-auto py-1">
            {orgsQuery.isPending ? (
              <div className="flex items-center gap-1.5 px-3 py-3 text-xs text-slate-500">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                正在加载组织…
              </div>
            ) : orgsQuery.isError ? (
              <div className="px-3 py-3 text-xs text-slate-500">
                组织列表加载失败，请稍后重试。
              </div>
            ) : items.length === 0 ? (
              <div className="px-3 py-3 text-xs text-slate-500">
                还没有加入任何组织。
              </div>
            ) : (
              items.map((org) => {
                const selected = org.id === activeId
                return (
                  <button
                    key={org.id}
                    type="button"
                    role="menuitem"
                    onClick={() => go(`/orgs/${org.id}`)}
                    className={cn(
                      'flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-slate-50',
                      selected ? 'bg-indigo-50/60' : undefined,
                    )}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs font-medium text-slate-800">
                        {org.name || org.code}
                      </span>
                      <span className="block truncate font-mono text-[10px] text-slate-400">
                        {org.code}
                      </span>
                    </span>
                    <OrganizationRoleBadge role={org.role} />
                    {selected ? (
                      <Check className="h-3.5 w-3.5 shrink-0 text-indigo-600" />
                    ) : null}
                  </button>
                )
              })
            )}
          </div>

          <div className="border-t border-slate-100 p-1">
            <button
              type="button"
              role="menuitem"
              onClick={() => go('/orgs?create=1')}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              <Plus className="h-3.5 w-3.5 text-slate-500" />
              创建组织
            </button>
            {activeId ? (
              <button
                type="button"
                role="menuitem"
                onClick={() => go(`/orgs/${activeId}?tab=settings`)}
                className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
              >
                <Settings2 className="h-3.5 w-3.5 text-slate-500" />
                当前组织设置
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  )
}
