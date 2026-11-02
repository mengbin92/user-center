import type { ReactNode } from 'react'

import { cn } from '../lib/cn'
import {
  PERMISSION_STATUS_LABELS,
  RESULT_LABELS,
  ROLE_STATUS_LABELS,
  USER_STATUS_LABELS,
} from '../lib/format'

export type BadgeTone =
  | 'neutral'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'violet'
  | 'outline'

const toneClasses: Record<BadgeTone, string> = {
  neutral: 'border-slate-200 bg-slate-100 text-slate-600',
  success: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  warning: 'border-amber-200 bg-amber-50 text-amber-700',
  danger: 'border-rose-200 bg-rose-50 text-rose-700',
  info: 'border-sky-200 bg-sky-50 text-sky-700',
  violet: 'border-violet-200 bg-violet-50 text-violet-700',
  outline: 'border-slate-300 bg-white text-slate-600',
}

export function Badge({
  tone = 'neutral',
  children,
  className,
  dot,
}: {
  tone?: BadgeTone
  children: ReactNode
  className?: string
  dot?: boolean
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium leading-4',
        toneClasses[tone],
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" /> : null}
      {children}
    </span>
  )
}

const statusTones: Record<string, BadgeTone> = {
  enabled: 'success',
  disabled: 'warning',
  archived: 'neutral',
  active: 'success',
  allow: 'success',
  deny: 'danger',
  success: 'success',
  failure: 'danger',
  denied: 'warning',
  ready: 'success',
  pending: 'warning',
  failed: 'danger',
  running: 'info',
  bound: 'success',
  unbound: 'neutral',
  low: 'neutral',
  medium: 'info',
  high: 'warning',
  critical: 'danger',
}

const statusLabels: Record<string, string> = {
  ...USER_STATUS_LABELS,
  ...ROLE_STATUS_LABELS,
  ...PERMISSION_STATUS_LABELS,
  ...RESULT_LABELS,
  bound: '已绑定',
  unbound: '未绑定',
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重',
  ready: '可下载',
  pending: '生成中',
  running: '生成中',
  failed: '失败',
}

export function StatusBadge({
  status,
  label,
}: {
  status?: string | null
  label?: ReactNode
}) {
  const value = status || 'unknown'
  return (
    <Badge tone={statusTones[value] ?? 'neutral'} dot>
      {label ?? statusLabels[value] ?? value}
    </Badge>
  )
}

export function RiskBadge({ level }: { level?: string | null }) {
  return <StatusBadge status={level} />
}
