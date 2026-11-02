import type { LucideIcon } from 'lucide-react'
import { Inbox, Loader2, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'

import { cn } from '../lib/cn'

export function Card({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <section
      className={cn(
        'rounded-xl border border-slate-200 bg-white shadow-panel',
        className,
      )}
    >
      {children}
    </section>
  )
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-4 py-3',
        className,
      )}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
        {description ? (
          <p className="mt-0.5 text-xs text-slate-500">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  )
}

export function CardContent({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return <div className={cn('p-4', className)}>{children}</div>
}

export function CardFooter({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-end gap-2 rounded-b-xl border-t border-slate-100 bg-slate-50/60 px-4 py-2.5',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  eyebrow?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        {eyebrow ? (
          <div className="mb-0.5 text-[11px] font-medium uppercase tracking-wider text-indigo-600">
            {eyebrow}
          </div>
        ) : null}
        <h1 className="text-lg font-semibold tracking-tight text-slate-900">
          {title}
        </h1>
        {description ? (
          <p className="mt-0.5 max-w-2xl text-xs text-slate-500">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  )
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = 'indigo',
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
  icon?: LucideIcon
  tone?: 'indigo' | 'emerald' | 'amber' | 'rose' | 'slate' | 'violet'
}) {
  const toneClasses = {
    indigo: 'bg-indigo-50 text-indigo-600',
    emerald: 'bg-emerald-50 text-emerald-600',
    amber: 'bg-amber-50 text-amber-600',
    rose: 'bg-rose-50 text-rose-600',
    slate: 'bg-slate-100 text-slate-600',
    violet: 'bg-violet-50 text-violet-600',
  }[tone]

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="text-xs font-medium text-slate-500">{label}</div>
        {Icon ? (
          <span className={cn('rounded-md p-1.5', toneClasses)}>
            <Icon className="h-3.5 w-3.5" />
          </span>
        ) : null}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums tracking-tight text-slate-900">
        {value}
      </div>
      {hint ? <div className="mt-1 text-[11px] text-slate-500">{hint}</div> : null}
    </Card>
  )
}

export function EmptyState({
  title,
  description,
  action,
  icon: Icon = Inbox,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  action?: ReactNode
  icon?: LucideIcon
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 px-6 py-10 text-center',
        className,
      )}
    >
      <span className="rounded-full bg-slate-100 p-2.5 text-slate-400">
        <Icon className="h-5 w-5" />
      </span>
      <div className="text-sm font-medium text-slate-700">{title}</div>
      {description ? (
        <p className="max-w-sm text-xs text-slate-500">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  )
}

export function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 px-6 py-12 text-xs text-slate-500">
      <Loader2 className="h-4 w-4 animate-spin text-indigo-500" />
      {label}
    </div>
  )
}

export function InlineAlert({
  tone = 'warning',
  title,
  children,
  icon: Icon = TriangleAlert,
}: {
  tone?: 'info' | 'warning' | 'danger' | 'success'
  title?: ReactNode
  children?: ReactNode
  icon?: LucideIcon
}) {
  const classes = {
    info: 'border-sky-200 bg-sky-50 text-sky-800',
    warning: 'border-amber-200 bg-amber-50 text-amber-800',
    danger: 'border-rose-200 bg-rose-50 text-rose-800',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  }[tone]

  return (
    <div className={cn('flex gap-2 rounded-md border px-3 py-2', classes)}>
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <div className="min-w-0 text-xs">
        {title ? <div className="font-medium">{title}</div> : null}
        {children ? <div className="opacity-90">{children}</div> : null}
      </div>
    </div>
  )
}
