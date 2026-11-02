import { ChevronLeft, ChevronRight } from 'lucide-react'
import type { ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react'

import { cn } from '../lib/cn'
import { formatNumber } from '../lib/format'
import { Button } from './button'

export function Table({
  children,
  className,
  minWidth = 'min-w-[680px]',
}: {
  children: ReactNode
  className?: string
  minWidth?: string
}) {
  return (
    <div className="w-full overflow-x-auto">
      <table
        className={cn(
          'w-full border-collapse text-left text-[13px]',
          minWidth,
          className,
        )}
      >
        {children}
      </table>
    </div>
  )
}

export function THead({ children }: { children: ReactNode }) {
  return (
    <thead className="bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500">
      {children}
    </thead>
  )
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>
}

export function TR({
  children,
  className,
  onClick,
}: {
  children: ReactNode
  className?: string
  onClick?: () => void
}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        'border-t border-slate-100 transition-colors hover:bg-slate-50/70',
        onClick ? 'cursor-pointer' : undefined,
        className,
      )}
    >
      {children}
    </tr>
  )
}

export function TH({
  children,
  className,
  ...props
}: ThHTMLAttributes<HTMLTableCellElement> & { children?: ReactNode }) {
  return (
    <th
      className={cn('whitespace-nowrap px-3 py-2 font-medium', className)}
      {...props}
    >
      {children}
    </th>
  )
}

export function TD({
  children,
  className,
  ...props
}: TdHTMLAttributes<HTMLTableCellElement> & { children?: ReactNode }) {
  return (
    <td className={cn('px-3 py-2.5 align-middle', className)} {...props}>
      {children}
    </td>
  )
}

export function TableEmpty({
  colSpan,
  children,
}: {
  colSpan: number
  children: ReactNode
}) {
  return (
    <tr className="border-t border-slate-100">
      <td colSpan={colSpan} className="px-3 py-10 text-center text-xs text-slate-500">
        {children}
      </td>
    </tr>
  )
}

export function Pagination({
  total,
  pageIndex,
  hasNext,
  onPrev,
  onNext,
  onRefresh,
  loading,
}: {
  total?: string | number
  pageIndex: number
  hasNext: boolean
  onPrev: () => void
  onNext: () => void
  onRefresh?: () => void
  loading?: boolean
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 px-3 py-2">
      <div className="text-[11px] text-slate-500">
        共 <span className="font-medium tabular-nums text-slate-700">{formatNumber(total)}</span> 条
        {pageIndex > 1 ? ` · 第 ${pageIndex} 页` : null}
        {loading ? ' · 更新中…' : null}
      </div>
      <div className="flex items-center gap-1">
        {onRefresh ? (
          <Button variant="ghost" size="xs" onClick={onRefresh}>
            刷新
          </Button>
        ) : null}
        <Button
          variant="secondary"
          size="xs"
          onClick={onPrev}
          disabled={pageIndex <= 1 || loading}
          icon={<ChevronLeft className="h-3.5 w-3.5" />}
        >
          上一页
        </Button>
        <Button
          variant="secondary"
          size="xs"
          onClick={onNext}
          disabled={!hasNext || loading}
        >
          下一页
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}
