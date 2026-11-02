import { cn } from '../lib/cn'

export type TabItem = {
  key: string
  label: string
  count?: number
}

export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: TabItem[]
  value: string
  onChange: (key: string) => void
  className?: string
}) {
  return (
    <div
      role="tablist"
      className={cn(
        'flex gap-1 overflow-x-auto border-b border-slate-200',
        className,
      )}
    >
      {tabs.map((tab) => {
        const active = tab.key === value
        return (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(tab.key)}
            className={cn(
              '-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition-colors',
              active
                ? 'border-indigo-600 text-indigo-700'
                : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800',
            )}
          >
            {tab.label}
            {typeof tab.count === 'number' ? (
              <span
                className={cn(
                  'rounded-full px-1.5 py-0.5 text-[10px] tabular-nums',
                  active
                    ? 'bg-indigo-100 text-indigo-700'
                    : 'bg-slate-100 text-slate-500',
                )}
              >
                {tab.count}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}
