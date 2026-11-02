import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Loader2 } from 'lucide-react'

import { cn } from '../lib/cn'

export type ButtonVariant =
  | 'primary'
  | 'secondary'
  | 'outline'
  | 'ghost'
  | 'danger'
  | 'subtle'

export type ButtonSize = 'xs' | 'sm' | 'md' | 'icon'

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-indigo-600 text-white shadow-sm hover:bg-indigo-500 active:bg-indigo-700',
  secondary:
    'border border-slate-300 bg-white text-slate-700 shadow-sm hover:bg-slate-50 active:bg-slate-100',
  outline:
    'border border-slate-300 bg-transparent text-slate-700 hover:border-slate-400 hover:bg-slate-50',
  ghost: 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
  danger:
    'bg-rose-600 text-white shadow-sm hover:bg-rose-500 active:bg-rose-700',
  subtle: 'bg-slate-100 text-slate-700 hover:bg-slate-200',
}

const sizeClasses: Record<ButtonSize, string> = {
  xs: 'h-7 gap-1 px-2 text-[11px]',
  sm: 'h-8 gap-1.5 px-2.5 text-xs',
  md: 'h-9 gap-1.5 px-3.5 text-[13px]',
  icon: 'h-8 w-8 p-0',
}

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
}

export function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  icon,
  className,
  children,
  disabled,
  type = 'button',
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex select-none items-center justify-center whitespace-nowrap rounded-md font-medium transition-colors',
        'disabled:pointer-events-none disabled:opacity-50',
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : icon}
      {children}
    </button>
  )
}

export function IconButton({
  label,
  children,
  className,
  ...props
}: ButtonProps & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex h-8 w-8 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900 disabled:pointer-events-none disabled:opacity-40',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
}
