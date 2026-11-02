import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'
import { useId } from 'react'

import { cn } from '../lib/cn'

const controlClasses =
  'w-full rounded-md border border-slate-300 bg-white text-[13px] text-slate-800 shadow-sm transition-colors placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-500 aria-[invalid=true]:border-rose-400 aria-[invalid=true]:focus:ring-rose-100'

export type FieldProps = {
  label?: ReactNode
  htmlFor?: string
  hint?: ReactNode
  error?: ReactNode
  required?: boolean
  className?: string
  children: ReactNode
}

export function Field({
  label,
  htmlFor,
  hint,
  error,
  required,
  className,
  children,
}: FieldProps) {
  return (
    <div className={cn('space-y-1.5', className)}>
      {label ? (
        <label
          htmlFor={htmlFor}
          className="flex items-center gap-1 text-xs font-medium text-slate-700"
        >
          {label}
          {required ? <span className="text-rose-500">*</span> : null}
        </label>
      ) : null}
      {children}
      {error ? (
        <p className="text-[11px] text-rose-600" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-[11px] text-slate-500">{hint}</p>
      ) : null}
    </div>
  )
}

export type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  invalid?: boolean
}

export function Input({ className, invalid, ...props }: InputProps) {
  return (
    <input
      aria-invalid={invalid || undefined}
      className={cn(controlClasses, 'h-9 px-3', className)}
      {...props}
    />
  )
}

export type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  invalid?: boolean
}

export function Textarea({ className, invalid, ...props }: TextareaProps) {
  return (
    <textarea
      aria-invalid={invalid || undefined}
      className={cn(controlClasses, 'min-h-20 px-3 py-2', className)}
      {...props}
    />
  )
}

export type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & {
  invalid?: boolean
}

export function Select({ className, invalid, children, ...props }: SelectProps) {
  return (
    <select
      aria-invalid={invalid || undefined}
      className={cn(controlClasses, 'h-9 px-2.5', className)}
      {...props}
    >
      {children}
    </select>
  )
}

export type CheckboxProps = InputHTMLAttributes<HTMLInputElement> & {
  label?: ReactNode
}

export function Checkbox({ label, className, ...props }: CheckboxProps) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-[13px] text-slate-700">
      <input
        type="checkbox"
        className={cn(
          'h-4 w-4 rounded border-slate-300 accent-indigo-600',
          className,
        )}
        {...props}
      />
      {label}
    </label>
  )
}

export type SwitchProps = {
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  disabled?: boolean
  label?: string
  id?: string
}

export function Switch({
  checked,
  onCheckedChange,
  disabled,
  label,
  id,
}: SwitchProps) {
  const generatedId = useId()
  const switchId = id ?? generatedId
  return (
    <div className="flex items-center gap-2">
      <button
        id={switchId}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onCheckedChange(!checked)}
        className={cn(
          'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50',
          checked ? 'bg-indigo-600' : 'bg-slate-300',
        )}
      >
        <span
          className={cn(
            'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform',
            checked ? 'translate-x-[18px]' : 'translate-x-0.5',
          )}
        />
      </button>
      {label ? (
        <label htmlFor={switchId} className="text-[13px] text-slate-700">
          {label}
        </label>
      ) : null}
    </div>
  )
}
