import {
  AlertTriangle,
  CheckCircle2,
  Info,
  X,
  XCircle,
} from 'lucide-react'
import type { ReactNode } from 'react'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { createPortal } from 'react-dom'

import { cn } from '../lib/cn'

export type ToastTone = 'success' | 'error' | 'info' | 'warning'

export type ToastOptions = {
  title: ReactNode
  description?: ReactNode
  tone?: ToastTone
  duration?: number
}

type ToastItem = ToastOptions & { id: number }

type ToastApi = {
  toast: (options: ToastOptions) => void
  success: (title: ReactNode, description?: ReactNode) => void
  error: (title: ReactNode, description?: ReactNode) => void
  info: (title: ReactNode, description?: ReactNode) => void
  warning: (title: ReactNode, description?: ReactNode) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const toneStyles: Record<ToastTone, string> = {
  success: 'border-emerald-200 bg-emerald-50 text-emerald-900',
  error: 'border-rose-200 bg-rose-50 text-rose-900',
  info: 'border-sky-200 bg-sky-50 text-sky-900',
  warning: 'border-amber-200 bg-amber-50 text-amber-900',
}

const toneIcons = {
  success: CheckCircle2,
  error: XCircle,
  info: Info,
  warning: AlertTriangle,
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const counter = useRef(0)
  const timers = useRef(new Map<number, number>())

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id))
    const timer = timers.current.get(id)
    if (timer) {
      window.clearTimeout(timer)
      timers.current.delete(id)
    }
  }, [])

  const toast = useCallback(
    (options: ToastOptions) => {
      counter.current += 1
      const id = counter.current
      setItems((current) => [...current.slice(-3), { ...options, id }])
      const timer = window.setTimeout(() => {
        setItems((current) => current.filter((item) => item.id !== id))
        timers.current.delete(id)
      }, options.duration ?? 4_500)
      timers.current.set(id, timer)
    },
    [],
  )

  useEffect(() => {
    const pending = timers.current
    return () => {
      for (const timer of pending.values()) window.clearTimeout(timer)
      pending.clear()
    }
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      toast,
      success: (title, description) => toast({ title, description, tone: 'success' }),
      error: (title, description) => toast({ title, description, tone: 'error' }),
      info: (title, description) => toast({ title, description, tone: 'info' }),
      warning: (title, description) =>
        toast({ title, description, tone: 'warning' }),
    }),
    [toast],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      {typeof document !== 'undefined'
        ? createPortal(
            <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(92vw,380px)] flex-col gap-2">
              {items.map((item) => {
                const tone = item.tone ?? 'info'
                const Icon = toneIcons[tone]
                return (
                  <div
                    key={item.id}
                    role={tone === 'error' ? 'alert' : 'status'}
                    className={cn(
                      'pointer-events-auto flex items-start gap-2.5 rounded-lg border p-3 shadow-lg animate-slide-up',
                      toneStyles[tone],
                    )}
                  >
                    <Icon className="mt-0.5 h-4 w-4 shrink-0" />
                    <div className="min-w-0 flex-1 text-xs">
                      <div className="font-semibold">{item.title}</div>
                      {item.description ? (
                        <div className="mt-0.5 break-words opacity-85">
                          {item.description}
                        </div>
                      ) : null}
                    </div>
                    <button
                      type="button"
                      aria-label="关闭通知"
                      onClick={() => dismiss(item.id)}
                      className="-m-1 rounded p-1 opacity-60 hover:opacity-100"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )
              })}
            </div>,
            document.body,
          )
        : null}
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast 必须在 ToastProvider 内使用')
  return context
}
