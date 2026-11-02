import { ShieldAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect, useId, useState } from 'react'

import { Dialog } from './dialog'
import { Button } from './button'
import { Field, Textarea } from './input'

export function ReasonDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = '确认执行',
  cancelLabel = '取消',
  tone = 'primary',
  requireReason = true,
  busy = false,
  error,
  minLength = 2,
  hint,
  children,
}: {
  open: boolean
  onClose: () => void
  onConfirm: (reason: string) => void
  title: ReactNode
  description?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  tone?: 'primary' | 'danger'
  requireReason?: boolean
  busy?: boolean
  error?: string | null
  minLength?: number
  hint?: ReactNode
  children?: ReactNode
}) {
  const [reason, setReason] = useState('')
  const fieldId = useId()

  useEffect(() => {
    if (open) setReason('')
  }, [open])

  const valid = !requireReason || reason.trim().length >= minLength

  const submit = () => {
    if (!valid || busy) return
    onConfirm(reason.trim())
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      size="md"
      dismissible={!busy}
      bodyClassName="space-y-3"
      footer={
        <>
          <Button variant="secondary" size="sm" onClick={onClose} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button
            variant={tone === 'danger' ? 'danger' : 'primary'}
            size="sm"
            onClick={submit}
            loading={busy}
            disabled={!valid}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children}
      {requireReason ? (
        <Field
          label="操作原因"
          htmlFor={fieldId}
          required
          hint={
            hint ??
            `请说明操作原因（至少 ${minLength} 个字符），原因会写入不可篡改的审计日志。`
          }
          error={reason.length > 0 && !valid ? `原因至少需要 ${minLength} 个字符` : undefined}
        >
          <Textarea
            id={fieldId}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="例如：员工离职，按工单 SEC-1024 归档账号"
            rows={3}
            invalid={reason.length > 0 && !valid}
          />
        </Field>
      ) : null}
      {error ? (
        <div className="flex items-start gap-2 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}
    </Dialog>
  )
}
