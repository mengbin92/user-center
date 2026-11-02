import { RefreshCw } from 'lucide-react'
import type { ReactNode } from 'react'
import { createContext, useCallback, useContext, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { useAuth } from '../lib/auth'
import { Button } from './button'
import { Dialog } from './dialog'
import { InlineAlert } from './card'
import { useToast } from './toast'

export type ConflictInfo = {
  title?: string
  message: string
  currentRevision?: string
  currentPolicyRevision?: string
  conflictType?: string
}

type ConflictContextValue = {
  showConflict: (info: ConflictInfo) => void
}

const ConflictContext = createContext<ConflictContextValue | null>(null)

export function ConflictProvider({ children }: { children: ReactNode }) {
  const [info, setInfo] = useState<ConflictInfo | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const queryClient = useQueryClient()
  const { refresh } = useAuth()
  const toast = useToast()

  const showConflict = useCallback((next: ConflictInfo) => {
    setInfo(next)
  }, [])

  const refreshAll = async () => {
    setRefreshing(true)
    try {
      await queryClient.invalidateQueries()
      await refresh(true)
      setInfo(null)
      toast.info('数据已刷新', '请重新核对最新版本后再提交变更。')
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <ConflictContext.Provider value={{ showConflict }}>
      {children}
      <Dialog
        open={info !== null}
        onClose={() => setInfo(null)}
        title={info?.title ?? '数据已被其他人更新'}
        description="乐观并发校验失败。为避免覆盖他人的变更，请刷新后重新提交。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setInfo(null)}
              disabled={refreshing}
            >
              稍后处理
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => void refreshAll()}
              loading={refreshing}
              icon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              刷新最新数据
            </Button>
          </>
        }
      >
        <InlineAlert tone="warning" title="版本冲突">
          {info?.message}
        </InlineAlert>
        <dl className="grid grid-cols-1 gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs sm:grid-cols-2">
          <div>
            <dt className="text-slate-500">目标数据最新 revision</dt>
            <dd className="font-mono text-slate-800">
              {info?.currentRevision ?? '—'}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">授权策略最新 revision</dt>
            <dd className="font-mono text-slate-800">
              {info?.currentPolicyRevision ?? '—'}
            </dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-slate-500">冲突类型</dt>
            <dd className="font-mono text-slate-800">
              {info?.conflictType ?? 'target'}
            </dd>
          </div>
        </dl>
      </Dialog>
    </ConflictContext.Provider>
  )
}

export function useConflict(): ConflictContextValue {
  const context = useContext(ConflictContext)
  if (!context) throw new Error('useConflict 必须在 ConflictProvider 内使用')
  return context
}
