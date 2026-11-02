import type { UseQueryResult } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  Loader2,
  RefreshCw,
  ShieldX,
  WifiOff,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router'

import { isApiError, reasonMessage, type ApiError } from '../lib/errors'
import { cn } from '../lib/cn'
import { Button } from './button'
import { Card } from './card'

type QueryLike = Pick<
  UseQueryResult<unknown>,
  'isPending' | 'isError' | 'error' | 'refetch'
>

export function QueryBoundary({
  query,
  children,
  loadingLabel,
  className,
}: {
  query: QueryLike
  children: ReactNode
  loadingLabel?: string
  className?: string
}) {
  if (query.isPending) {
    return (
      <div
        className={cn(
          'flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-6 py-16 text-xs text-slate-500',
          className,
        )}
      >
        <Loader2 className="h-4 w-4 animate-spin text-indigo-500" />
        {loadingLabel ?? '正在加载…'}
      </div>
    )
  }
  if (query.isError) {
    return (
      <ErrorPanel
        error={query.error}
        onRetry={() => {
          void query.refetch()
        }}
        className={className}
      />
    )
  }
  return <>{children}</>
}

export function ErrorPanel({
  error,
  onRetry,
  className,
  compact = false,
}: {
  error: unknown
  onRetry?: () => void
  className?: string
  compact?: boolean
}) {
  const navigate = useNavigate()
  const apiError: ApiError | null = isApiError(error) ? error : null
  const status = apiError?.status ?? 0

  let title = '加载失败'
  let description =
    apiError?.message ??
    (error instanceof Error ? error.message : '发生未知错误，请稍后重试')
  let icon = <AlertTriangle className="h-5 w-5" />
  let tone = 'border-amber-200 bg-amber-50 text-amber-700'

  if (status === 403) {
    title = '无访问权限'
    const mappedReason = reasonMessage(apiError?.reason)
    description =
      apiError?.reason === 'STEP_UP_REQUIRED'
        ? '该操作需要近期安全验证。请先在安全中心完成验证，再重试。'
        : (mappedReason ??
          `当前账号未被授予此功能的权限${apiError?.reason ? `（${apiError.reason}）` : ''}。请联系管理员调整角色或数据范围，页面不会展示空数据来掩盖权限问题。`)
    icon = <ShieldX className="h-5 w-5" />
    tone = 'border-rose-200 bg-rose-50 text-rose-700'
  } else if (status === 401) {
    title = '登录状态已失效'
    description = '请重新登录后继续操作。'
  } else if (status === 404) {
    title = '资源不存在'
    description = apiError?.message ?? '请求的资源可能已被删除或归档。'
  } else if (status === 409) {
    title = '数据冲突'
    description =
      apiError?.message ?? '数据已被其他人更新，请刷新页面后重试。'
  } else if (status === 429) {
    title = '请求过于频繁'
    description = `${apiError?.message ?? '请稍后重试'}。系统已触发限流，请等待一段时间后再次操作。`
  } else if (status === 0) {
    title = '无法连接服务器'
    description = apiError?.message ?? '请确认后端服务已启动。'
    icon = <WifiOff className="h-5 w-5" />
  }

  return (
    <Card className={cn('overflow-hidden', className)}>
      <div className={cn('flex flex-col items-center gap-3 px-6 text-center', compact ? 'py-8' : 'py-14')}>
        <span className={cn('rounded-full border p-2.5', tone)}>{icon}</span>
        <div>
          <div className="text-sm font-semibold text-slate-900">{title}</div>
          <p className="mx-auto mt-1 max-w-md text-xs text-slate-500">
            {description}
          </p>
          {apiError?.requestId ? (
            <p className="mt-1 font-mono text-[10px] text-slate-400">
              request_id: {apiError.requestId}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center justify-center gap-2">
          {onRetry ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={onRetry}
              icon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              重试
            </Button>
          ) : null}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => navigate(-1)}
            icon={<ArrowLeft className="h-3.5 w-3.5" />}
          >
            返回上一页
          </Button>
        </div>
      </div>
    </Card>
  )
}

export function PermissionDenied({
  title = '无权访问此页面',
  description,
  required,
  backTo = '/account',
}: {
  title?: string
  description?: string
  required?: string
  backTo?: string
}) {
  const navigate = useNavigate()
  return (
    <div className="mx-auto flex max-w-xl flex-col items-center gap-4 rounded-xl border border-slate-200 bg-white px-6 py-14 text-center shadow-panel">
      <span className="rounded-full border border-rose-200 bg-rose-50 p-3 text-rose-600">
        <ShieldX className="h-5 w-5" />
      </span>
      <div>
        <h2 className="text-base font-semibold text-slate-900">{title}</h2>
        <p className="mt-1 text-xs text-slate-500">
          {description ??
            '当前账号的权限投影中没有访问该页面所需的操作权限。请联系管理员授予角色，或切换到具备权限的会话角色。'}
        </p>
        {required ? (
          <p className="mt-2 inline-block rounded bg-slate-100 px-2 py-1 font-mono text-[11px] text-slate-600">
            需要权限：{required}
          </p>
        ) : null}
      </div>
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="secondary"
          onClick={() => navigate(backTo)}
        >
          返回
        </Button>
        <Button
          size="sm"
          onClick={() => navigate('/account/roles')}
        >
          切换会话角色
        </Button>
      </div>
    </div>
  )
}
