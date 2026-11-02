import {
  useMutation,
  useQueryClient,
  type QueryKey,
} from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { useAuth } from './auth'
import { errorMessage, isApiError, type ApiError } from './errors'
import { useConflict } from '../components/conflict'
import { useStepUp } from '../components/step-up'
import { useToast } from '../components/toast'

export type UseApiMutationOptions<TData, TVariables> = {
  mutationFn: (variables: TVariables) => Promise<TData>
  successMessage?:
    | ReactNode
    | ((data: TData, variables: TVariables) => ReactNode)
  successDescription?: ReactNode
  invalidate?: QueryKey[]
  refreshAuth?: boolean
  stepUpRetry?: boolean
  onSuccess?: (data: TData, variables: TVariables) => void | Promise<void>
  onError?: (error: ApiError) => void
}

export function useApiMutation<TData, TVariables>(
  options: UseApiMutationOptions<TData, TVariables>,
) {
  const queryClient = useQueryClient()
  const toast = useToast()
  const { requestStepUp } = useStepUp()
  const { showConflict } = useConflict()
  const { refresh } = useAuth()

  return useMutation<TData, unknown, TVariables>({
    mutationFn: async (variables: TVariables) => {
      try {
        return await options.mutationFn(variables)
      } catch (error) {
        if (
          options.stepUpRetry !== false &&
          isApiError(error) &&
          error.isStepUpRequired
        ) {
          const verified = await requestStepUp()
          if (verified) {
            return await options.mutationFn(variables)
          }
        }
        throw error
      }
    },
    onSuccess: async (data, variables) => {
      if (options.invalidate?.length) {
        await Promise.all(
          options.invalidate.map((queryKey) =>
            queryClient.invalidateQueries({ queryKey }),
          ),
        )
      }
      if (options.refreshAuth) {
        await refresh(true)
      }
      if (options.successMessage) {
        const message =
          typeof options.successMessage === 'function'
            ? options.successMessage(data, variables)
            : options.successMessage
        toast.success(message, options.successDescription)
      }
      await options.onSuccess?.(data, variables)
    },
    onError: (error) => {
      if (!isApiError(error)) {
        toast.error('操作失败', '发生未知错误，请稍后重试')
        return
      }

      const message = errorMessage(error)

      if (error.status === 409) {
        if (
          error.currentRevision ||
          error.currentPolicyRevision ||
          error.reason === 'POLICY_CONFLICT' ||
          error.reason === 'REVISION_CONFLICT'
        ) {
          showConflict({
            message: error.message,
            currentRevision: error.currentRevision,
            currentPolicyRevision: error.currentPolicyRevision,
            conflictType: error.conflictType,
          })
        } else {
          toast.error('数据冲突', message)
        }
      } else if (error.status === 429) {
        toast.warning('请求过于频繁', `${message}，请等待一段时间后重试。`)
      } else if (error.status === 403 && error.isStepUpRequired) {
        toast.info('需要安全验证', '未完成近期安全验证，操作尚未执行。')
      } else if (error.status === 403) {
        toast.error('没有操作权限', message)
      } else if (error.status === 401) {
        toast.warning('登录状态已失效', '请重新登录后再操作。')
      } else if (error.status === 400) {
        toast.error('请求不合法', message)
      } else if (error.status === 404) {
        toast.error('资源不存在', message)
      } else if (error.status === 0) {
        toast.error('网络错误', message)
      } else {
        toast.error('操作失败', message)
      }

      options.onError?.(error)
    },
  })
}
