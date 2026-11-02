import { QueryClient } from '@tanstack/react-query'

import { ApiError } from './errors'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error instanceof ApiError) {
          if ([400, 401, 403, 404, 409, 429].includes(error.status)) return false
        }
        return failureCount < 1
      },
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
    mutations: {
      retry: false,
    },
  },
})
