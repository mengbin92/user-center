import { useQuery } from '@tanstack/react-query'

import { api } from './api'

/**
 * Security status is shared between the account layout, the security page and
 * the admin guard. React Query deduplicates the request and keeps the
 * password-change gate consistent across navigation.
 */
export function useSecurityStatus(options?: {
  enabled?: boolean
  staleTime?: number
}) {
  return useQuery({
    queryKey: ['me', 'security'],
    queryFn: () => api.me.security(),
    enabled: options?.enabled ?? true,
    retry: false,
    staleTime: options?.staleTime ?? 10_000,
  })
}
