import type { ReactNode } from 'react'
import { QueryClientProvider } from '@tanstack/react-query'

import { AuthProvider } from '../lib/auth'
import { queryClient } from '../lib/query'
import { ConflictProvider } from '../components/conflict'
import { StepUpProvider } from '../components/step-up'
import { ToastProvider } from '../components/toast'

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <StepUpProvider>
            <ConflictProvider>{children}</ConflictProvider>
          </StepUpProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  )
}
