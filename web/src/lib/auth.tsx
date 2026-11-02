import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'

import { api } from './api'
import { ApiError, errorMessage, isApiError } from './errors'
import { setUnauthorizedHandler } from './http'
import { isPublicPath, loginPath } from './paths'
import {
  buildMenuKeySet,
  buildPermissionSet,
  hasAdminAccess,
  hasAnyPermission,
  hasPermission,
} from './permissions'
import type { AuthorizationReply, User } from './types'

export type AuthStatus = 'loading' | 'authenticated' | 'anonymous' | 'error'

export type AuthContextValue = {
  status: AuthStatus
  user: User | null
  authorization: AuthorizationReply | null
  permissions: Set<string>
  menuKeys: Set<string>
  can: (operation: string) => boolean
  canAny: (operations: string[]) => boolean
  hasAdmin: boolean
  bootError: string | null
  refresh: (quiet?: boolean) => Promise<void>
  signIn: () => Promise<void>
  signOut: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [user, setUser] = useState<User | null>(null)
  const [authorization, setAuthorization] = useState<AuthorizationReply | null>(
    null,
  )
  const [bootError, setBootError] = useState<string | null>(null)
  const booted = useRef(false)

  const load = useCallback(async (quiet: boolean) => {
    if (!quiet) setStatus('loading')
    try {
      const [nextUser, nextAuthorization] = await Promise.all([
        api.me.get(),
        api.me.authorization(),
      ])
      setUser(nextUser)
      setAuthorization(nextAuthorization)
      setBootError(null)
      setStatus('authenticated')
    } catch (error) {
      if (isApiError(error) && error.status === 401) {
        setUser(null)
        setAuthorization(null)
        setStatus('anonymous')
        setBootError(null)
        return
      }
      if (!quiet) {
        setBootError(errorMessage(error))
        setStatus('error')
      }
    }
  }, [])

  useEffect(() => {
    if (booted.current) return
    booted.current = true
    void load(false)
  }, [load])

  useEffect(() => {
    setUnauthorizedHandler((error: ApiError) => {
      queryClient.clear()
      setUser(null)
      setAuthorization(null)
      setStatus('anonymous')
      const path = window.location.pathname
      if (!isPublicPath(path)) {
        const next = `${path}${window.location.search}`
        navigate(loginPath(next), { replace: true })
      }
      void error
    })
    return () => setUnauthorizedHandler(null)
  }, [navigate, queryClient])

  const signIn = useCallback(async () => {
    queryClient.clear()
    await load(true)
  }, [load, queryClient])

  const signOut = useCallback(async () => {
    try {
      await api.auth.logout()
    } catch {
      // Clearing local state is still correct when the cookie already expired.
    }
    queryClient.clear()
    setUser(null)
    setAuthorization(null)
    setStatus('anonymous')
    navigate('/login', { replace: true })
  }, [navigate, queryClient])

  const permissions = useMemo(
    () => buildPermissionSet(authorization?.permissions),
    [authorization],
  )
  const menuKeys = useMemo(
    () => buildMenuKeySet(authorization?.menu_keys),
    [authorization],
  )

  const can = useCallback(
    (operation: string) => hasPermission(permissions, operation),
    [permissions],
  )
  const canAny = useCallback(
    (operations: string[]) => hasAnyPermission(permissions, operations),
    [permissions],
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      authorization,
      permissions,
      menuKeys,
      can,
      canAny,
      hasAdmin: hasAdminAccess(permissions),
      bootError,
      refresh: (quiet = true) => load(quiet),
      signIn,
      signOut,
    }),
    [
      status,
      user,
      authorization,
      permissions,
      menuKeys,
      can,
      canAny,
      bootError,
      load,
      signIn,
      signOut,
    ],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth 必须在 AuthProvider 内使用')
  }
  return context
}
