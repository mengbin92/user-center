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
import { useToast } from '../components/toast'
import { ApiError, errorMessage, isApiError } from './errors'
import { invalidateHttpSession, setUnauthorizedHandler } from './http'
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
  sessionGeneration: number
  getSessionGeneration: () => number
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
  const toast = useToast()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [user, setUser] = useState<User | null>(null)
  const [authorization, setAuthorization] = useState<AuthorizationReply | null>(
    null,
  )
  const [bootError, setBootError] = useState<string | null>(null)
  const requestGeneration = useRef(0)
  const currentGeneration = useRef(0)
  const authorizationSnapshot = useRef<string | null>(null)
  const [sessionGeneration, setSessionGeneration] = useState(0)
  const channel = useRef<BroadcastChannel | null>(null)

  const getSessionGeneration = useCallback(() => currentGeneration.current, [])
  const resetSession = useCallback(() => {
    requestGeneration.current += 1
    invalidateHttpSession()
    currentGeneration.current += 1
    setSessionGeneration(currentGeneration.current)
    void queryClient.cancelQueries()
    queryClient.clear()
    setUser(null)
    setAuthorization(null)
    authorizationSnapshot.current = null
  }, [queryClient])

  const load = useCallback(async (quiet: boolean) => {
    const request = ++requestGeneration.current
    if (!quiet) setStatus('loading')
    try {
      const [nextUser, nextAuthorization] = await Promise.all([
        api.me.get(),
        api.me.authorization(),
      ])
      if (request !== requestGeneration.current) return
      const snapshot = JSON.stringify([nextUser.id, nextAuthorization])
      if (authorizationSnapshot.current !== null && authorizationSnapshot.current !== snapshot) {
        void queryClient.cancelQueries()
        queryClient.clear()
      }
      authorizationSnapshot.current = snapshot
      setUser(nextUser)
      setAuthorization(nextAuthorization)
      setBootError(null)
      setStatus('authenticated')
    } catch (error) {
      if (request !== requestGeneration.current) return
      resetSession()
      if (isApiError(error) && error.status === 401) {
        setUser(null)
        setAuthorization(null)
        setStatus('anonymous')
        setBootError(null)
        return
      }
      setBootError(errorMessage(error))
      setStatus('error')
    }
  }, [queryClient, resetSession])

  useEffect(() => {
    void load(false)
    return () => { requestGeneration.current += 1 }
  }, [load])

  useEffect(() => {
    setUnauthorizedHandler((error: ApiError) => {
      resetSession()
      setStatus('anonymous')
      channel.current?.postMessage({ type: 'logout' })
      const path = window.location.pathname
      if (!isPublicPath(path)) {
        const next = `${path}${window.location.search}`
        navigate(loginPath(next), { replace: true })
      }
      void error
    })
    return () => setUnauthorizedHandler(null)
  }, [navigate, resetSession])

  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') return
    const connection = new BroadcastChannel('user-center-auth')
    channel.current = connection
    connection.onmessage = (event: MessageEvent<unknown>) => {
      const message = event.data as { type?: string } | null
      if (!message || !['logout', 'session', 'authorization'].includes(message.type ?? '')) return
      resetSession()
      setBootError(null)
      if (message.type === 'logout') {
        setStatus('anonymous')
      } else {
        void load(false)
      }
    }
    return () => {
      connection.close()
      channel.current = null
    }
  }, [load, resetSession])

  const signIn = useCallback(async () => {
    resetSession()
    await load(false)
    channel.current?.postMessage({ type: 'session' })
  }, [load, resetSession])

  const signOut = useCallback(async () => {
    // Invalidate in-flight reads before waiting for the logout request.
    resetSession()
    const generation = getSessionGeneration()
    setStatus('loading')
    try {
      await api.auth.logout()
    } catch (error) {
      if (generation !== getSessionGeneration()) return
      if (!isApiError(error) || error.status !== 401) {
        await load(false)
        toast.error('退出失败', `${errorMessage(error)}。当前会话尚未撤销，请重试退出。`)
        return
      }
    }
    if (generation !== getSessionGeneration()) return
    setStatus('anonymous')
    setBootError(null)
    channel.current?.postMessage({ type: 'logout' })
    navigate('/login', { replace: true })
  }, [getSessionGeneration, load, navigate, resetSession, toast])

  const refresh = useCallback(async (quiet = true) => {
    await load(quiet)
    channel.current?.postMessage({ type: 'authorization' })
  }, [load])

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
      sessionGeneration,
      getSessionGeneration,
      user,
      authorization,
      permissions,
      menuKeys,
      can,
      canAny,
      hasAdmin: hasAdminAccess(permissions),
      bootError,
      refresh,
      signIn,
      signOut,
    }),
    [
      status,
      sessionGeneration,
      getSessionGeneration,
      user,
      authorization,
      permissions,
      menuKeys,
      can,
      canAny,
      bootError,
      refresh,
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
