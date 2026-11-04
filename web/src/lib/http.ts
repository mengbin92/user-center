import axios, {
  isAxiosError,
  type AxiosAdapter,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'

import { ApiError, parseErrorBody } from './errors'

export const CSRF_COOKIE = 'uc_csrf'
export const CSRF_HEADER = 'X-CSRF-Token'
export const REQUEST_ID_HEADER = 'X-Request-ID'

const SAFE_METHODS = new Set(['get', 'head', 'options'])
const AUTH_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/mfa/complete',
  '/api/v1/auth/context',
]

let sessionGeneration = 0
const requestGenerations = new WeakMap<InternalAxiosRequestConfig, number>()

export function invalidateHttpSession(): void {
  sessionGeneration += 1
}

let csrfBootstrap: Promise<string | null> | null = null
let unauthorizedHandler: ((error: ApiError) => void) | null = null

export type UnauthorizedHandler = (error: ApiError) => void

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

export function readCookie(name: string): string | null {
  if (typeof document === 'undefined' || !document.cookie) return null
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const entry = part.trim()
    if (entry.startsWith(prefix)) {
      const raw = entry.slice(prefix.length)
      try {
        return decodeURIComponent(raw)
      } catch {
        return raw
      }
    }
  }
  return null
}

export function newRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `req-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

/**
 * Reads the non-HttpOnly double-submit cookie. When a browser has not visited
 * any API route yet the cookie does not exist, so a safe GET to the public auth
 * context is used to bootstrap it.
 */
export async function ensureCsrfToken(): Promise<string | null> {
  const existing = readCookie(CSRF_COOKIE)
  if (existing) return existing
  if (csrfBootstrap) return csrfBootstrap

  const baseURL = import.meta.env.VITE_API_BASE ?? ''
  csrfBootstrap = fetch(`${baseURL}/api/v1/auth/context`, {
    method: 'GET',
    credentials: 'include',
    headers: { [REQUEST_ID_HEADER]: newRequestId() },
  })
    .then(() => readCookie(CSRF_COOKIE))
    .catch(() => null)
    .finally(() => {
      csrfBootstrap = null
    })

  return csrfBootstrap
}

function isAuthExempt(url: string | undefined): boolean {
  if (!url) return false
  return AUTH_PATHS.some((path) => url.includes(path))
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error

  if (isAxiosError(error)) {
    const response = error.response
    if (response) {
      const body = parseErrorBody(response.data)
      const requestId =
        body.metadata?.request_id ||
        (response.headers?.['x-request-id'] as string | undefined)
      return new ApiError({
        status: response.status,
        reason: body.reason,
        message:
          body.message ||
          error.message ||
          `请求失败（HTTP ${response.status}）`,
        metadata: body.metadata,
        requestId,
      })
    }

    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      return new ApiError({
        status: 0,
        reason: 'TIMEOUT',
        message: '请求超时，请稍后重试',
      })
    }

    return new ApiError({
      status: 0,
      reason: 'NETWORK_ERROR',
      message: '无法连接服务器，请检查网络或后端服务是否已启动',
    })
  }

  if (error instanceof Error) {
    return new ApiError({ status: 0, reason: 'UNKNOWN', message: error.message })
  }

  return new ApiError({ status: 0, reason: 'UNKNOWN', message: '未知错误' })
}

export type HttpClientOptions = {
  adapter?: AxiosAdapter
  baseURL?: string
}

export function createHttpClient(options: HttpClientOptions = {}): AxiosInstance {
  const client = axios.create({
    baseURL: options.baseURL ?? import.meta.env.VITE_API_BASE ?? '',
    withCredentials: true,
    timeout: 30_000,
    adapter: options.adapter,
  })

  client.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
    requestGenerations.set(config, sessionGeneration)
    config.headers.set(REQUEST_ID_HEADER, newRequestId())

    const method = (config.method ?? 'get').toLowerCase()
    if (!SAFE_METHODS.has(method)) {
      const token = await ensureCsrfToken()
      if (token) config.headers.set(CSRF_HEADER, token)
    }
    return config
  })

  client.interceptors.response.use(
    (response) => {
      if (requestGenerations.get(response.config) !== sessionGeneration) {
        return Promise.reject(new ApiError({ status: 401, reason: 'SESSION_CHANGED', message: '登录会话已变化，请重新发起请求' }))
      }
      return response
    },
    (error: unknown) => {
      const apiError = toApiError(error)
      const requestURL = isAxiosError(error) ? error.config?.url : undefined

      if (
        apiError.status === 401 &&
        (!isAxiosError(error) || !error.config || requestGenerations.get(error.config) === sessionGeneration) &&
        !isAuthExempt(requestURL) &&
        apiError.reason !== 'INVALID_CREDENTIALS' &&
        apiError.reason !== 'MFA_REQUIRED' &&
        apiError.reason !== 'CHALLENGE_INVALID' &&
        unauthorizedHandler
      ) {
        unauthorizedHandler(apiError)
      }
      return Promise.reject(apiError)
    },
  )

  return client
}

export const http = createHttpClient()
