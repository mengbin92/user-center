import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios'
import { afterEach, describe, expect, it } from 'vitest'

import {
  CSRF_COOKIE,
  CSRF_HEADER,
  REQUEST_ID_HEADER,
  createHttpClient,
} from './http'

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function createCaptureClient() {
  const captured: InternalAxiosRequestConfig[] = []
  const adapter: AxiosAdapter = async (config) => {
    captured.push(config)
    return {
      data: { ok: true },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }
  }
  const client = createHttpClient({ adapter, baseURL: '' })
  return { client, captured }
}

describe('CSRF and request id client', () => {
  afterEach(() => {
    document.cookie = `${CSRF_COOKIE}=; Max-Age=0; path=/`
  })

  it('sends X-CSRF-Token from the uc_csrf cookie and a unique X-Request-ID on writes', async () => {
    document.cookie = `${CSRF_COOKIE}=token-from-cookie; path=/`
    const { client, captured } = createCaptureClient()

    await client.post('/api/v1/me/password:change', { new_password: 'secret' })

    expect(captured).toHaveLength(1)
    const config = captured[0]
    expect(config.method).toBe('post')
    expect(config.headers.get(CSRF_HEADER)).toBe('token-from-cookie')
    expect(config.headers.get(REQUEST_ID_HEADER)).toMatch(UUID_PATTERN)
  })

  it('does not require a CSRF token for safe GET requests but still sends a request id', async () => {
    const { client, captured } = createCaptureClient()

    await client.get('/api/v1/me')

    const first = captured[0]
    await client.get('/api/v1/me')
    const second = captured[1]

    expect(first.method).toBe('get')
    expect(first.headers.get(CSRF_HEADER)).toBeFalsy()
    expect(first.headers.get(REQUEST_ID_HEADER)).toMatch(UUID_PATTERN)
    expect(second.headers.get(REQUEST_ID_HEADER)).not.toBe(
      first.headers.get(REQUEST_ID_HEADER),
    )
  })
})
