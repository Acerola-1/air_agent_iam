import type { ErrorBody } from './types'

// 浏览器唯一 API 通道：同源相对路径 + HttpOnly cookie 会话。
// 不读取、不存储、不拼接待 Bearer/内部凭据；写请求附双重提交 CSRF。
const CSRF_COOKIE_CANDIDATES = ['air_iam_dev_csrf', '__Host-air_iam_csrf']
const CSRF_HEADER = 'X-CSRF-Token'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId: string | null

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
  }

  get contextChanged(): boolean {
    return this.status === 409
  }

  get unauthenticated(): boolean {
    return this.status === 401
  }

  get dependencyUnavailable(): boolean {
    return this.status === 503
  }
}

function readCookie(name: string): string | null {
  const prefix = `${name}=`
  const segment = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
  return segment ? decodeURIComponent(segment.slice(prefix.length)) : null
}

export function csrfToken(): string | null {
  for (const name of CSRF_COOKIE_CANDIDATES) {
    const value = readCookie(name)
    if (value) {
      return value
    }
  }
  return null
}

type Query = Record<string, string | number | boolean | null | undefined>

export function withQuery(path: string, query: Query = {}): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== null && value !== undefined && value !== '') {
      params.append(key, String(value))
    }
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

interface RequestOptions {
  signal?: AbortSignal
  expectText?: boolean
}

export async function request<T>(
  method: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
  options: RequestOptions = {}
): Promise<T> {
  const headers = new Headers()
  const mutating = method !== 'GET' && method !== 'HEAD'
  if (body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (mutating) {
    const token = csrfToken()
    if (token) {
      headers.set(CSRF_HEADER, token)
    }
  }

  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: options.signal,
      cache: 'no-store'
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw e
    }
    throw new ApiError(0, 'network_error', '网络不可达或服务未响应', null)
  }

  if (response.status === 204) {
    return undefined as T
  }

  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.includes('application/json')) {
    if (response.ok) {
      return (await response.text()) as T
    }
    throw new ApiError(response.status, 'non_json_error', `服务异常返回（HTTP ${response.status}）`, null)
  }

  const payload = (await response.json()) as ErrorBody | T
  if (!response.ok) {
    const envelope = payload as ErrorBody
    const error = envelope.error
    if (error) {
      throw new ApiError(response.status, error.code, error.message, error.request_id ?? null)
    }
    throw new ApiError(response.status, 'error_unknown', `请求失败（HTTP ${response.status}）`, null)
  }
  return payload as T
}

export const get = <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, { signal })
export const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {})
export const put = <T>(path: string, body: unknown) => request<T>('PUT', path, body)
export const patch = <T>(path: string, body: unknown) => request<T>('PATCH', path, body)
export const del = <T>(path: string) => request<T>('DELETE', path)
