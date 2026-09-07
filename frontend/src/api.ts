import { Json, Session } from './types'

const API_URL = (import.meta.env.VITE_THREATLENS_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const STORAGE_KEY = 'threatlens.session.v014'
let refreshInFlight: Promise<void> | null = null

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

export function saveSession(session: Session | null) {
  if (session) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session))
  else sessionStorage.removeItem(STORAGE_KEY)
}

function messageFromBody(body: unknown, fallback: string) {
  if (body && typeof body === 'object' && 'error' in body) {
    const error = (body as { error?: { message?: string } }).error
    if (error?.message) return error.message
  }
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail?: string | { message?: string } }).detail
    if (typeof detail === 'string') return detail
    if (detail?.message) return detail.message
  }
  return fallback
}

function expireSession() {
  saveSession(null)
  window.dispatchEvent(new Event('threatlens:session-expired'))
}

export async function login(username: string, password: string): Promise<Session> {
  const form = new URLSearchParams({ username, password })
  const response = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(messageFromBody(body, 'Login failed.'))
  const token = body as { access_token: string; refresh_token: string; user: Json }
  return { accessToken: token.access_token, refreshToken: token.refresh_token, user: token.user }
}

async function refreshSession(session: Session): Promise<void> {
  if (refreshInFlight) return refreshInFlight

  refreshInFlight = (async () => {
    const refreshTokenUsed = session.refreshToken
    const response = await fetch(`${API_URL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshTokenUsed }),
    })
    const body = await response.json().catch(() => ({}))
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) expireSession()
      throw new Error(messageFromBody(body, 'Unable to refresh the ThreatLens session.'))
    }
    const token = body as { access_token: string; refresh_token: string; user: Json }
    session.accessToken = token.access_token
    session.refreshToken = token.refresh_token
    session.user = token.user
    saveSession(session)
  })().finally(() => {
    refreshInFlight = null
  })

  return refreshInFlight
}

async function request(session: Session, path: string, init: RequestInit): Promise<Response> {
  return fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      ...(init.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(init.headers || {}),
    },
  })
}

async function authorizedResponse(session: Session, path: string, init: RequestInit = {}): Promise<Response> {
  const accessTokenUsed = session.accessToken
  let response = await request(session, path, init)
  if (response.status === 401 && path !== '/api/v1/auth/refresh') {
    if (session.accessToken === accessTokenUsed) await refreshSession(session)
    response = await request(session, path, init)
  }
  return response
}

export async function api<T = Json>(session: Session, path: string, init: RequestInit = {}): Promise<T> {
  const response = await authorizedResponse(session, path, init)
  if (response.status === 204) return {} as T
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(messageFromBody(body, `Request failed (${response.status}).`))
  return body as T
}

export async function apiBlob(session: Session, path: string, init: RequestInit = {}): Promise<{ blob: Blob; filename: string; sha256: string }> {
  const response = await authorizedResponse(session, path, init)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(messageFromBody(body, `Download failed (${response.status}).`))
  }
  const disposition = response.headers.get('Content-Disposition') || ''
  const filename = disposition.match(/filename="?([^";]+)"?/)?.[1] || 'threatlens-download.bin'
  return { blob: await response.blob(), filename, sha256: response.headers.get('X-Content-SHA256') || '' }
}

export async function logout(session: Session) {
  try {
    await api(session, '/api/v1/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: session.refreshToken }),
    })
  } finally {
    saveSession(null)
  }
}

export { API_URL }
export type { Json, Session }
