import { Json } from './types'

export function value(row: Json | null | undefined, keys: string[], fallback = '—'): string {
  if (!row) return fallback
  for (const key of keys) {
    const item = row[key]
    if (item !== undefined && item !== null && item !== '') {
      if (typeof item === 'string') return item
      if (typeof item === 'number' || typeof item === 'boolean') return String(item)
      return compact(item)
    }
  }
  return fallback
}

export function compact(item: unknown): string {
  if (item === null || item === undefined) return '—'
  if (typeof item === 'string') return item
  if (typeof item === 'number' || typeof item === 'boolean') return String(item)
  try {
    return JSON.stringify(item)
  } catch {
    return String(item)
  }
}

export function asJson(value: unknown): Json {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : {}
}

export function asRows(value: unknown): Json[] {
  return Array.isArray(value) ? value.filter(item => item && typeof item === 'object') as Json[] : []
}

export function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : []
}

export function rowsFromList(value: Json): Json[] {
  return asRows(value.items ?? value.rules ?? value.records)
}

export function humanize(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function formatDate(value: unknown): string {
  if (!value) return '—'
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

export function formatPercent(value: unknown): string {
  const n = Number(value)
  if (!Number.isFinite(n)) return '—'
  return `${n.toFixed(n % 1 === 0 ? 0 : 1)}%`
}

export function downloadText(filename: string, content: string, type = 'application/json') {
  const blob = new Blob([content], { type })
  downloadBlob(filename, blob)
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export function csvFromRows(rows: Json[]): string {
  if (!rows.length) return ''
  const columns = Array.from(new Set(rows.flatMap(row => Object.keys(row))))
  const escape = (input: unknown) => {
    const text = compact(input)
    return `"${text.replaceAll('"', '""')}"`
  }
  return [columns.map(escape).join(','), ...rows.map(row => columns.map(column => escape(row[column])).join(','))].join('\n')
}

export function firstArray(container: Json, keys: string[]): Json[] {
  for (const key of keys) {
    const rows = asRows(container[key])
    if (rows.length || Array.isArray(container[key])) return rows
  }
  return []
}

export function toneForStatus(status: string): 'ok' | 'warn' | 'bad' | 'neutral' {
  const normalized = status.toLowerCase()
  if (['ready', 'ok', 'passed', 'resolved', 'contained', 'active', 'enabled'].includes(normalized)) return 'ok'
  if (['failed', 'error', 'critical', 'disabled', 'locked'].includes(normalized)) return 'bad'
  if (['open', 'investigating', 'warning', 'high', 'partial', 'partially_supported'].includes(normalized)) return 'warn'
  return 'neutral'
}


export function permissions(user: Json): Set<string> {
  return new Set(Array.isArray(user.permissions) ? user.permissions.map(String) : [])
}

export function hasPermission(user: Json, permission: string): boolean {
  return permissions(user).has(permission)
}

export async function sha256Hex(blob: Blob): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}

export function fileSizeMiB(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(1)
}
