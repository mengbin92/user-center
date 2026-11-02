const dateTimeFormatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
})

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
})

export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return dateTimeFormatter.format(date).replaceAll('/', '-')
}

export function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return dateFormatter.format(date).replaceAll('/', '-')
}

export function formatNumber(value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '0'
  const numeric = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(numeric)) return String(value)
  return new Intl.NumberFormat('zh-CN').format(numeric)
}

export function toRfc3339(localValue: string): string | undefined {
  if (!localValue) return undefined
  const date = new Date(localValue)
  if (Number.isNaN(date.getTime())) return undefined
  return date.toISOString()
}

export const USER_STATUS_LABELS: Record<string, string> = {
  enabled: '已启用',
  disabled: '已禁用',
  archived: '已归档',
}

export const ROLE_STATUS_LABELS: Record<string, string> = {
  active: '启用中',
  disabled: '已停用',
  archived: '已归档',
}

export const PERMISSION_STATUS_LABELS: Record<string, string> = {
  active: '启用中',
  disabled: '已停用',
  archived: '已归档',
}

export const GRANT_EFFECT_LABELS: Record<string, string> = {
  allow: '允许',
  deny: '拒绝',
}

export const RESULT_LABELS: Record<string, string> = {
  success: '成功',
  failure: '失败',
  denied: '拒绝',
}

export const SESSION_ROLE_ORIGIN_LABELS: Record<string, string> = {
  direct: '直接分配',
  role: '角色继承',
  system: '系统授予',
}

export function formatScope(scope?: {
  all?: boolean
  self?: boolean
  user_ids?: string[]
} | null): string {
  if (!scope) return '全部'
  if (scope.all) return '全部数据'
  if (scope.self) return '仅本人'
  if (scope.user_ids?.length) return `指定用户（${scope.user_ids.length}）`
  return '未指定'
}

export function formatScopeCode(scope?: string | null): string {
  switch (scope) {
    case 'all':
      return '全部数据'
    case 'self':
      return '仅本人'
    case 'user_ids':
      return '指定用户'
    default:
      return scope || '—'
  }
}

export function prettyJson(raw?: string | null): string {
  if (!raw) return '—'
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

export function splitList(value: string): string[] {
  return value
    .split(/[,，\n]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function maskMiddle(value?: string | null, head = 4, tail = 4): string {
  if (!value) return '—'
  if (value.length <= head + tail) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}
