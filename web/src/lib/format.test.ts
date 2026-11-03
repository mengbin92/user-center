import { describe, expect, it } from 'vitest'
import { formatNumber } from './format'
import { safeNext } from './paths'

describe('wire values', () => {
  it('formats decimal counts without losing 64-bit precision', () => {
    expect(formatNumber('9223372036854775807')).toBe('9,223,372,036,854,775,807')
    expect(formatNumber('9007199254740993')).toBe('9,007,199,254,740,993')
    expect(formatNumber(20)).toBe('20')
  })
  it('rejects redirect paths that browsers normalize into another origin', () => {
    expect(safeNext('/\\example.com/path')).toBeNull()
    expect(safeNext('/\n/example.com/path')).toBeNull()
    expect(safeNext('//example.com/path')).toBeNull()
    expect(safeNext('/account/security?tab=mfa')).toBe('/account/security?tab=mfa')
  })
})
