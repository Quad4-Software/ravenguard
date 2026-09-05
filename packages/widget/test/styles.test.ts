import { describe, expect, it } from 'vitest'
import { styles } from '../src/styles'

describe('widget styles', () => {
  it('exposes theme custom properties', () => {
    expect(styles).toContain('--rg-bg')
    expect(styles).toContain('--rg-fg')
    expect(styles).toContain('--rg-accent')
    expect(styles).toContain(":host([theme='light'])")
    expect(styles).toContain(":host([theme='dark'])")
  })

  it('keeps checkbox and spinner box-sizing aligned', () => {
    expect(styles).toContain('box-sizing: border-box')
    expect(styles).toContain(".rg-check[data-state='verifying']")
    expect(styles).toContain('border-color: transparent')
  })
})
