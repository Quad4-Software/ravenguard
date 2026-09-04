import { test, expect } from '@playwright/test'

const PASS = 'http://127.0.0.1:18080'
const ATTACK = 'http://127.0.0.1:18081'
const CAPTCHA = 'http://127.0.0.1:18082'
const REFUSE = 'http://127.0.0.1:18083'
const STRESS = 'http://127.0.0.1:18084'

async function clickWidget(page: import('@playwright/test').Page) {
  await page.locator('#rg-widget').evaluate((el) => {
    const btn = el.shadowRoot?.querySelector('button.rg-check') as HTMLButtonElement | null
    btn?.click()
  })
}

async function waitUpstream(page: import('@playwright/test').Page) {
  await page.waitForFunction(
    () => document.body && document.body.innerText.includes('upstream-ok'),
    undefined,
    { timeout: 90_000 },
  )
}

test.describe('invisible gate', () => {
  test('auto-solves and reaches upstream @smoke', async ({ page }) => {
    const probe = await page.request.get(PASS + '/')
    const html = await probe.text()
    expect(html).toContain('auto="onload"')
    expect(html).toContain('display="invisible"')
    await page.goto(PASS + '/')
    await waitUpstream(page)
    const cookies = await page.context().cookies()
    expect(cookies.some((c) => c.name === 'rg_clear')).toBeTruthy()
  })
})

test.describe('attack mode', () => {
  test('shows interactive checkbox and clears after click', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'attack interactive covered on chromium')
    await page.goto(ATTACK + '/')
    await expect(page.locator('#rg-widget')).toHaveAttribute('auto', 'off')
    await expect(page.locator('body')).toHaveClass(/gate-interactive/)
    await page.waitForTimeout(1500)
    expect(await page.locator('body').innerText()).not.toContain('upstream-ok')
    await clickWidget(page)
    await waitUpstream(page)
  })
})

test.describe('captcha stub', () => {
  test('wrong token is refused', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'captcha covered on chromium')
    await page.goto(CAPTCHA + '/')
    await expect(page.locator('#captcha')).toBeVisible()
    await page.locator('#captcha').fill('nope')
    await clickWidget(page)
    await expect(page.locator('#status')).toContainText(/captcha failed/i, { timeout: 30_000 })
    expect(await page.locator('body').innerText()).not.toContain('upstream-ok')
  })

  test('ok token clears', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'captcha covered on chromium')
    await page.goto(CAPTCHA + '/')
    await expect(page.locator('#captcha')).toBeVisible()
    await page.locator('#captcha').fill('ok')
    await clickWidget(page)
    await waitUpstream(page)
  })
})

test.describe('automation refuse', () => {
  test('playwright markers are refused when env_probe on', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'refuse covered on chromium')
    await page.goto(REFUSE + '/')
    await expect(page.locator('#rg-widget')).toBeAttached()
    await expect(page.locator('#rg-widget')).toHaveAttribute('display', 'invisible')
    await page.waitForTimeout(5000)
    const text = await page.locator('body').innerText()
    expect(text).not.toContain('upstream-ok')
    const cookies = await page.context().cookies(REFUSE)
    expect(cookies.some((c) => c.name === 'rg_clear')).toBeFalsy()
  })
})

test.describe('difficulty stress', () => {
  test('clears under higher difficulty', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'stress covered on chromium')
    test.setTimeout(180_000)
    await page.goto(STRESS + '/')
    await waitUpstream(page)
  })
})

test.describe('escalation', () => {
  test('invalid verify escalates next page to interactive', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'escalation covered on chromium')
    await page.request.post(PASS + '/_rg/challenge', {
      data: { payload: 'bad' },
      headers: { 'Content-Type': 'application/json' },
    })
    await page.goto(PASS + '/')
    await expect(page.locator('#rg-widget')).toHaveAttribute('auto', 'off')
  })
})
