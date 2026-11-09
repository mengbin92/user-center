// Self-contained recording: temporary SQLite database and random loopback port.
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const { chromium } = createRequire(new URL('../web/package.json', import.meta.url))('playwright')
const output = join(root, 'docs/videos')
const images = join(root, 'docs/images')
const reason = '操作手册演示数据'
const password = 'Guide-' + crypto.randomBytes(16).toString('hex') + '!'
const newPassword = 'New-' + crypto.randomBytes(16).toString('hex') + '!'

function totp(secret, seconds = Date.now() / 1000) {
  let bits = 0, value = 0
  const bytes = []
  for (const c of secret.toUpperCase().replace(/=+$/, '')) {
    const digit = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c)
    assert(digit >= 0, 'Invalid base32 secret')
    value = (value << 5) | digit
    bits += 5
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / 30)))
  const digest = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter).digest()
  return String((digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, '0')
}
function takeRecoveryCode(codes) {
  const code = codes.pop()
  assert(code, 'No remaining demo recovery codes')
  return code
}
assert.equal(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59), '287082')
assert.equal(takeRecoveryCode(['test-code']), 'test-code')
assert.throws(() => takeRecoveryCode([]), /No remaining demo recovery codes/)
if (process.argv.includes('--self-test')) {
  console.log('PASS: RFC 6238 TOTP vector; recovery-code exhaustion; recorder imports')
  process.exit(0)
}

await readFile(join(root, 'web/dist/index.html'))
await mkdir(output, { recursive: true })
await mkdir(images, { recursive: true })
const temp = await mkdtemp(join(tmpdir(), 'uc-guides-'))
const reservation = createServer()
reservation.listen(0, '127.0.0.1')
await once(reservation, 'listening')
const port = reservation.address().port
const baseURL = 'http://127.0.0.1:' + port
const configPath = join(temp, 'config.yaml')
// Bootstrap reads settings while holding its transaction; it needs a second connection.
const config = await readFile(join(root, 'configs/config.dev.yaml'), 'utf8')
assert(config.includes('max_open_conns: 1'), 'Development connection-pool config changed; update the recording fixture')
await writeFile(configPath, config.replace('max_open_conns: 1', 'max_open_conns: 5'), { mode: 0o600 })
// Override inherited deployment settings; the recorder never accepts a remote URL.
const env = {
  ...process.env, DB_DRIVER: 'sqlite', DB_DSN: 'file:' + temp + '/demo.db?_fk=1',
  REDIS_ADDR: '', HTTP_ADDR: '127.0.0.1:' + port, GRPC_ADDR: '127.0.0.1:0', METRICS_ADDR: 'off',
  PUBLIC_BASE_URL: baseURL, WEB_DIST: join(root, 'web/dist'), COOKIE_SECURE: 'false', COOKIE_DOMAIN: '',
  ARTIFACT_DIR: join(temp, 'artifacts'), OIDC_SIGNING_KEY_PEM: '', OIDC_SIGNING_KEY_PATH: '',
  USER_CENTER_BOOTSTRAP_USERNAME: '', USER_CENTER_BOOTSTRAP_PASSWORD: '', USER_CENTER_BOOTSTRAP_EMAIL: '',
  SESSION_SECRET: crypto.randomBytes(32).toString('hex'), CSRF_SECRET: crypto.randomBytes(32).toString('hex'),
  MFA_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
}
let server, browser, activeContext, rootState, userState, rootCodes, userCodes, labOrgId
const manifest = []

async function api(context, method, path, data) {
  const csrf = (await context.cookies(baseURL)).find((cookie) => cookie.name === 'uc_csrf')?.value ?? ''
  const response = await context.request.fetch(baseURL + path, {
    method, data, headers: { 'X-CSRF-Token': csrf }, timeout: 15000,
  })
  assert(response.ok(), method + ' ' + path + ': HTTP ' + response.status())
  const text = await response.text()
  return text ? JSON.parse(text) : {}
}
async function caption(page, title, detail) {
  await page.evaluate(({ title, detail }) => {
    let panel = document.getElementById('guide-caption')
    if (!panel) {
      panel = document.createElement('aside')
      panel.id = 'guide-caption'
      panel.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);width:min(760px,90vw);box-sizing:border-box;padding:14px 20px;border-radius:12px;background:#0f172aee;color:white;box-shadow:0 8px 30px #0f172a33;z-index:2147483647;pointer-events:none;font:14px/1.6 system-ui'
      document.body.append(panel)
    }
    panel.replaceChildren()
    const heading = document.createElement('strong')
    heading.textContent = title
    const paragraph = document.createElement('div')
    paragraph.style.cssText = 'color:#cbd5e1;font-size:12px'
    paragraph.textContent = detail
    panel.append(heading, paragraph)
  }, { title, detail })
  await page.waitForTimeout(3000)
}
async function visit(page, path, title) {
  await page.goto(path)
  await page.getByRole('heading', { name: title, exact: true }).first().waitFor()
  await page.waitForLoadState('networkidle')
}
async function screenshot(page, name) {
  for (const close of await page.getByRole('button', { name: '关闭通知', exact: true }).all()) await close.click()
  await page.screenshot({ path: join(images, name + '.png') })
}
async function assertMaskedCodes(page) {
  const codes = page.getByRole('dialog').locator('code')
  assert(await codes.count() > 0, 'Expected sensitive code fields; check redaction selectors')
  assert(await codes.evaluateAll((nodes) => nodes.every((node) => getComputedStyle(node).color === 'rgba(0, 0, 0, 0)')), 'Sensitive code field is visible')
}
async function record(name, title, state, action) {
  const context = await browser.newContext({
    baseURL, storageState: state, locale: 'zh-CN', timezoneId: 'Asia/Shanghai',
    viewport: { width: 1440, height: 1000 },
    recordVideo: { dir: temp, size: { width: 1440, height: 1000 } },
  })
  activeContext = context
  // Redact before rendering, including dialogs opened later in this document.
  await context.addInitScript(() => {
    const install = () => {
      const style = document.createElement('style')
      style.textContent = '[role="dialog"] code{color:transparent!important;background:#cbd5e1!important;user-select:none!important}[role="dialog"]:has(#setup-code) div>svg{visibility:hidden!important}[role="dialog"]:has(#setup-code) div:has(>svg){position:relative}[role="dialog"]:has(#setup-code) div:has(>svg)::after{content:"演示已遮挡 · 请在真实页面扫码";position:absolute;inset:30px 20px 50px;display:grid;place-items:center;border-radius:8px;background:#edf2f7;color:#64748b;font-size:12px}input[autocomplete="one-time-code"],#setup-code,#step-up-code,#login-mfa-code{-webkit-text-security:disc!important}'
      document.head.append(style)
    }
    if (document.head) install()
    else document.addEventListener('DOMContentLoaded', install, { once: true })
  })
  const page = await context.newPage()
  page.setDefaultTimeout(12000)
  const errors = []
  const denied = []
  page.on('pageerror', (error) => errors.push(error.message))
  page.on('response', async (response) => {
    if (response.url().includes('/api/') && response.status() >= 400) {
      const body = await response.json().catch(() => ({}))
      denied.push({ path: new URL(response.url()).pathname, status: response.status(), reason: body.reason })
    }
  })
  // Step-up is bound to the session, and rootState was verified once during
  // setup. Re-verifying per chapter burned a recovery code each time and left
  // the last chapter without one.
  assert(!(state === rootState && state) || rootCodes.length >= 0)
  try {
    await action(page, context)
  } catch (error) {
    console.error('Failed chapter: ' + name + '; page: ' + new URL(page.url()).pathname)
    console.error('Page headings: ' + JSON.stringify(await page.getByRole('heading').allTextContents()))
    console.error('Browser errors: ' + JSON.stringify(errors))
    console.error('Rejected requests: ' + JSON.stringify(denied))
    throw error
  }
  assert.deepEqual(errors, [], name + ': browser errors')
  const video = page.video()
  await context.close()
  activeContext = undefined
  await video.saveAs(join(output, name + '.webm'))
  manifest.push({ name, title, video: name + '.webm' })
  console.log('PASS: ' + name)
}

try {
  for (const [command, args] of [
    ['migrate', []],
    ['admin-rescue', ['-action', 'bootstrap', '-username', 'guide.admin', '-password', password, '-email', 'admin@example.com']],
  ]) {
    const result = spawnSync('go', ['run', './cmd/' + command, '-config', configPath, ...args], { cwd: root, env, encoding: 'utf8', timeout: 180000 })
    assert.equal(result.status, 0, command + ' failed: ' + (result.error?.message ?? result.stderr ?? '').replaceAll(password, '[redacted]'))
  }
  console.log('PASS: isolated SQLite migrations and demo administrator')
  await new Promise((resolve) => reservation.close(resolve))
  let startupError = ''
  server = spawn('go', ['run', './cmd/user-center', '-config', configPath], { cwd: root, env, detached: true, stdio: ['ignore', 'ignore', 'pipe'] })
  server.stderr.on('data', (chunk) => { startupError = (startupError + chunk.toString()).slice(-4000) })
  const deadline = Date.now() + 180000
  while (true) {
    if (await fetch(baseURL + '/readyz', { signal: AbortSignal.timeout(2000) }).then((response) => response.ok).catch(() => false)) break
    const diagnostic = [password, env.SESSION_SECRET, env.CSRF_SECRET, env.MFA_ENCRYPTION_KEY].reduce((message, secret) => message.replaceAll(secret, '[redacted]'), startupError)
    assert(Date.now() < deadline && server.exitCode === null, 'Demo server failed to start: ' + diagnostic)
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  console.log('PASS: demo server ready')
  browser = await chromium.launch({ slowMo: 140 })
  const setup = await browser.newContext({ baseURL })
  await api(setup, 'GET', '/api/v1/auth/context')
  await api(setup, 'POST', '/api/v1/auth/login', { username: 'guide.admin', password })
  const mfa = await api(setup, 'POST', '/api/v1/me/mfa:setup', { current_password: password })
  const recovery = await api(setup, 'POST', '/api/v1/me/mfa:confirm', { code: totp(mfa.secret) })
  rootCodes = [...recovery.recovery_codes]
  await api(setup, 'POST', '/api/v1/me/security:verify', { current_password: password, code: takeRecoveryCode(rootCodes) })
  rootState = await setup.storageState()
  await setup.close()

  await record('delegation-sod', '查看委派与职责分离配置', rootState, async (page) => {
    await visit(page, '/admin/iam/delegations', '委派管理')
    await page.getByRole('button', { name: '新建委派', exact: true }).click()
    await caption(page, '01 / 委派配置表单', '指定管理角色、目标角色、动作、用户范围、授权上限与有效期。本段只查看，不提交。')
    await screenshot(page, 'delegation')
    await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click()
    await visit(page, '/admin/iam/constraints', '职责分离约束')
    await page.getByRole('button', { name: /新建.*约束/ }).click()
    await page.locator('#constraint-name').fill('演示职责互斥')
    await caption(page, '02 / 职责分离配置表单', '互斥限制角色同时持有；数量上限只统计所选角色。本段只查看，不提交。')
    await screenshot(page, 'constraints')
  })

  await record('oidc-app', '创建 OIDC 应用', rootState, async (page) => {
    await visit(page, '/admin/applications', 'OIDC 应用')
    await page.getByRole('button', { name: /创建.*应用/ }).first().click()
    await page.locator('#oidc-create-name').fill('演示应用')
    await page.locator('#oidc-create-owner').fill('演示团队')
    await page.locator('#oidc-create-redirects').fill('https://app.example.com/callback')
    await page.locator('#oidc-create-reason').fill(reason)
    await caption(page, '01 / 填写应用配置', '回调 URI 必须精确匹配；按应用类型选择 PKCE、scope 与令牌有效期。')
    await screenshot(page, 'oidc-create')
    const response = page.waitForResponse((res) => res.url().includes('/api/v1/admin/oidc-clients') && res.request().method() === 'POST')
    await page.getByRole('dialog').getByRole('button', { name: '创建应用', exact: true }).click()
    assert((await response).ok(), 'OIDC creation failed')
    await page.getByRole('heading', { name: '请立即保存客户端密钥', exact: true }).waitFor()
    await assertMaskedCodes(page)
    await caption(page, '02 / 保存一次性密钥', '机密客户端密钥仅展示一次；录制中已遮挡，实际接入时应安全保存。')
    await screenshot(page, 'oidc-created')
  })

  await record('settings-auth', '查看认证策略与会话配置', rootState, async (page) => {
    await visit(page, '/admin/settings/auth', '认证配置')
    await caption(page, '01 / 认证策略', '查看注册策略、管理员 MFA、密码规则及会话期限。本段只查看，不保存。')
    await screenshot(page, 'settings-auth')
    await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }))
    await caption(page, '02 / 提交前确认影响', '修改策略会影响后续认证与会话行为；提交必须填写原因并通过权限检查。')
  })

  await record('login', '账号登录与个人资料', undefined, async (page) => {
    await visit(page, '/login', '登录用户中心')
    await caption(page, '01 / 登录用户中心', '输入用户名或邮箱与密码；已启用 MFA 的账号还需完成第二因素验证。')
    await screenshot(page, 'login')
    await page.locator('#login-username').fill('guide.admin')
    await page.locator('#login-password').fill(password)
    await page.getByRole('button', { name: '登录', exact: true }).click()
    await page.locator('#login-mfa-code').fill(takeRecoveryCode(rootCodes))
    await caption(page, '02 / 完成两步验证', '动态码与一次性恢复码均可使用；录制中已遮挡凭据。')
    await page.getByRole('button', { name: '验证并登录', exact: true }).click()
    await page.waitForURL('**/admin')
    await visit(page, '/account', '个人资料')
    await caption(page, '03 / 登录成功', '在个人资料查看账号信息；管理权限账号可以进入管理控制台。')
    await screenshot(page, 'account')
  })

  await record('user-create', '创建用户并核对资料', rootState, async (page) => {
    await visit(page, '/admin/users', '用户管理')
    await caption(page, '01 / 用户管理', '点击创建用户；演示使用一次性开发库，所有资料均为虚构。')
    await page.getByRole('button', { name: '创建用户', exact: true }).first().click()
    const dialog = page.getByRole('dialog')
    await dialog.locator('#create-username').fill('guide.demo')
    await dialog.locator('#create-email').fill('demo@example.com')
    await dialog.locator('#create-display-name').fill('演示用户')
    await dialog.locator('#create-password').fill(password)
    await dialog.getByRole('checkbox').uncheck()
    await dialog.locator('#create-reason').fill(reason)
    await caption(page, '02 / 填写资料与操作原因', '关闭激活邮件后需填写初始密码；创建后用户首次登录必须改密。')
    await screenshot(page, 'user-create')
    await dialog.getByRole('button', { name: '创建用户', exact: true }).click()
    await page.waitForURL(/\/admin\/users\/\d+$/)
    await page.getByText('guide.demo', { exact: true }).first().waitFor()
    await caption(page, '03 / 创建成功', '核对用户状态、资料与默认角色；重置凭据等操作需要近期安全验证。')
    await screenshot(page, 'user-detail')
  })

  await record('audit-export', '筛选审计并导出 CSV', rootState, async (page) => {
    await visit(page, '/admin/audits', '审计日志')
    await page.locator('#audit-action').fill('identity.user.create')
    await page.getByRole('button', { name: '筛选', exact: true }).click()
    await page.waitForLoadState('networkidle')
    await caption(page, '01 / 筛选审计事件', '按操作、操作者、目标与时间追踪变更；事件详情提供原因和版本。')
    await screenshot(page, 'audits')
    await page.getByRole('button', { name: /导出/ }).first().click()
    await page.getByRole('dialog').getByLabel('操作原因', { exact: false }).fill(reason)
    await page.getByRole('button', { name: '创建导出任务', exact: true }).click()
    await page.waitForURL('**/admin/exports**')
    await page.getByRole('button', { name: /下载/ }).first().waitFor()
    await caption(page, '02 / 下载导出产物', '导出沿用筛选与权限范围，24 小时内可下载，过期需重新创建。')
    await screenshot(page, 'exports')
    const download = page.waitForEvent('download')
    await page.getByRole('button', { name: /下载/ }).first().click()
    assert.equal(await (await download).failure(), null, 'CSV download failed')
  })

  await record('first-login', '首次登录改密与启用 MFA', undefined, async (page, context) => {
    await visit(page, '/login', '登录用户中心')
    await page.locator('#login-username').fill('guide.demo')
    await page.locator('#login-password').fill(password)
    await page.getByRole('button', { name: '登录', exact: true }).click()
    await page.waitForURL('**/account/security**')
    await caption(page, '01 / 首次登录先修改密码', '使用管理员提供的初始密码登录后，在安全中心设置自己的密码。')
    await page.locator('#current-password').fill(password)
    await page.locator('#new-password').fill(newPassword)
    await page.locator('#confirm-password').fill(newPassword)
    await page.getByRole('button', { name: '更新密码', exact: true }).click()
    await page.getByText('密码已更新', { exact: true }).first().waitFor()
    await page.getByRole('button', { name: '启用 MFA', exact: true }).click()
    await page.locator('#setup-password').fill(newPassword)
    const response = page.waitForResponse((res) => res.url().endsWith('/me/mfa:setup') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '生成密钥', exact: true }).click()
    const data = await (await response).json()
    await page.locator('#setup-code').waitFor()
    assert.equal(await page.getByRole('dialog').locator('div > svg').first().evaluate((node) => getComputedStyle(node).visibility), 'hidden', 'MFA QR code is visible')
    await assertMaskedCodes(page)
    await caption(page, '02 / 扫码并输入动态验证码', '用身份验证器扫描二维码。二维码、密钥与验证码在教程中已遮挡。')
    await screenshot(page, 'mfa-setup')
    await page.locator('#setup-code').fill(totp(data.secret))
    const confirmed = page.waitForResponse((res) => res.url().endsWith('/me/mfa:confirm') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '确认启用', exact: true }).click()
    userCodes = (await (await confirmed).json()).recovery_codes
    await page.getByRole('heading', { name: '请立即保存恢复码', exact: true }).waitFor()
    await assertMaskedCodes(page)
    await caption(page, '03 / 离线保存恢复码', '恢复码仅展示一次，每枚只能使用一次。请保存到安全的离线位置。')
    await screenshot(page, 'recovery-codes')
    await page.getByRole('button', { name: '我已保存', exact: true }).click()
    assert.equal((await api(context, 'GET', '/api/v1/me/security')).mfa_enabled, true)
    userState = await context.storageState()
  })

  const otherDevice = await browser.newContext({ baseURL, userAgent: 'Guide second device' })
  await api(otherDevice, 'GET', '/api/v1/auth/context')
  const challenge = await api(otherDevice, 'POST', '/api/v1/auth/login', { username: 'guide.demo', password: newPassword })
  await api(otherDevice, 'POST', '/api/v1/auth/mfa/complete', { challenge_id: challenge.challenge_id, code: takeRecoveryCode(userCodes) })
  await otherDevice.close()

  await record('sessions', '查看会话并撤销其他设备', userState, async (page) => {
    await visit(page, '/account/sessions', '会话管理')
    await caption(page, '01 / 检查有效会话', '核对设备、来源和最近活跃时间。当前会话有单独标记。')
    await screenshot(page, 'sessions')
    await page.getByRole('button', { name: '撤销其他会话', exact: true }).click()
    await caption(page, '02 / 撤销其他会话', '确认后，其他设备需要重新登录；当前设备继续使用。')
    await page.getByRole('button', { name: '全部撤销', exact: true }).click()
    await page.getByText('其他会话已全部撤销', { exact: true }).waitFor()
    await visit(page, '/account/activity', '安全事件')
    await caption(page, '03 / 查看登录记录', '发现陌生登录时，修改密码并撤销其他会话。')
    await screenshot(page, 'activity')
  })

  await record('org-create', '创建组织与查看组织空间', userState, async (page) => {
    await visit(page, '/orgs', '我的组织')
    await page.getByRole('button', { name: '创建组织', exact: true }).first().click()
    await page.locator('#org-create-code').fill('guide-lab')
    await page.locator('#org-create-name').fill('演示实验室')
    await caption(page, '01 / 创建组织', '填写全局唯一的组织 code 与组织名称；创建者自动成为拥有者。')
    await page.getByRole('dialog').getByRole('button', { name: '创建组织', exact: true }).click()
    await page.waitForURL(/\/orgs\/\d+$/)
    await page.getByRole('heading', { name: '演示实验室', exact: true }).waitFor()
    await page.waitForLoadState('networkidle')
    const match = page.url().match(/\/orgs\/(\d+)/)
    assert(match, 'Organization id missing from URL')
    labOrgId = match[1]
    await caption(page, '02 / 组织空间', '在页签中管理成员、部门、组织角色、职责分离、审计与设置。')
    await screenshot(page, 'organization')
  })

  // A delegation write needs a recent step-up; the shared user session has
  // none yet, so verify once and reuse the resulting storage state.
  const delegationCtx = await browser.newContext({ baseURL, storageState: userState })
  await api(delegationCtx, 'GET', '/api/v1/auth/context')
  await api(delegationCtx, 'POST', '/api/v1/me/security:verify', { current_password: newPassword, code: takeRecoveryCode(userCodes) })
  const delegationState = await delegationCtx.storageState()
  await delegationCtx.close()

  await record('org-delegation', '组织委派：创建与撤销', delegationState, async (page) => {
    await visit(page, '/orgs/' + labOrgId, '演示实验室')
    await page.getByRole('tab', { name: '职责分离' }).click()
    await page.getByRole('heading', { name: '组织内委派', exact: true }).waitFor()
    await page.getByRole('button', { name: '新建委派', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByLabel('管理角色').selectOption({ index: 1 })
    await dialog.getByLabel('目标角色').selectOption({ index: 2 })
    await caption(page, '01 / 选择管理角色与目标角色', '管理角色是委派的使用者，目标角色是能被授出的角色；授权上限自动取目标角色当前权限。')
    await screenshot(page, 'org-delegation-form')
    await dialog.getByRole('button', { name: '下一步', exact: true }).click()
    await page.getByLabel(/操作原因/).fill(reason)
    const created = page.waitForResponse((res) => res.url().includes('/iam/delegations') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '创建', exact: true }).click()
    assert((await created).ok(), 'Organization delegation creation failed')
    await page.getByText('生效中', { exact: true }).first().waitFor()
    await caption(page, '02 / 委派已生效', '委派只放宽目标角色的分配能力，不授予角色或策略修改权。')
    await screenshot(page, 'org-delegation')
    const revoked = page.waitForResponse((res) => res.url().includes(':revoke') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '撤销', exact: true }).first().click()
    await page.getByLabel(/操作原因/).fill('演示结束，撤销委派')
    await page.getByRole('button', { name: '撤销', exact: true }).last().click()
    assert((await revoked).ok(), 'Organization delegation revoke failed')
    await page.getByText('已撤销', { exact: true }).first().waitFor()
    await caption(page, '03 / 撤销后立即失效', '撤销写入组织审计并推进策略版本；已授出的分配不会自动回滚。')
  })

  await record('provisioning', 'SCIM 凭据与目录同步', rootState, async (page) => {
    await visit(page, '/orgs/' + labOrgId, '演示实验室')
    await page.getByRole('tab', { name: '设置' }).click()
    await page.getByRole('heading', { name: 'SCIM 2.0 用户供给', exact: true }).waitFor()
    await page.getByRole('button', { name: '新建凭据', exact: true }).click()
    await page.getByLabel('凭据名称').fill('演示 IdP')
    await page.getByRole('button', { name: '下一步', exact: true }).click()
    await page.getByLabel(/操作原因/).fill(reason)
    const token = page.waitForResponse((res) => res.url().includes('/admin/scim/tokens') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '确认', exact: true }).click()
    assert((await token).ok(), 'SCIM token creation failed')
    await page.getByRole('heading', { name: '请立即保存凭据', exact: true }).waitFor()
    await assertMaskedCodes(page)
    await caption(page, '01 / 凭据只显示一次', '凭据绑定本组织，服务端只保存摘要；关闭后只能轮换。录制中已遮挡。')
    await screenshot(page, 'scim-token')
    await page.getByRole('button', { name: '我已保存', exact: true }).click()
    await page.getByRole('button', { name: '新建目录源', exact: true }).click()
    const sourceDialog = page.getByRole('dialog')
    await sourceDialog.getByLabel('名称').fill('corp-ad')
    await sourceDialog.getByLabel(/连接配置/).fill(JSON.stringify({
      url: 'https://directory.example.com/users', interval_seconds: 300,
      deletion_policy: 'disable', conflict_policy: 'source_wins',
    }, null, 2))
    await caption(page, '02 / 目录同步配置', '支持 LDAP / AD 与 JSON 网关；外部凭据加密入库，同步支持预演与对账。本段只查看，不提交。')
    await screenshot(page, 'directory-sync')
    await sourceDialog.getByRole('button', { name: '取消', exact: true }).click()
  })

  await record('iam-grant', '创建角色并预览、提交授权', rootState, async (page) => {
    await visit(page, '/admin/iam/roles', '角色管理')
    await page.getByRole('button', { name: '创建角色', exact: true }).first().click()
    await page.locator('#role-code').fill('guide-reader')
    await page.locator('#role-name').fill('演示只读角色')
    await page.locator('#role-description').fill('演示授权流程；新角色尚未配置操作权限')
    await page.locator('#role-create-reason').fill(reason)
    await caption(page, '01 / 创建角色', '新角色默认没有操作权限；实际使用前应在详情页配置权限与范围。')
    await page.getByRole('dialog').getByRole('button', { name: '创建', exact: true }).click()
    await page.waitForURL(/\/admin\/iam\/roles\/\d+$/)
    await visit(page, '/admin/iam/assignments', '授权分配')
    await page.locator('#assign-role').selectOption({ label: '演示只读角色（guide-reader）' })
    await page.locator('#assign-boundary').selectOption('self')
    await page.locator('#assign-user-search').fill('guide.demo')
    await page.getByRole('button', { name: '搜索', exact: true }).first().click()
    await page.locator('tr').filter({ hasText: '@guide.demo' }).getByRole('checkbox').check()
    await page.getByRole('button', { name: '预览资格', exact: true }).click()
    await page.getByText('尚未运行预览', { exact: true }).waitFor({ state: 'hidden' })
    await caption(page, '02 / 预览资格与冲突', '选择用户、角色与数据边界，预览通过后才提交。预览本身不会写入数据。')
    await screenshot(page, 'iam-preview')
    await page.getByRole('button', { name: '批量分配', exact: true }).click()
    await page.getByRole('dialog').getByLabel('操作原因', { exact: false }).fill(reason)
    const assigned = page.waitForResponse((res) => res.url().endsWith('/iam/assignments:batch-assign') && res.request().method() === 'POST')
    await page.getByRole('button', { name: '确认分配', exact: true }).click()
    assert.equal((await (await assigned).json()).assignments?.length, 1, 'Expected one role assignment')
    await page.locator('tr').filter({ hasText: 'guide-reader' }).filter({ hasText: '@guide.demo' }).waitFor()
    await caption(page, '03 / 分配成功', '本示例只演示分配流程；获得哪些操作能力取决于角色实际配置。')
  })

  const mobile = await browser.newContext({ baseURL, storageState: userState, viewport: { width: 390, height: 844 }, isMobile: true, deviceScaleFactor: 1, locale: 'zh-CN' })
  for (const [path, title, name] of [['/account', '个人资料', 'mobile-account'], ['/orgs', '我的组织', 'mobile-organizations']]) {
    const page = await mobile.newPage()
    await visit(page, path, title)
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), name + ': horizontal overflow')
    await screenshot(page, name)
  }
  await mobile.close()
  assert.equal(manifest.length, 12)
  const recordedAt = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', dateStyle: 'long', timeStyle: 'medium', hour12: false }).format(new Date()) + '（北京时间）'
  await writeFile(join(output, 'manifest.json'), JSON.stringify({ recorded_at: recordedAt, viewport: '1440×1000', mobile: '390×844', clips: manifest }, null, 2) + '\n')
  console.log('PASS: 12 videos, key screenshots, mobile overflow assertions and CSV download')
} finally {
  await activeContext?.close().catch(() => {})
  await browser?.close().catch(() => {})
  try {
    if (server?.pid) {
      const stopped = once(server, 'exit')
      try { process.kill(-server.pid, 'SIGTERM') } catch (error) { if (error.code !== 'ESRCH') throw error }
      if (server.exitCode === null) await stopped
    }
  } finally {
    await rm(temp, { recursive: true, force: true })
    if (reservation.listening) await new Promise((resolve) => reservation.close(resolve))
  }
}
