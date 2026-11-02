import type { ReactNode } from 'react'
import { Link } from 'react-router'

import { AuthShell } from './auth-shell'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
      <div className="space-y-2 text-xs leading-6 text-slate-600">{children}</div>
    </section>
  )
}

export function TermsPage() {
  return (
    <AuthShell
      wide
      title="服务条款"
      subtitle="版本 v1 · 生效日期 2026-11-02"
      footer={
        <Link to="/login" className="font-medium text-indigo-700 hover:underline">
          返回登录
        </Link>
      }
    >
      <div className="space-y-5">
        <Section title="1. 服务说明">
          <p>
            用户中心为组织内部账号与身份治理平台，提供登录、账号资料、多因素认证、会话管理以及授权与审计能力。使用本服务即表示你代表所在组织同意本条款。
          </p>
        </Section>
        <Section title="2. 账号与凭据">
          <p>
            你应妥善保管密码、动态验证码与恢复码，不得与他人共享。所有登录会话通过 HttpOnly Cookie 建立，平台不会在浏览器存储中保存会话令牌、MFA 密钥或恢复码。
          </p>
        </Section>
        <Section title="3. 可接受使用">
          <ul className="list-disc space-y-1 pl-4">
            <li>不得尝试绕过权限校验、越权访问他人数据或探测系统漏洞。</li>
            <li>不得使用自动化手段对登录、验证码等接口进行高频请求。</li>
            <li>发现安全问题时，应及时联系组织管理员或安全团队。</li>
          </ul>
        </Section>
        <Section title="4. 审计与合规">
          <p>
            为保障平台安全，登录、授权变更、会话撤销、MFA 重置等操作会记录审计事件，包括操作者、目标、结果、原因、请求标识与时间。审计记录按组织策略保留。
          </p>
        </Section>
        <Section title="5. 服务变更与终止">
          <p>
            组织管理员可以调整认证策略、禁用或归档账号，并撤销会话。违反本条款可能导致访问权限被暂停或终止。
          </p>
        </Section>
        <Section title="6. 免责声明">
          <p>
            本服务按现状提供。对于因网络、依赖服务或不可抗力导致的中断，平台将在合理范围内恢复服务，但不承担由此产生的间接损失。
          </p>
        </Section>
      </div>
    </AuthShell>
  )
}

export function PrivacyPage() {
  return (
    <AuthShell
      wide
      title="隐私政策"
      subtitle="版本 v1 · 生效日期 2026-11-02"
      footer={
        <Link to="/login" className="font-medium text-indigo-700 hover:underline">
          返回登录
        </Link>
      }
    >
      <div className="space-y-5">
        <Section title="1. 我们收集的信息">
          <ul className="list-disc space-y-1 pl-4">
            <li>账号信息：用户名、昵称、邮箱、账号状态、角色与权限投影。</li>
            <li>安全信息：登录时间、脱敏 IP、设备摘要、MFA 状态与安全事件。</li>
            <li>操作信息：管理变更的原因、目标、结果与请求标识，用于审计。</li>
          </ul>
        </Section>
        <Section title="2. 信息的使用">
          <p>
            上述信息仅用于身份认证、访问控制、安全审计、故障排查与合规要求，不用于广告或与平台服务无关的用途。
          </p>
        </Section>
        <Section title="3. 存储与保护">
          <p>
            密码以强哈希保存；MFA 密钥加密存储；恢复码仅保存不可逆摘要；会话 Cookie 设置为 HttpOnly 与 SameSite=Lax。浏览器端不在 localStorage 或 sessionStorage 中保存会话令牌、MFA 密钥或恢复码。
          </p>
        </Section>
        <Section title="4. 共享与披露">
          <p>
            除法律法规要求、组织内部审计或经你授权的第三方身份提供方外，我们不会向第三方披露个人信息。
          </p>
        </Section>
        <Section title="5. 你的权利">
          <p>
            你可以在账号中心查看和修改昵称、管理会话、启用或关闭多因素认证，并查看个人安全事件。如需导出或删除账号数据，请联系组织管理员。
          </p>
        </Section>
        <Section title="6. 联系方式">
          <p>如对本政策有疑问，请联系组织管理员或平台安全团队。</p>
        </Section>
      </div>
    </AuthShell>
  )
}
