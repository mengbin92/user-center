# v0.2.1 · 2026-11-03

上一版：[v0.2.0](./release-v0.2.0.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.2.1)

## 修复

1. **邮件配置首次保存误报冲突**：无 `auth_email_settings` 行时，`expected_revision=0` 规范化为首版，不再返回 `REVISION_CONFLICT`。
2. **OAuth + MFA 回归覆盖**：v0.2.0 已实现第三方登录后的第二因素；本版补充 `/login?mfa_challenge=...` 的端到端测试，防止回归。

## 验证补充

- GitHub/Google 适配器用本地 fake provider 验证真实 HTTP 交换路径。
- SMTP 使用本地 fake SMTP server 验证运行时配置、发件人、主题与正文。
- 本地与 `linux/amd64` 镜像构建、容器内迁移/健康检查/SPA 冒烟通过；CI 新增 container job。

## 升级

无 schema 变更；替换镜像即可。OAuth 用户若已启用 MFA，登录仍会要求第二因素。
