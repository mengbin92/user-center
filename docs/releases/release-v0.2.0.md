# v0.2.0 · 2026-11-02

上一版：[v0.1.0](./release-v0.1.0.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.2.0)

## 版本说明

v0.2.0 完成用户中心 V1 的治理与集成闭环：管理员强制 MFA、首次改密、OAuth 登录/绑定、可委派的受限授权、接入客户端与 Outbox 投递，以及离线迁移工具。0.1.0 已交付账号、会话、IAM、审计和双端 SPA。

## 主要变更

1. **管理员 MFA 与首次改密**
   - 管理授权入口在 `MFARequiredForAdmins` 为真且未绑定 TOTP 时返回 `MFA_ENROLLMENT_REQUIRED`，但保留安全中心完成绑定。
   - 初始密码账号登录返回 `password_change_required`，改密前 `/admin/*` 被中间件阻断并返回 `PASSWORD_CHANGE_REQUIRED`。

2. **第三方登录**
   - GitHub/Google OAuth2 服务端 code 交换、单次 state、HttpOnly state Cookie。
   - 绑定模式要求已登录会话；不按邮箱自动合并。
   - 已启用 MFA 的账号 OAuth 登录仍进入第二因素，不直接建立会话。

3. **治理能力**
   - 管理员邮箱变更：新邮箱验证码 + Step-up + 身份版本提升 + 会话撤销。
   - 授权分配列表、用户/审计导出过滤。
   - 委派 CRUD；受限角色分配/撤销时校验管理角色、目标角色、用户范围、动作与边界。

4. **接入与事件**
   - 接入客户端凭据一次性展示、SHA-256 存储、gRPC 方法白名单、轮换/停用。
   - Outbox Webhook worker：HMAC-SHA256、至少一次投递、指数退避、投递列表与手动重试。

5. **迁移**
   - `cmd/import-legacy` dry-run/apply、冲突报告、保留用户 ID 与 bcrypt 摘要、角色分配、`legacy_import_batches` 记录。

6. **前端**
   - 登录/绑定提供方按钮、OAuth 回调、强制改密与 MFA 提示、管理员邮箱变更、分配列表、委派、接入服务页面。

## 兼容性

- 新增 MySQL 迁移 `002_delegations_integrations.sql`；从 0.1.0 升级需先执行 `cmd/migrate`。
- `iam.assignment.create/revoke` 增加 `user_ids` scope 支持；种子会更新目录元数据。
- 默认 `MFARequiredForAdmins=true`：root 首次登录后需先绑定 TOTP。
- OAuth/SMTP 仍需真实凭据；代码已用本地 fake provider/SMTP 测试。

## 升级步骤

1. 备份 MySQL 与制品。
2. 构建/拉取 v0.2.0 的 `migrate` 与主服务镜像。
3. 执行 `migrate`（001 + 002）。
4. 滚动重启；root 完成 MFA 绑定。
5. 验证登录、`/me/authorization`、用户列表、审计、OAuth（如配置）。

## 验证

- `go test ./...`、`go vet ./...`
- `cd web && npm run build && npm test`
- MySQL 8.4 迁移与 root 登录/MFA 拦截
- Docker 镜像构建与容器内迁移/健康检查/SPA
- GitHub Actions backend、frontend、container 三个任务

## 完整变更日志

见 [CHANGELOG.md](../../CHANGELOG.md) 的 `[0.2.0]`。
