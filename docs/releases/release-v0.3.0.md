# v0.3.0 · 2026-11-03

上一版：[v0.2.1](./release-v0.2.1.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.3.0)

## V2 启动：标准 OIDC Provider

- Discovery / JWKS / Authorization / Token / UserInfo。
- Authorization Code + S256 PKCE；public client 强制 PKCE；redirect_uri 精确匹配。
- RS256 ID/access token；`nonce`、`auth_time`、`profile`/`email` scope claims。
- `offline_access` 刷新令牌，单次使用并轮换。
- 管理端 `admin/applications`：创建/更新/轮换密钥/停用；密钥只展示一次。
- RSA 签名密钥通过 `OIDC_SIGNING_KEY_PATH`/`OIDC_SIGNING_KEY_PEM` 提供；未配置时开发环境使用临时密钥（重启失效）。

## SMTP 真实验收

QQ 邮箱 587/STARTTLS 发信并被 IMAP 收件箱确认；代码同时支持 465 implicit TLS。凭据仅从环境变量读取，不进入仓库。详见 [SMTP 验收记录](../acceptance-smtp-2026-11-03.md)。

## 兼容性/升级

- 新增 MySQL 迁移 `003_oidc.sql`；执行 `cmd/migrate`。
- 新增环境变量 `OIDC_ISSUER`、`OIDC_SIGNING_KEY_PATH`/`OIDC_SIGNING_KEY_PEM`、`OIDC_ACCESS_TTL_SECONDS`、`OIDC_REFRESH_TTL_SECONDS`。
- 生产必须提供稳定 RSA 私钥，否则重启后已签发 token 无法验证。
- OIDC 客户端默认对管理员预注册的客户端自动同意；交互式 consent / end-session 在 V2.2。

## 验证

- Go 全量测试、OIDC 授权码/刷新/userinfo/客户端管理测试。
- 前端构建与测试。
- MySQL 8.4 001/002/003 迁移。
- Docker 镜像与容器冒烟（CI container job）。

## 完整变更日志

见 [CHANGELOG.md](../../CHANGELOG.md) `[0.3.0]`。
