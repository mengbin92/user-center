# User Center（统一用户中心）

从 [`micro-one-api`](https://github.com/mengbin92/micro-one-api) 抽离出来的独立用户中心。它拥有账号、凭据、邮箱验证、MFA、会话和平台 IAM 权限治理，拥有自己的 MySQL 数据库、Redis 命名空间、邮件适配器和前端 SPA，不依赖 Relay / Channel / Billing / Log / Config / Monitor / Notify 即可完成注册、登录、用户管理、密码恢复、MFA、会话撤销、角色授权与审计。

> **状态：v0.5.2 — V2.3 交付组织域 IAM 与多租户隔离：`organization:{id}` 授权上下文、组织自定义角色/授权、租户审计与上下文隔离查询；WebAuthn、SCIM、目录同步继续按 V2 里程碑推进。** 设计依据：`用户中心独立项目设计文档.md`（2026-11-02）。

## 目录

- [快速开始](#快速开始)
- [架构](#架构)
- [仓库结构](#仓库结构)
- [认证与安全模型](#认证与安全模型)
- [权限模型](#权限模型)
- [API 概览](#api-概览)
- [实现范围与已知差异](#实现范围与已知差异)
- [测试](#测试)
- [部署](#部署)
- [文档](#文档)

## 快速开始

### 本地 SQLite（无需 MySQL/Redis）

```bash
cd user-center

# 1. 建表 + 写入权限目录（SQLite 使用 AutoMigrate + SeedCatalog）
go run ./cmd/migrate -config configs/config.dev.yaml

# 2. 创建最高治理账号（离线命令，不接受 HTTP 万能口令）
go run ./cmd/admin-rescue -config configs/config.dev.yaml \
  -action bootstrap -username root \
  -password 'ChangeMe-12345' -email root@example.com

# 3. 启动 HTTP :8080 / gRPC :9090
go run ./cmd/user-center -config configs/config.dev.yaml
# 管理员默认被要求绑定 MFA：登录后先到 /account/security 完成 TOTP，
# 否则 /admin/* 返回 403 MFA_ENROLLMENT_REQUIRED。

# 4. 前端（另一个终端）
cd web && npm install && npm run dev   # http://localhost:5173
```

首次请求 `GET /api/v1/auth/context` 会下发 CSRF Cookie。浏览器端从 `uc_csrf` Cookie 读取令牌并在所有写请求中发送 `X-CSRF-Token`；会话只存在于 HttpOnly 的 `uc_session` Cookie 中。

### MySQL（生产形态）

```bash
cp configs/config.yaml configs/config.local.yaml   # 修改 DSN，勿提交真实密钥
export SESSION_SECRET="$(openssl rand -base64 48)"
export CSRF_SECRET="$(openssl rand -base64 48)"
export MFA_ENCRYPTION_KEY="$(openssl rand -base64 48)"
go run ./cmd/migrate -config configs/config.local.yaml
go run ./cmd/admin-rescue -config configs/config.local.yaml \
  -action bootstrap -username root -password '...' -email root@example.com
go run ./cmd/user-center -config configs/config.local.yaml
```

生产环境可用环境变量覆盖配置：`DB_DSN`、`REDIS_ADDR`、`SESSION_SECRET`、`CSRF_SECRET`、`MFA_ENCRYPTION_KEY`、`COOKIE_SECURE`、`COOKIE_DOMAIN`、`PUBLIC_BASE_URL` 等，详见 `internal/config/config.go`。内部 gRPC 使用数据库管理的接入客户端凭据。

## 架构

```mermaid
flowchart TB
    U[用户 / 管理员浏览器] --> EDGE[HTTPS 反向代理]
    EDGE --> SPA[React SPA]
    EDGE --> API[HTTP /api/v1]
    API --> MW[RequestID / CSRF / Session / 限流]
    MW --> SVC[service: DTO ↔ DO]
    SVC --> BIZ[biz: 用例 + 仓储接口 + 授权决策]
    BIZ --> DATA[data: MySQL / Redis / 邮件 / Outbox]
    DATA --> DB[(usercenter MySQL)]
    DATA --> REDIS[(Redis 挑战 / 限流 / Step-up)]
    BFF[原系统 BFF / 资源 owner] --> RPC[gRPC :9090]
    RPC --> BIZ
    DATA --> OUTBOX[(event_outbox)]
```

- **一个模块化的 Kratos 进程**：HTTP 与 gRPC 调用同一用例层，gRPC 不绕过任何校验。
- **分层契约**：`service` 只做 DTO ↔ DO；`biz` 拥有 DO、用例、仓储接口与决策；`data` 实现仓储与 PO。`cmd` 负责 Wire 装配。
- **独立数据权**：`users` 只保留身份字段；密码、MFA、外部身份、会话、IAM、审计各自成表。余额、路由组、API Key 等业务属性不进入用户中心。

## 仓库结构

```text
api/usercenter/v1/        auth / me / admin / iam / audit / settings / integration / integration_admin proto
cmd/user-center/          主服务（HTTP + gRPC + SPA）
cmd/migrate/              MySQL 版本化迁移 + 权限目录种子
cmd/admin-rescue/         离线 root 初始化 / 凭据恢复
cmd/import-legacy/        离线用户快照导入（dry-run / apply）
internal/conf/            配置 proto
internal/config/          配置加载 + 环境变量覆盖
internal/server/          HTTP/gRPC 装配、中间件、CSV 下载、SPA
internal/service/         DTO ↔ DO
internal/biz/             用例、端口、授权决策、审计、Outbox
internal/data/            GORM PO/仓储、Redis、邮件、种子
internal/wiring/          Wire ProviderSet 与 CLI 组装
domain/authorization/     纯授权类型、Scope 求交、决策、继承图
platform/httpx/           传输元数据契约
pkg/jsonx/                统一 JSON（sonic ConfigStd 语义）
pkg/totp/                 RFC 6238 TOTP
pkg/aesgcm/               AES-GCM
migrations/mysql/         版本化 DDL（001 起）
configs/                  无真实密钥的配置样例
deployments/docker-compose/
web/                      React 19 + TypeScript + Vite + Tailwind SPA
docs/                     架构 / API / 数据模型 / 迁移 / 运维 / 安全
scripts/                  开发与检查脚本
```

`pkg/jsonx`、`pkg/totp`、`pkg/aesgcm` 从 `micro-one-api` 按 MIT 许可证复制并独立维护；用户中心核心代码**不 import 原仓库**。

## 认证与安全模型

| 项 | 实现 |
|---|---|
| 浏览器会话 | 32 字节随机不透明令牌；DB 只存 SHA-256；HttpOnly + SameSite=Lax Cookie；服务端权威校验状态、身份版本、过期与空闲超时 |
| CSRF | 双提交 Cookie：非 HttpOnly 的 `uc_csrf` + 写请求 `X-CSRF-Token`；中间件对全部 `/api/v1` 非安全方法强制校验 |
| 密码 | bcrypt；最小字符数可配置（默认 10），最多 72 字节；修改密码后提升 `identity_version` 并撤销其他会话 |
| MFA | TOTP（RFC 6238）+ 8 个一次性恢复码；秘钥 AES-GCM 加密；`last_step` 防重放；5 次失败锁定 5 分钟 |
| Step-up | 高风险操作要求近期主认证 + 第二因素验证，证明绑定当前 session 与身份版本、5 分钟过期 |
| 邮箱 | 注册/换绑使用一次性验证码；验证码 HMAC 后存 Redis（无 Redis 时内存），单次消费 + 数据库完成记录幂等 |
| 审计 | 所有敏感写入在业务事务内写 `iam_audit_events`；登录与安全事件写 `security_events`；CSV 导出重新校验权限与范围 |
| 授权 | 权限目录 + 角色继承 + 分配边界 + 有效期 + 显式 deny + 职责分离约束；决策由服务端根据 DB 事实实时计算，客户端只消费投影 |

## 权限模型

- **Scope**：`all`、`self`、`user_ids`。授权关系 = 角色 Grant Scope ∩ 分配 Boundary；显式 deny 优先。
- **会话角色**：登录时默认激活全部有效分配；用户可在 `/me/session-roles` 切换到已分配角色的子集，切换时重新执行互斥约束。
- **数据范围**：管理员列表/详情/导出/会话接口同时执行操作权限与目标用户范围检查；受限管理员不会因分页或导出看到范围外用户。
- **职责分离**：`mutual_exclusion`（互斥角色）与 `max_roles`（角色数量）在分配和会话激活时分别校验。
- **内置角色**：`root`（受保护，拥有全部权限）、`admin`（账号与权限治理）、`member`（默认注册角色，仅本人范围）。

## API 概览

统一前缀 `/api/v1`，JSON 使用 `snake_case`，ID / revision 以十进制字符串输出。

| 接口族 | 路径 |
|---|---|
| 公开认证 | `/auth/context`、`/auth/registration-challenges`、`/auth/register`、`/auth/login`、`/auth/mfa/complete`、`/auth/logout`、`/auth/password-reset-challenges`、`/auth/password-reset` |
| 第三方登录 | `GET /auth/providers/{provider}/start`、`GET /auth/providers/{provider}/callback`（GitHub / Google；绑定使用 `?mode=bind`） |
| 本人 | `/me`、`/me/password:change`、`/me/email-challenges`、`/me/email:confirm`、`/me/security`、`/me/mfa:*`、`/me/sessions`、`/me/session-roles`、`/me/authorization`、`/me/security-events` |
| 用户管理 | `/admin/overview`、`/admin/users`、`/admin/users/{id}`、`{id}:set-status`、`{id}:archive`、`{id}/password-reset-requests`、`{id}/mfa:reset`、`{id}/email-changes*`、`{id}/sessions*`、`{id}/effective-permissions`、`/admin/users:export`、`/admin/exports/{id}`、`/admin/exports/{id}/download` |
| IAM | `/admin/iam/resources`、`permissions*`、`roles*`、`assignments*`（含列表）、`delegations*`、`constraints*`、`menus*`、`authorization:explain`、`authorization:simulate` |
| 接入服务 | `/admin/integration-clients*`、`/admin/event-deliveries*` |
| OIDC Provider | `/.well-known/openid-configuration`、`/oidc/jwks`、`/oidc/authorize`、`/oidc/token`、`/oidc/userinfo`；管理端 `/admin/oidc-clients*` |
| 组织 | `/api/v1/orgs`、`/orgs/{id}`、`/members*`、`/departments*`、`/iam/roles*`、`/iam/assignments*`、`/audits`；管理端 `/admin/organizations` |
| 审计 / 配置 | `/admin/audits*`、`/admin/settings/auth`、`/admin/settings/email` |
| 内部 gRPC | `ValidateSession`、`ValidateSubject`、`GetUser`、`BatchGetUsers`、`GetSessionAuthorization`、`GetResourceAuthorization`、`RevokeSession` |

完整契约见 [`openapi.yaml`](openapi.yaml) 与 `api/usercenter/v1/*.proto`。错误使用 HTTP 状态 + 稳定 `reason`（`REVISION_CONFLICT`、`STEP_UP_REQUIRED`、`PERMISSION_DENIED` 等），详见 [docs/api.md](docs/api.md)。

## 实现范围与已知差异

**已实现（V1）**：用户生命周期（创建/资料/启停/归档）、密码与邮箱变更、管理员邮箱变更、强制首次改密、TOTP + 恢复码、管理员强制 MFA、Step-up、会话治理、角色/会话角色、权限目录、角色继承、授权分配（含列表与批量，事务内整批拒绝）、委派、职责分离、菜单投影、授权解释/模拟、审计与导出、认证配置、GitHub/Google 登录与绑定、接入客户端管理、gRPC 客户端鉴权、Outbox Webhook 投递、`cmd/import-legacy` 离线导入。

**V2 已交付**：
- v0.3.0：标准 OIDC Provider（discovery/JWKS/authorization code + PKCE/token/userinfo/refresh）、OIDC 客户端管理与 RSA 签名密钥配置。
- v0.4.0：组织、部门与成员管理；owner/admin/member 组织角色；最后 owner 保护；平台管理员组织目录与归档；成员邮箱按角色脱敏。
- v0.5.0：组织域 IAM（`organization:{id}` 上下文、内置/自定义组织角色、组织内授权分配与权限目录）与多租户隔离（上下文查询、租户审计、跨租户拒绝）；存量组织自动回填。
- v0.6.0 W4/W5：WebAuthn/Passkey 第二因素与个人信息保留清理 CLI；V2.4 全量统一发 `v0.6.0`（MINOR），分波次明细见发布说明与波次附记。
- v0.6.0 W1/W2：OIDC 交互式同意页与 RP-initiated logout；组织邀请与接受、组织域授权解释、租户审计导出、组织域事件进 Outbox。
- v0.6.0 W3：内部 gRPC `Authenticate`/`CompleteMFA`、审计详情页、身份提供方配置页、用户名修改、单条分配预览、组织创建配额。
- v0.5.2：全项目审查修复——改密门禁覆盖组织路由、用户列表批量授权查询、组织域并发与隔离加固、`reason` 强制、Webhook 回调限制、迁移可恢复。

**仍延后（V2 后续里程碑）**：排期、验收标准与明确不做的项见 [V2.4 路线图](docs/roadmap-v2.4.md)。

- SCIM、企业目录同步、租户物理隔离与组织级 SoD；R13/R14 已实现，见下；
- OAuth 真实提供方沙箱验收：代码与本地 fake provider 测试已就绪，需配置真实凭据后执行；QQ 邮箱 SMTP 已完成真实发信与 IMAP 送达验收（[记录](docs/acceptance-smtp-2026-11-03.md)）；
- 委派目前约束“分配/撤销角色”的目标角色、用户范围与动作；角色 Grant/继承的变更仍要求直接权限，不允许通过委派修改策略本身；
- 原 `micro-one-api` 的 BFF 兼容层与适配器不在本仓库内，接入契约见 `docs/migration.md`；
- OpenAPI 未描述 Cookie/CSRF 安全方案与原始 OAuth/CSV 下载路由；这些在 `docs/api.md` 中约定；

这些差异不会把权限退化回 `role >= 10`：未实现的模块不暴露菜单/接口，而不是用空实现伪装完成。

## 测试

```bash
go test ./...           # 领域、仓储（SQLite）、HTTP 集成、MFA 全流程
cd web && npm test      # 前端组件测试
cd web && npm run build # tsc + vite 构建
```

关键覆盖：
- `domain/authorization`：Scope 求交/包含、deny、过期、继承环检测、`platform` / `organization:{id}` 上下文隔离与 `context_types` 拒绝。
- `internal/data`：唯一约束、revision CAS、会话哈希/撤销、目录种子幂等、legacy 导入、GitHub/Google 适配器（本地 fake provider）、SMTP（本地 fake server）、角色/分配跨上下文不可见与不可写。
- `internal/server`：未登录 401、缺失 CSRF 403、登录、受限管理员越权 403、并发更新 409、导出下载、MFA 完整登录、注册/重置/改密、管理员邮箱变更、OAuth 绑定/登录/OAuth+MFA、委派、接入客户端与 Outbox 投递、MFA 强制与首次改密拦截、OIDC 授权码 + PKCE/refresh/userinfo、OIDC 客户端管理、组织/成员/部门与最后 owner 保护、组织自定义角色与授权、跨租户拒绝、租户审计过滤、存量组织 IAM 回填；OIDC 同意（首次/复用/拒绝/扩权/撤销/prompt）、end_session 白名单与幂等、邀请接受/过期/撤销/配额/跨租户、组织域 explain、租户审计导出隔离与 CSV 注入转义、组织事件 PII 与订阅过滤、gRPC 登录与 MFA 挑战重放、用户名修改冲突、单条预览与组织配额。
- `docker build` / `docker buildx --platform linux/amd64`：镜像内迁移、健康检查与 SPA 均已验证。
- 真实 SMTP：QQ 邮箱 587/STARTTLS 发信并在收件箱确认（opt-in `TestLiveSMTP`）。

## 部署

```bash
cd deployments/docker-compose
cp .env.example .env   # 设置 MYSQL_PASSWORD / SESSION_SECRET / CSRF_SECRET / MFA_ENCRYPTION_KEY
docker compose up -d --build
```

镜像同时包含 `user-center`、`migrate`、`admin-rescue` 与已构建的 SPA。`migrate` 以一次性任务运行，成功后主服务才启动。HTTPS、安全响应头与 Cookie `Secure` 由反向代理和 `COOKIE_SECURE=true` 共同保证。详见 [docs/operations.md](docs/operations.md)。

## 文档

- [架构与分层](docs/architecture.md)
- [API 契约与错误码](docs/api.md)
- [数据模型](docs/data-model.md)
- [从 micro-one-api 迁移](docs/migration.md)
- [运维手册](docs/operations.md)
- [安全设计](docs/security.md)
- [前端说明](docs/frontend.md)
- [V2.4 路线图](docs/roadmap-v2.4.md)
- [v0.6.0 发布说明](docs/releases/release-v0.6.0.md)
- [W3 波次附记](docs/releases/release-v0.7.0.md)
- [W4/W5 波次附记](docs/releases/release-v0.8.0.md)
- [v0.5.2 发布说明](docs/releases/release-v0.5.2.md)
- [v0.5.1 发布说明](docs/releases/release-v0.5.1.md)
- [v0.5.0 发布说明](docs/releases/release-v0.5.0.md)
- [v0.4.0 发布说明](docs/releases/release-v0.4.0.md)
- [v0.3.0 发布说明](docs/releases/release-v0.3.0.md)
- [v0.2.1 发布说明](docs/releases/release-v0.2.1.md)

## License

MIT，见 [LICENSE](LICENSE)。`pkg/jsonx`、`pkg/totp`、`pkg/aesgcm` 来自 `micro-one-api`（Copyright (c) 2026 孟斯特），按同一许可证维护。
