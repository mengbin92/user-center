# 架构与分层

## 1. 目标与边界

`user-center` 是单一可部署的 Kratos 服务 + 单一 React SPA。它拥有：

- 账号（`users`）、凭据（`user_credentials`）、外部身份（`user_oauth_identities`）；
- 邮箱验证、密码恢复、MFA 与 Step-up（`auth_flow_completions`、`identity_mfa`、Redis 挑战）；
- 浏览器会话（`iam_sessions`、`iam_session_roles`）；
- 平台 IAM（资源、权限、角色、继承、分配、约束、菜单、审计）；
- 认证配置、导出任务、事务 Outbox。

它**不拥有**：模型 API Key、余额/流水/支付/订阅、路由组、渠道、公告、日志检索。原系统通过用户 ID 关联这些数据，通过 gRPC 读取最小身份事实。

## 2. 组件

| 组件 | 说明 |
|---|---|
| `cmd/user-center` | HTTP `:8080` + gRPC `:9090`；Wire 装配；可选一次性 root 自举 |
| `cmd/migrate` | MySQL 版本化 DDL；SQLite 开发 AutoMigrate；权限目录种子 |
| `cmd/admin-rescue` | 离线 root 创建/凭据恢复，必须拥有数据库与主机权限 |
| MySQL | 权威身份、IAM、审计、Outbox；账号隔离，运行账号无建表权限（生产建议） |
| Redis | 注册/重置/换绑验证码、登录限流、Step-up 证明、OAuth state；配置后不可用则启动失败，未配置时使用开发内存存储 |
| 邮件适配器 | `console`（开发）或 SMTP；配置可在管理端热更新；不依赖原 `notify-worker` |
| 第三方身份 | GitHub/Google OAuth2，服务端 code 交换；浏览器不接触 provider token |
| Outbox worker | 随主进程启动，订阅客户端 Webhook 投递，HMAC 签名 + 指数退避 |
| SPA | 用户门户 + 管理控制台，仅消费 `/api/v1` |

## 3. 分层契约

```text
client ──► DTO ──► service ──► DO ──► biz ──► DO ──► data ──► PO ──► MySQL
                                  ▲                ▲
                                  │ 仓储接口        │ 实现
                                  └────────────────┘
```

- `service`：proto ↔ DO；解析 query/pagination；设置/清理 Cookie；不访问存储。
- `biz`：DO、用例、仓储接口、授权决策、审计/Outbox 事务语义；不 import proto 生成的 HTTP 传输。
- `data`：GORM PO、仓储实现、Redis、SMTP；把驱动错误映射为 `biz` 错误。
- `domain/authorization`：纯类型与算法（Scope 求交、决策、继承图），不依赖任何存储/框架。
- `platform/httpx`：server 与 service 共享的已验证传输元数据（request_id、IP、CSRF），避免两层互相 import。
- `cmd` / `internal/wiring`：唯一装配点，Wire 生成 `wire_gen.go`。

## 4. 请求生命周期

```mermaid
sequenceDiagram
    participant B as Browser
    participant H as HTTP middleware
    participant S as Service
    participant U as Usecase
    participant D as Data
    B->>H: GET /api/v1/me (Cookie uc_session)
    H->>H: request_id, CSRF cookie, 安全响应头
    H->>D: ValidateSession(token)
    D-->>H: user + session + active roles
    H->>S: context(actor)
    S->>U: Me(actor)
    U->>D: users.Get / roles / mfa
    D-->>U: DO
    U-->>S: DO
    S-->>B: protojson JSON (snake_case)
```

写请求额外经过：CSRF 双提交校验 → 会话校验 → 用例内 `Authorize`（操作权限 + 目标范围 + 约束）→ 事务内 CAS + 审计 + Outbox。高风险操作再校验 Step-up。

## 5. 会话与身份版本

- 登录成功后生成 32 字节随机令牌；DB 存 `SHA-256(token)`，不存明文。
- 会话行包含 `identity_version`。每次请求比较用户当前 `identity_version`；不一致立即视为失效并撤销。
- 禁用、归档、密码重置、管理员 MFA 重置都会提升 `identity_version` 并撤销会话。
- 空闲超时由每次请求刷新 `idle_expires_at`；绝对过期由 `expires_at` 控制。
- 会话角色是 `iam_session_roles` 的子集；授权只使用当前会话激活的角色。

## 6. 授权决策

`biz.Services.LoadAuthzFacts` 读取：policy revision、用户 revision、全部角色（含 Grant 与继承边）、用户的有效分配、全部约束。然后：

1. 每个有效分配 → 继承闭包 → 每个有效角色的 Grant 生成 `GrantSource`；
2. 有效 Scope = `Grant.Scope ∩ Assignment.Boundary`；
3. `authorization.Evaluate` 依次检查身份、操作已绑定/启用、约束、allow 覆盖、deny 命中、业务规则；
4. 返回 `Decision{Allowed, Reason, Sources, ValidUntil}`；`Sources` 用于解释与审计。

管理操作在决策通过后还会执行两项治理拦截：

- `MFARequiredForAdmins` 为真时，root/admin 未绑定 TOTP 返回 `MFA_ENROLLMENT_REQUIRED`（认证与安全中心仍可用，以便完成绑定）；
- `must_change_password` 账号由 HTTP 中间件拦截 `/api/v1/admin/*`，返回 `PASSWORD_CHANGE_REQUIRED`。

受限角色（非 All scope）执行分配/撤销时，还必须命中一条有效委派：管理角色、目标角色、动作、目标用户范围与分配边界同时满足；root/All scope 不受此额外约束。

列表查询把 allow Scope 并集与 deny 排除集合一起下推到 SQL，先应用范围再计数和分页；self 解析为当前 actor ID。概览的用户、MFA、会话及登录事件统计使用同一可见用户集合。列表逐行决策保留为附加校验。

## 7. 事务与幂等

同一 MySQL 事务内完成：

- 创建用户 + 凭据 + 默认角色分配 + 完成记录 + 审计 + `user.created` Outbox；
- 修改资料 + revision CAS + 审计 + `user.profile.updated`；
- 禁用/归档 + 撤销会话 + 提升身份版本 + 审计 + 状态事件；
- 改密 + 密码版本 + 身份版本 + 撤销其他会话 + 审计 + 事件；
- 角色/权限/分配/约束变更 + policy revision + 审计 + 授权事件。

验证码使用“数据库完成记录唯一键 + Redis 校验后删除”的方式：重复提交被唯一键拒绝，数据库失败可在验证码删除前重试。

## 8. Outbox 与接入客户端

业务写在同一事务写 `event_outbox`。管理员创建的 `integration_clients` 保存允许的 gRPC 方法、事件订阅、回调 URL 与凭据摘要；凭据只在创建/轮换时返回一次。

工作线程每 15 秒：

1. 按客户端分页读取尚未入队的历史事件并创建 `event_deliveries`（唯一键去重，只投递客户端创建后的事件），积压不受最近 200 条窗口截断；
2. 原子领取到期的 pending/retrying 或租约已过期投递，向回调 URL POST JSON；
3. 成功写 `delivered`，失败按指数退避重写 `retrying` 与 `attempts`，最多保留历史，支持管理员重试。

请求头 `X-UserCenter-Signature: sha256=...` 对原始 body 做 HMAC（`OUTBOX_SIGNING_SECRET`）。投递为至少一次，消费端按 `event_id` 去重。事件载荷不含密码摘要、验证码、TOTP 秘钥、恢复码或第三方令牌。

## 9. 可观测性

- 每个请求生成/透传 `X-Request-ID`，写入安全事件与审计。
- 结构化日志（zap）记录启动、邮件、数据库/迁移错误。
- `/healthz` 供容器探针使用。
- Prometheus / OpenTelemetry 接入点保留在 `cmd` 启动层，当前未默认导出，避免无配置时产生外部依赖。
