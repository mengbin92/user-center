# 运维手册

## 1. 前置条件

- MySQL 8.x（生产唯一验收数据库）、Redis 7.x（多实例部署必需；仅未配置 Redis 的单进程开发环境可使用内存存储）。
- HTTPS 反向代理（Nginx/Caddy/网关），负责 TLS、请求体上限、基础 WAF。
- 独立数据库账号；生产账号不应具备跨库读取或 DDL 权限（DDL 由 `migrate` 专用账号执行）。

## 2. 密钥

| 环境变量 | 用途 |
|---|---|
| `SESSION_SECRET` | 验证码 HMAC 与内部签名材料；变更会使未完成验证码失效 |
| `CSRF_SECRET` | 保留给签名型 CSRF 扩展；当前双提交不依赖它，但生产必须设置 |
| `MFA_ENCRYPTION_KEY` | TOTP secret AES-GCM 密钥；**丢失将无法解密现有 MFA** |
| `OUTBOX_SIGNING_SECRET` | Outbox Webhook HMAC-SHA256 签名密钥；启用订阅时必须配置独立的至少 32 字节随机密钥 |
| `OAUTH_GITHUB_CLIENT_ID/SECRET` | GitHub 登录；两者都设置才启用 |
| `OAUTH_GOOGLE_CLIENT_ID/SECRET` | Google 登录；两者都设置才启用 |
| `OIDC_ISSUER` | OIDC issuer，默认 `PUBLIC_BASE_URL`；必须与 discovery 地址一致 |
| `OIDC_SIGNING_KEY_PATH` / `OIDC_SIGNING_KEY_PEM` | RS256 私钥（PEM）；生产必须配置稳定密钥 |
| `OIDC_ACCESS_TTL_SECONDS` / `OIDC_REFRESH_TTL_SECONDS` | 默认 900 / 86400 秒；客户端可覆盖 |

SMTP 支持 465 implicit TLS 与 587 STARTTLS；真实 QQ 邮箱验收步骤见
[SMTP 验收记录](acceptance-smtp-2026-11-03.md)。
| `COOKIE_SECURE` | 生产 `true` |
| `COOKIE_DOMAIN` | 门户域名；留空表示 host-only |
| `PUBLIC_BASE_URL` | 邮件链接基址 |

生成：

```bash
openssl rand -base64 48   # 每个密钥单独生成
```

密钥只通过环境变量/密钥管理注入，不写入镜像、Compose 文件或 Git。轮换 `MFA_ENCRYPTION_KEY` 需要先离线解密再以新密钥重加密；当前未内置批量轮换工具，轮换前必须演练。

## 3. 部署

```bash
cd deployments/docker-compose
cp .env.example .env
# 编辑 .env：MYSQL_PASSWORD、SESSION_SECRET、CSRF_SECRET、MFA_ENCRYPTION_KEY、PUBLIC_BASE_URL、COOKIE_SECURE
docker compose up -d --build
docker compose ps
docker compose logs -f user-center
```

顺序：`mysql` 健康 → `migrate` 一次性执行（DDL + 权限目录）；`migrate` 成功且 `redis` 健康后启动 `user-center`。默认 HTTP/gRPC 仅映射到宿主机 `127.0.0.1`，供本机反向代理和受信接入使用。MySQL 密码必须显式配置；镜像构建会排除 `.env`、`.env.*` 与 `configs/config.local.yaml`。镜像默认命令可被 Compose 的 `command` 和 `docker compose run` 覆盖，支持 `/app/migrate`、`/app/admin-rescue` 与 `/app/import-legacy`。

首次初始化 root：

```bash
docker compose run --rm user-center /app/admin-rescue \
  -config /app/configs/config.docker.yaml -action bootstrap \
  -username root -password '...' -email root@example.com
```

或在 `.env` 设置 `USER_CENTER_BOOTSTRAP_USERNAME/PASSWORD`，主服务启动时自举（仅当用户名不存在时）。生产建议使用离线 `admin-rescue`，不要在长期环境变量中保留初始密码。

> 管理员默认受 `MFARequiredForAdmins` 约束：root 首次登录后必须先到 `/account/security` 绑定 TOTP，之后 `/admin/*` 才会放行；否则返回 `MFA_ENROLLMENT_REQUIRED`。管理员新建用户若设置了初始密码，用户首次登录会被要求改密。

第三方登录回调地址为 `PUBLIC_BASE_URL + /api/v1/auth/providers/{provider}/callback`，需要在 GitHub/Google 控制台登记。

## 4. 反向代理

要求：

- 终止 TLS；转发 `Host`、`X-Forwarded-For`、`X-Real-IP`；设置 `TRUST_PROXY_HEADERS=true` 时才会信任这些头。
- 请求体上限 ≤ 1 MiB；禁用代理层缓存 `/api/`。
- 透传 `Set-Cookie`（不要重写 `uc_session`/`uc_csrf`）。
- 将 `/.well-known/openid-configuration`、`/oidc/` 与 `/api/` 一起转发到后端；SPA 由同一后端托管时无需额外配置。
- 建议安全头：`Strict-Transport-Security`、`Content-Security-Policy`（SPA 资源同源）、`X-Content-Type-Options`（服务已设置后者）。

Nginx 片段：

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_http_version 1.1;
  client_max_body_size 1m;
}
```

## 5. 健康检查与日志

- `GET /healthz` → `{"status":"ok"}`；仅表示进程存活，不代表 DB/Redis 可用。
- 日志为 zap JSON；关注 `open database`、`send mail failed`、`run migrations`。
- 每个请求的 `X-Request-ID` 会写入安全事件与审计；排障时先取该 ID。

### 5.1 指标与采集（v0.7.0）

指标在**独立监听端口**暴露，不走 `/api/v1`，不需要会话，也不经过反向代理：

| 项 | 值 |
|---|---|
| 默认地址 | `127.0.0.1:9091`（只绑回环） |
| 覆盖方式 | `METRICS_ADDR` 环境变量或 `server.metrics.addr` |
| 关闭 | `METRICS_ADDR=off`（也接受 `none` / `disabled`） |
| 抓取路径 | `GET /metrics`（同端口另有 `/healthz`） |
| 刷新周期 | 30 秒，`server.metrics.refresh_seconds` 可调 |

**不要**把该端口挂到公网反代上。指标不含用户标识，但会暴露路由表与流量规模。

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `usercenter_http_requests_total` | counter | `route`、`method`、`status` | 已认证/未认证都计数，401/403 短路同样计入 |
| `usercenter_http_request_duration_seconds` | histogram | `route`、`method` | 桶 5ms–5s |
| `usercenter_event_deliveries` | gauge | `status` | Outbox 投递行数，未知状态归 `other` |
| `usercenter_schema_migrations_applied` | gauge | — | 已记录的迁移步数（按语句计，不等于文件数） |
| `usercenter_dependency_up` | gauge | `dependency` | 1 = 上次探测成功；`mysql` / `redis` |

`route` 是路由模板而非原始路径：`/api/v1/orgs/7/members` 与 `/api/v1/orgs/11/members` 都记到 `/api/v1/orgs/{id}/members`。SPA 历史路由与未知路径统一记为 `spa`，因此标签基数由路由表决定，不会随用户输入增长。

两个容易误读的点：

- **SQLite 开发实例**下 `usercenter_schema_migrations_applied` 为 `0`，因为 SQLite 走 AutoMigrate，不写 `schema_migrations`；MySQL 才逐步记录。
- 未配置 Redis（内存回退模式）时 `usercenter_dependency_up{dependency="redis"}` 为 `1`，含义是"该依赖不适用"，不是"Redis 可用"。

Prometheus 抓取示例：

```yaml
scrape_configs:
  - job_name: user-center
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9091"]
```

跨主机部署时把地址改为该主机的内网地址，并在安全组/防火墙上只放行 Prometheus 实例。容器部署时容器内的 `127.0.0.1` 在宿主机不可达，因此 compose 已把 `METRICS_ADDR` 设为 `0.0.0.0:9091` 并把端口发布在 `127.0.0.1:9091`（只回环，不默认暴露）；需要换端口或关闭时改这两处，关闭用 `METRICS_ADDR=off`。`scripts/e2e/compose-e2e.sh` 会断言该端点从宿主机可抓取，避免"端口绑了但没发布"这种只有告警响时才发现的问题。

日志字段（结构化，字段名稳定）：

| 场景 | 字段 |
|---|---|
| 慢请求（超过 `SLOW_REQUEST_THRESHOLD_MS`，默认 500ms） | `request_id`、`route`（模板，非原始路径）、`method`、`status`、`duration_ms` |
| 邮件投递失败 / console 投递 | `request_id`、`to`（**已脱敏**：`a***@example.com`）、`subject` |

请求体、请求头、查询串、Cookie、密码、验证码、一次性令牌**从不出现在日志里**，`internal/server/logging_test.go` 用字段白名单与内容断言守着这条规则（新增字段会让测试失败，必须显式审查）。`X-Request-ID` 在 HTTP 与 gRPC 两条入口都会注入（缺省生成，超长替换而非截断），审计表的 `request_id` 与日志可互相定位。

### 5.2 SLO 与告警（v0.7.0）

服务目标（单实例，来自 `docs/performance.md` 的实测水位）：

| 指标 | 目标 | 依据 |
|---|---|---|
| 可用性 | 月度 99.9% | 5xx 比例是主要信号 |
| P95 延迟 | < 300 ms | 实测 32 VUs 下 P95 < 60 ms，300 ms 是"明显不正常"的线 |
| 5xx 比例 | < 1% | 正常应为 0（冒烟与压测均为 0） |
| Outbox 未投递 | < 1000 条 | 正常为个位数；上千意味着订阅方故障 |
| DB 连接池占用 | < 90% 且无排队 | 池耗尽的表现与"数据库慢"无法区分，必须单独看 |

告警规则在 [`deployments/prometheus/alerts.yml`](../deployments/prometheus/alerts.yml)，接入方式：

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/user-center.yml
```

| 告警 | 触发条件 | 影响 | 首步排查 |
|---|---|---|---|
| `UserCenterHighErrorRate` | 5xx 占比 > 1%，持续 5 分钟 | 用户看到报错 | `/metrics` 找 5xx 最多的 route → 用该请求的 `request_id` 查日志；503 多为依赖不可用 |
| `UserCenterLatencyHigh` | P95 > 300 ms，持续 10 分钟 | 全站变慢 | 先看连接池 `in_use/max` 与 `wait_total` 增长率，排除池饱和再查 SQL |
| `UserCenterLoginFailureSpike` | 登录非 2xx 占比 > 50% 且 > 0.2 req/s，持续 10 分钟 | 用户无法登录 | 按状态码拆分：429 = 限流正常工作、401 = 撞库或客户端配置错误、5xx = 认证链路故障 |
| `UserCenterOutboxBacklog` | 未投递事件 > 1000，持续 15 分钟 | 下游收不到变更 | 查 `event_deliveries` 按 subscriber 分组，通常单个订阅方不可达 |
| `UserCenterDependencyDown` | `dependency_up == 0`，持续 2 分钟 | MySQL 时全站不可用；Redis 时退化为内存会话 | Redis 回退后重启会丢全部会话，需提前告知 |
| `UserCenterDBPoolExhausted` | 占用 > 90% 且 `wait_total` 在涨，持续 5 分钟 | 请求排队，延迟飙升 | 先确认 `max_open_conns` 不是 SQLite 的 1；能加就加，不能加先限流 |
| `UserCenterMigrationsNotApplied` | `schema_migrations_applied == 0`，持续 10 分钟 | 表结构缺失，功能大面积报错 | `migrate` 一次性任务没跑或失败；**该规则仅对 MySQL 部署启用**，SQLite 走 AutoMigrate 时此值恒为 0 |

为什么 P95 用直方图而不是平均值：平均值会被大量快请求稀释，掩盖尾部；实测里 admin 列表修复前 P50 88 ms 时 P95 已 111 ms，平均值看不出问题。

## 6. 离线导入与事件投递

```bash
# 先 dry-run（默认），输出冲突与计数；无冲突后加 -apply
go run ./cmd/import-legacy -config configs/config.local.yaml -file legacy.json
go run ./cmd/import-legacy -config configs/config.local.yaml -file legacy.json -apply

# 查看/重试 Outbox 投递（管理员 API）
curl ... /api/v1/admin/event-deliveries
curl -X POST ... /api/v1/admin/event-deliveries/{event_id}/subscribers/{subscriber_id}:retry
```

Webhook 工作线程随主服务启动，每 15 秒拉取一次；`X-UserCenter-Signature: sha256=<hex>` 对**原始请求体**做 HMAC。消费端必须按 `event_id` 去重，并拒绝旧 `aggregate_revision` 覆盖新状态。`integration-clients` 的凭据只在创建/轮换响应中出现一次。

## 7. 备份与恢复

```bash
# 数据库
mysqldump --single-transaction --routines --triggers \
  -h HOST -u usercenter -p usercenter > usercenter-$(date +%F).sql

# 导出制品
docker run --rm -v user-center_artifacts:/data -v "$PWD":/backup alpine \
  tar czf /backup/artifacts-$(date +%F).tgz -C /data .
```

恢复：

1. 停 `user-center`，保留 `migrate` 镜像版本；
2. 恢复 MySQL 到同版本 schema；
3. 恢复制品目录（可选，导出任务可重新生成）；
4. 启动服务并执行 `GET /healthz`、管理员登录、`/me/authorization` 抽查。

审计表不允许通过恢复旧备份回滚来“消除”事件；如有合规要求，应在恢复后记录恢复操作本身。

## 8. 紧急恢复 root

```bash
# 主机/数据库权限 + 离线命令，不接受 HTTP 万能口令
docker compose run --rm user-center /app/admin-rescue \
  -config /app/configs/config.docker.yaml -action reset -username root -password '...'
```

`reset` 会校验目标确实是 root 角色成员，更新密码、提升身份版本、撤销全部会话并写审计。若 root 账号被归档/禁用，`reset` 会恢复为 `enabled`。遗失 MFA 设备且无恢复码时，另行执行 `-action reset-mfa -username root`；该动作移除 MFA、提升身份版本、撤销会话并同事务写入审计和事件，不隐含在密码重置中。离线迁移、导入与救援命令不依赖 Redis。

## 9. 常见故障

| 现象 | 排查 |
|---|---|
| 所有写请求 403 `PERMISSION_DENIED` | 缺少 `X-CSRF-Token` 或与 `uc_csrf` 不一致；前端先请求 `/auth/context` |
| 登录后立即 401 | 会话 Cookie 未透传、`COOKIE_SECURE` 与访问协议不匹配、或用户被禁用/身份版本已变 |
| 管理员 403 | 检查 `iam_user_roles` 是否 active、角色状态、Scope 边界与 deny、会话激活角色 |
| 409 反复出现 | 前端未回读最新 revision；不要自动重放高风险写 |
| 验证码总是无效 | Redis key 前缀/DB 不一致、时钟漂移、验证码过期或已消费；检查 `SESSION_SECRET` 是否变更 |
| MFA 验证码无效 | 设备时钟漂移 > 30s；检查 `last_step` 与锁定时间 |
| 邮件未发送 | `console` 驱动只记录收件人和主题，不输出正文/验证码；开发收信应使用本地 SMTP。SMTP 驱动检查 host/port/凭据/发件人 |

## 10. 升级

1. 备份数据库与制品；
2. 构建/拉取新镜像（`migrate` 与主服务同版本）；
3. 先运行 `migrate`；DDL 必须向后兼容一个版本；
4. 滚动重启主服务；
5. 验证登录、`/me/authorization`、用户列表、审计写入；
6. 保留上一版本镜像用于回退。回退二进制前确认新迁移未引入不可逆列删除。

## 11. 容量与扩展

- 会话保存在 MySQL；多实例部署必须共享 Redis 以存储挑战、限流与 Step-up。配置 Redis 后连接失败会阻止启动。gRPC 仅接受数据库管理的接入客户端凭据；所有实例使用同一数据库与密钥。
- 授权事实每次请求实时读取 DB；用户/角色规模增大后应加入带版本失效的缓存，缓存键必须包含 policy/user/session revision。
- 导出为同步生成，大表导出应迁移到异步 worker（当前限制 100000 行）。
- 审计表增长快，建议按月分区或归档到只读存储；不要删除普通管理员可见的审计证据。

## 个人信息保留与清理（V2.4 R14）

`cmd/retention` 对**已归档**且超过保留期的账号做不可逆匿名化。默认保留期 **365 天**（按 `users.archived_at` 计算），可用 `RETENTION_DAYS` 环境变量或 `-retention-days` 覆盖。

清理范围：`users.username / username_normalized / display_name / email / email_normalized / email_verified_at`、`user_credentials`、`identity_mfa`（含恢复码）、`iam_sessions`、`iam_session_roles`、`user_oauth_identities`、`webauthn_credentials`。审计事件与 Outbox 事件**不删除**，只保留不可逆的 `user_id`；`users.anonymized_at` 作为幂等标记，已清理账号不会再次入选。

### ⚠️ 执行前必须完成的流程

1. **备份**：对 MySQL 做一次完整逻辑备份（`mysqldump --single-transaction`），并确认备份可恢复。清理不可逆。
2. **双人确认**：由数据 owner 与运维各自复核 dry-run 报告；实际写入需要同时传 `-apply` 与 `-acknowledge=I_HAVE_BACKED_UP`。
3. **先 dry-run**：默认即为 dry-run，输出 JSON 报告（scanned / eligible / cleaned / skipped_legal_hold / failed 与候选 user_id）。
4. **执行**：仅限窗口期执行，保留结构化日志与审计事件。
5. **复核**：确认 `identity.retention.cleanup` 审计条数等于 `cleaned`，且候选账号的审计仍可按 user_id 追溯。

```bash
# 1. 预览（默认 dry-run，不写库）
go run ./cmd/retention -config configs/config.yaml -retention-days 365 -limit 100

# 2. 加/解 legal hold（命中则跳过清理）
go run ./cmd/retention -config configs/config.yaml -hold-user 42 -hold-reason '诉讼保全 2026-xx'
go run ./cmd/retention -config configs/config.yaml -release-user 42 -release-reason '保全解除'

# 3. 实际执行（需备份 + 双人确认）
go run ./cmd/retention -config configs/config.yaml -apply -acknowledge=I_HAVE_BACKED_UP
```

> 该命令不随服务常驻，也不由容器自动执行；是否纳入定时任务由部署方按合规要求决定。所有写入与审计在同一事务提交，失败不会留下半匿名化账号。
