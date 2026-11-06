# v0.6.0 · 2026-11-05

上一版：[v0.5.2](./release-v0.5.2.md)

**版本判定：MINOR（v0.5.2 → v0.6.0）。** 本次为新增能力（R1–R14 与工程前置），无破坏性契约变更；虽有 code review 缺陷修复，但均随本次新增能力一并交付，不单独构成 PATCH 版本。

> 发版决策：路线图 §5 原建议 W1/W2→`v0.6.0`、W3→`v0.7.0`、W4→`v0.8.0` 分波次打标。实际情况是三波连续合入同一 `develop` 分支，且 `e526362` 的 P1 安全修复横跨全部波次；若把 tag 打在历史 commit 上，v0.6.0/v0.7.0 会缺少已修复的安全问题。因此本次改为**一次对外交付 = 一个 MINOR**：统一打 `v0.6.0` 于最终 commit，三份波次说明保留为追溯记录（`release-v0.6.0-w3.md`、`release-v0.6.0-w4w5.md` 标注为波次附记，不单独打标）。路线图 §5 与变更记录已同步。

本版包含 V2.4 路线图 W1–W5 共 14 个工作项（R1–R14）、一次完整 code review 修复，以及 E2E 冒烟脚本收纳。W4 原「可滑动到 V2.5」、W5 原「未排期」，按用户要求一并交付。

## 数据库迁移

- `007_oidc_consent.sql`：`oidc_consents`、`oidc_consent_requests`；`oidc_clients.post_logout_redirect_uris`；`export_jobs.organization_id`。
- `008_org_invitations.sql`：`organization_invitations`。
- 权限目录新增 `settings.organization.read/update`；菜单新增 `account/consents`、`admin/settings/providers`、`admin/settings/organization`。

## OIDC 收尾

- **R1 交互式同意页**：`/oidc/authorize` 校验通过后不再直接签码。首次授权或 scope 扩张时把已校验请求暂存为一次性服务端 handle，302 到 `/consent?handle=...`；同意页只展示客户端、scopes 与回调来源，由 `POST /api/v1/me/oidc-requests/{handle}:decide` 在服务端签码。
- `prompt=consent` 强制重新征询；`prompt=none` 且无同意返回 `interaction_required`，不会静默同意或 500。
- `/me/oidc-consents` 可列出与撤销；撤销后下次授权重新征询。
- **R2 RP-initiated logout**：discovery 新增 `end_session_endpoint`；`GET/POST /oidc/logout` 支持 hint、client_id、state 与白名单精确匹配；撤销会话并清理 Cookie；重复调用幂等；无效/过期/跨客户端 hint 与缺失 hint 行为一致。

## 组织企业化

- **R3 邀请与接受**：按邮箱邀请，令牌只出现在邮件中、DB 存哈希、默认 72 小时（`ORG_INVITATION_TTL_HOURS` 可配 1–720）；接受要求登录且邮箱归一化后完全匹配，不匹配统一 404；不自动建号；接受后同步内置角色授权；过期/撤销/重复接受/已是成员/配额/跨租户各有稳定错误码与审计。
- **R4 组织域 explain**：`GET /api/v1/orgs/{id}/iam/authorization:explain`，权限为组织角色/分配读权限，只加载本租户事实，复用平台 explain 的 `authorization.Evaluate` 与同一 Input 构造；非成员返回 404。
- **R5 租户审计导出**：`POST /api/v1/orgs/{id}/audits:export` 复用平台 CSV/导出任务/下载签名；任务行记录 `organization_id`，跨租户下载、权限或 policy revision 变化均返回 404；CSV 公式前缀转义沿用现有规则。
- **R6 组织域事件**：成员/部门/角色/分配/归档事件与业务事务同提交进 Outbox；载荷只含 ID/revision/角色码；订阅按 `event_type` 过滤；事件表见 [架构 §8.1](../architecture.md)。

## W3 / W4 / W5 摘要

- W3（[波次附记](./release-v0.6.0-w3.md)）：内部 gRPC 登录、审计详情页、provider 配置页、用户名修改、单条分配预览、组织创建配额。
- W4（[波次附记](./release-v0.6.0-w4w5.md)）：WebAuthn/Passkey 第二因素（真实 COSE/ES256 验签、sign_count 回退拒绝、Step-up 与登录 MFA）。
- W5（同上）：`cmd/retention` 个人信息保留清理、dry-run/双人确认/legal hold/幂等匿名化。
- Code review（[提交 e526362]）：16 项问题修复，含配额拒绝审计被事务回滚、gRPC 会话被当浏览器 Cookie、HTTP/gRPC MFA 挑战混用、provider 空列表语义冲突、邀请并发与幽灵邀请、租户导出平台路由复检等。
- 工程前置：`scripts/e2e/smoke.sh`（`--base-url`、自动清理、失败快照），本地 dev 实例 E2E 全部步骤通过。

## 验证

`./scripts/check.sh`（gofmt + go vet + go test + npm test + npm run build）通过；`go test -race ./domain/... ./internal/biz/ ./internal/data/` 通过；`make api` / `make wire` 生成物无差异；MySQL 8.4 容器真实应用 `001–011` 两次幂等通过；本地 dev 实例 E2E 冒烟通过；**本地 compose 全栈冒烟通过（连续两次全绿）**。

`go vet ./...`、`go test ./...`、`cd web && npm test && npm run build` 全部通过；新增 HTTP 级用例覆盖同意首次/复用/拒绝/扩权/撤销/prompt、登出白名单与幂等、邀请过期/撤销/配额/跨租户、explain 允许/拒绝/过期分配、租户导出隔离/403/CSV 注入/policy revision、组织事件 PII/回滚/去重/订阅过滤。MySQL 迁移真跑已在临时 `mysql:8.4` 容器执行（001–011 两次幂等应用通过）；compose 全栈（MySQL 8.4 + Redis 7 + migrate + user-center）冒烟两次通过。

## compose 冒烟结果（2026-11-05）

| 项 | 结果 |
|---|---|
| 镜像 | `user-center:latest` 重建，创建时间与 `HEAD` 一致 |
| 容器 | mysql/redis healthy，migrate `Exited (0)`，user-center `healthy` |
| 迁移 | `schema_migrations` 含 `010_webauthn`、`011_retention`；`webauthn_credentials`、`user_legal_holds`、`users.anonymized_at` 均存在 |
| 冒烟 | `scripts/e2e/smoke.sh --compose ... --compose-env ...` 连续两次全部步骤通过 |
| 日志 | 两次运行期间容器日志 0 条 `level=error`、0 个 5xx |
| 落库 | 2 个组织、3 条审计（bootstrap + 2×`organization.create`）、3 条 Outbox（`user.created` + 2×`organization.created`） |

> 首轮失败根因并非环境不可用：`docker compose build | tail` 让管道退出码恒为 0，构建失败被吞掉，`up -d` 复用了 11-04 的旧镜像（镜像内没有 V2.4 路由，`/api/v1/me/oidc-consents` 返回 404）。改为「构建输出落日志 + 校验真实退出码 + 比对镜像创建时间」后一次通过。`scripts/e2e/smoke.sh` 同时新增 `--compose-env`，否则带 `:?` 强制校验的 compose 文件连 `logs` 都无法解析。

## 未执行 / 已知限制

- 真实浏览器 WebAuthn 交互未在硬件认证器上验收；服务端验证链由软件 P-256 认证器端到端覆盖。
- 清理任务不常驻、不自动调度，是否纳入定时任务由部署方按合规要求决定。
- compose 冒烟使用密码账号夹具（bootstrap root + 显式关闭「管理员必须 MFA」策略），管理员 MFA 登录链路本身由 `go test` 的 TOTP/WebAuthn 用例覆盖；部署到目标环境时仍建议按实际策略再跑一次 `scripts/e2e/smoke.sh --compose ...`。
