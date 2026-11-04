# v0.6.0 · V2.4 W1/W2（待发版草稿）

> 状态：代码已合入 `develop`，**尚未打 tag**。此文件为路线图 §5 要求的波次发布说明草稿，发版时补日期与上一版链接。

上一版：[v0.5.2](./release-v0.5.2.md)

本版包含 V2.4 路线图 W1（OIDC 收尾）与 W2（组织企业化）共 6 个工作项：R1–R6。

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

## 验证

`go vet ./...`、`go test ./...`、`cd web && npm test && npm run build` 全部通过；新增 HTTP 级用例覆盖同意首次/复用/拒绝/扩权/撤销/prompt、登出白名单与幂等、邀请过期/撤销/配额/跨租户、explain 允许/拒绝/过期分配、租户导出隔离/403/CSV 注入/policy revision、组织事件 PII/回滚/去重/订阅过滤。MySQL 迁移真跑已在临时 `mysql:8.4` 容器执行（001–009 两次幂等应用通过）；本地 compose 全流程冒烟仍需在部署环境执行。

## 未执行 / 已知限制

- 迁移已在真实 MySQL 8.4 容器验证（`USER_CENTER_MYSQL_TEST_DSN`）；但**本地 compose 全流程冒烟未执行**，HTTP 级验证基于 SQLite 集成测试与生成物一致性检查。
- v0.5.1 的 Docker E2E 脚本尚未收进 `scripts/e2e/`（路线图 §6 工程前置，本波次未做）。
