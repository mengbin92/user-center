# 租户物理隔离（独立 schema）

> V2.6 阶段④。**状态：已完整交付**（租户数据域 cutover、SQL 建表、跨租户聚合、迁移工具、测试）。账号/会话等身份数据按设计留在平台 schema，见 §6。

## 1. 形态

单 MySQL 实例、每组织一个 schema（MySQL 中 schema 即 database），按请求路由。两类存储形态共用一套路由：

| 驱动 | 路由方式 | 事务语义 |
|---|---|---|
| MySQL | 表名改写为 `` `schema`.`table` ``，连接仍是平台库 | 同一事务可写平台表与租户表，**跨库原子**（InnoDB 单实例） |
| SQLite（开发/测试） | 每组织一个独立数据库文件与连接池 | 租户写不在平台事务内，**非原子**；仅用于开发与测试 |

MySQL 方案的关键点是**不换连接**：只在 SQL 里限定 schema。因此组织域的事务（成员、角色、分配、约束、委派、审计）与平台表（`organizations`、`event_outbox`）仍然是一个事务，不需要第二事务、发件箱改写或补偿任务。

租户选择器只有两个来源，都不由请求体控制：

- `/api/v1/orgs/{id}/...`：`platform/tenant.FromPath` 从 URL 解析；
- `/scim/v2/...`：已验证的 SCIM bearer token 的 `organization_id`。

平台路径解析为 0，永远使用平台 schema。**默认关闭**（`data.tenancy.schema_isolation` / `TENANT_SCHEMA_ISOLATION=1`），关闭时路由回调不生效，存量行为与测试不变。

## 2. 数据域

| 位置 | 表 |
|---|---|
| 租户 schema | `organization_members`、`organization_departments`、`organization_invitations`、`iam_roles`、`iam_role_permissions`、`iam_role_inheritance`、`iam_user_roles`、`iam_role_constraints`、`iam_delegations`、`iam_audit_events`、`scim_identities`、`scim_groups`、`scim_group_members`、`directory_objects`、`directory_sync_runs` |
| 平台 schema | `organizations`（注册表）、`users`、`user_credentials`、`identity_mfa`、`iam_sessions`、`user_oauth_identities`、`webauthn_credentials`、平台 `iam_*` 行、`iam_policy_state`、平台 `iam_audit_events`、`event_outbox`、`integration_clients`、`oidc_*`、`settings_*`、`export_jobs`、`tenant_schemas` |

`tenant_tables` 是闭集（`internal/data/tenancy.go`），新增租户表必须同时加入该集合与 DDL 文件。

## 3. 建表：全部走 SQL

租户 schema 的建表**不使用 GORM 的 Migrator**，而是执行签入仓库的 DDL：

- `internal/data/tenantddl/mysql.sql`
- `internal/data/tenantddl/sqlite.sql`

通过 `//go:embed` 打包，`EnsureTenantSchema` 把 `{{schema}}` 替换为实际 schema 名后逐条执行。MySQL 使用 `CREATE TABLE IF NOT EXISTS`，SQLite 模板由平台 schema 的 DDL 生成（表与索引一一对应）。

这样做有三个原因：DDL 可评审、可 diff；`Migrator` 的 `HasTable` 用模型表名做存在性检查，平台表已存在时会静默跳过租户建表；SQLite 没有 schema 级复制原语。

## 4. 启用与 cutover

```bash
# 1) 平台库常规迁移（含 017 tenant_schemas）
go run ./cmd/migrate -config configs/config.yaml

# 2) 建租户 schema（幂等）
go run ./cmd/tenant-schema -config configs/config.yaml -all

# 3) 存量数据搬迁：先预演，再执行，核对后可清理平台副本
go run ./cmd/tenant-migrate -config configs/config.yaml -all -dry-run
go run ./cmd/tenant-migrate -config configs/config.yaml -all
go run ./cmd/tenant-migrate -config configs/config.yaml -all -purge

# 4) 开启开关并滚动重启
export TENANT_SCHEMA_ISOLATION=1
```

`cmd/tenant-migrate` 按表复制并校验行数，逐表幂等（先清空该组织的租户行再插入）。`-purge` 只在行数校验通过后删除平台副本。清理前建议保留一次备份。

新建组织在 `OrganizationUsecase.Create` 内自动完成三阶段：写平台注册行（`provisioning`）→ 建 schema → 租户事务内写成员/内置角色/审计/事件并激活。中途失败保留 `provisioning` 状态（`orgAccess` 不可见），用同一 code 重试会续做而非撞唯一键。

## 5. 跨租户查询

物理隔离后，需要跨组织读的查询改为聚合：

| 查询 | 处理 |
|---|---|
| 我的组织（`ListOrganizationsForUser`） | 遍历 `tenant_schemas` 的 ready 组织，逐租户查成员后回平台库取组织行；SQLite 下拆两步（成员 + 组织） |
| 平台审计列表 | 平台行 + 每个租户 schema 的审计行合并后排序分页（`auditRepo.listAcrossTenants`） |
| 成员列表 / 角色分配 | MySQL 用跨库 JOIN；SQLite 拆成租户查询 + 平台 `users` 回填 |
| 组织 owner 配额 | 平台 `organizations.created_by` 仍可用，无需聚合 |

## 6. 设计边界（不是未完成项）

**身份属于平台，授权属于租户。** `users`、凭据、MFA、会话、OAuth 绑定、WebAuthn 留在平台 schema，因为同一个人可以属于多个组织，登录也不携带组织上下文。把账号拆进租户库会要求联邦身份与登录链路改造，属于产品决策，不是本次隔离的遗漏。

相应地：

- 组织成员资格、角色、分配、约束、委派、审计**全部**在租户 schema；
- `event_outbox` 留在平台（`aggregate_id` 已带组织语义，消费者按事件类型处理），因此组织事务与 outbox 同库同事务；
- 平台策略版本 `iam_policy_state` 是全局策略，留在平台。

## 7. 运维前置

- **MySQL 权限**：`cmd/tenant-schema` 需要 `CREATE DATABASE` 与租户库 DDL；运行账号需要租户库的读写权限。与 `docs/operations.md` 中「运行账号不应具备跨库权限」的默认建议冲突，启用隔离时必须用专用迁移账号建库、运行账号按最小权限授予每个 `usercenter_org_*` 库。
- **备份/恢复**：必须覆盖平台库与所有 `usercenter_org_*` 库。`scripts/dr/tenant-schemas.sh` 列出并逐个 `mysqldump`；恢复后需校验 `tenant_schemas` 注册表与实际库一致。
- **多实例**：建库与建表是幂等的（`CREATE DATABASE IF NOT EXISTS` + `IF NOT EXISTS` DDL），并发执行安全；cutover 建议在维护窗口单实例执行。
- **回滚**：关闭 `TENANT_SCHEMA_ISOLATION` 即回到平台 schema。未执行 `-purge` 时平台副本仍在，可直接回退；已 purge 时需从备份恢复平台副本。

## 8. 验证

| 用例 | 覆盖 |
|---|---|
| `internal/data/tenancy_test.go` | 两租户独立存储、跨租户不可见、同 externalId 可共存、平台库无租户行、默认关闭、非法 id |
| `internal/server/tenancy_test.go` | HTTP 级：A 的 token 读 B 的 SCIM 用户 404、列表只含本租户、平台库无租户映射；组织创建后成员/角色/审计落在租户库、平台审计聚合可见 |
| 全量回归 | `go test ./...` 在隔离关闭（默认）与开启两种配置下均通过 |
