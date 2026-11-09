# 租户物理隔离（独立 schema）

> V2.6 阶段④。**状态：基础设施与租户数据域已交付，存量数据 cutover 未完成。** 本文如实区分两者，未完成的项保留 `[ ]`。

## 1. 形态

选型为**单 MySQL 实例、每组织一个 schema**（MySQL 中 schema 即 database），按请求路由到独立连接池；平台 schema 保留共享身份与跨租户治理表。相比「每租户独立实例」改造可控，相比「RLS」不依赖 MySQL 并不具备的行级安全特性。

```text
请求 → 中间件/协议处理器解析组织 → platform/tenant.With(ctx, orgID)
     → Data.TenantDB(ctx) → usercenter_org_<id> 的独立 *gorm.DB + *sql.DB
     → 租户仓储读写
```

租户选择器只有两个来源，都不可由请求体覆盖：

- `/api/v1/orgs/{id}/...`：由 `platform/tenant.FromPath` 从 URL 解析；
- `/scim/v2/...`：由已验证的 SCIM bearer token 的 `organization_id` 决定。

平台路径解析为 0，永远使用平台连接池。**默认关闭**：`data.tenancy.schema_isolation` 或 `TENANT_SCHEMA_ISOLATION=1` 才启用；关闭时 `TenantDB` 直接返回平台池，存量行为与全部既有测试不变。

## 2. 已交付（✅）

| 能力 | 说明 |
|---|---|
| 配置 | `conf.Data.Tenancy`（`schema_isolation`、`schema_prefix`、`max_open_conns`、`max_idle_conns`），环境变量 `TENANT_SCHEMA_ISOLATION` / `TENANT_SCHEMA_PREFIX` 覆盖 |
| 连接池路由 | `Data.TenantDB(ctx)` 懒加载、缓存、独立池上限；租户库不可用时返回必然查询失败的句柄，**绝不回退平台库**串数据 |
| Schema 编排 | `cmd/tenant-schema -org <id>` / `-all` / `-list`；幂等建库并建全套表结构。静态 SQL 迁移无法表达「每组织一套 schema」，因此 DDL 编排放在 CLI |
| 上下文注入 | 中间件（组织 URL）、SCIM 处理器（token）、目录同步引擎（触发与 worker 均绑定 source 的 organization） |
| 租户数据域物理隔离 | `scim_identities` / `scim_groups` / `scim_group_members` / `directory_objects` / `directory_sync_runs` 落在各自组织的 schema |
| 治理元数据 | `scim_tokens` / `directory_sources` 保留在平台 schema（凭据与配置需跨组织签发/审计，且本身带 `organization_id` 约束、只存摘要或密文） |
| 拒绝用例 | `internal/data/tenancy_test.go`（不同池、跨 schema 不可见、同 externalId 在不同租户可共存、平台库无租户行、默认关闭）与 `internal/server/tenancy_test.go`（A 的 token 读 B 的 SCIM 用户 → 404、列表只含本租户、平台库无租户映射） |

## 3. 启用步骤

1. 先在平台库执行全部 SQL 迁移（含 `015`、`016`）。
2. 运行 `go run ./cmd/tenant-schema -all`，为所有活跃组织创建 schema 与表结构。**必须先于开启开关**：否则租户查询会打到不存在的 schema 并失败（这是有意的 fail-closed，不是静默降级）。
3. 设置 `TENANT_SCHEMA_ISOLATION=1`（或配置 `data.tenancy.schema_isolation: true`）后滚动重启。
4. 用 `go run ./cmd/tenant-schema -list` 核对已打开的 schema；新建组织后需再执行 `-org <id>`。

新建组织的自动建库**尚未接入创建事务**，见下节。

## 4. 未完成（[ ]，上线前必须处理）

这些不是「有代码但没测」，而是确实没有实现。把它们标成完成会造成错误的合规结论。

- [ ] **存量数据 cutover**：`organization_members`、`organization_departments`、`organization_invitations`、组织域 `iam_roles` / `iam_user_roles` / `iam_role_constraints` / `iam_delegations`、组织审计仍在平台 schema，继续依赖 `organization_id` / `(context_type, context_id)` 的**逻辑隔离**。需要拆表迁移脚本与双写/校验窗口。
- [ ] **全局账号物理隔离**：`users` / `user_credentials` / `iam_sessions` / `user_oauth_identities` 仍在平台 schema。SCIM 与目录同步创建的账号也写在平台库（租户库只保存映射与组数据）。若合规要求账号级隔离，需定义「同一人跨组织」的联邦身份映射并改造登录链路。
- [ ] **登录链路按租户路由**：当前登录不知道组织，因此账号必须留在平台库；账号拆分后需要按标识符跨租户查账号或引入联邦登录。
- [ ] **平台跨租户治理聚合**：审计/策略仍在平台库，短期可见性不受影响；但存量组织数据迁到租户库后，平台管理员的跨租户只读视图需要改为跨库聚合，并重新评估 D7（平台管理员无组织约束入口）与新通道的冲突。
- [ ] **新建组织自动建库**：`CreateOrganization` 事务尚未调用 `EnsureTenantSchema`，目前靠运维执行 CLI。
- [ ] **多实例编排**：schema 创建只保证幂等，没有跨实例租约；多副本同时为新组织建库需要加分布式锁。
- [ ] **跨库事务一致性**：租户映射写在平台账号事务之外（避免一个事务跨越两个数据库）。极端情况下可能留下「平台账号已建、租户映射未写」的孤立行；下次同步按邮箱匹配会幂等补齐，但没有自动补偿事务。
- [ ] **备份/DR 脚本**：`scripts/dr/*` 仍按单个 `usercenter` 库重建/恢复，多 schema 后需逐库备份并校验 schema 清单。
- [ ] **MySQL 权限模型**：`CREATE DATABASE` 与跨库 DDL 需要运行账号具备相应权限，与 `docs/operations.md` 现有「生产账号不应具备跨库读取或 DDL 权限」的建议冲突，需重新定权并回归验证。

## 5. 与既有隔离的关系

物理隔离**不替代**现有三层逻辑隔离，两者叠加：URL `{id}` 唯一租户选择器 → 授权上下文门禁 → SQL `WHERE context_type/context_id` / `WHERE organization_id` → 业务纯函数二次过滤。即使路由选错库，这些谓词仍会挡住跨租户行；反之，物理 schema 在代码漏写 WHERE 时提供额外边界。

`docs/security.md` §4.5 关于「未做独立库/表分区或 RLS」的表述已按本文更新为分域状态。
