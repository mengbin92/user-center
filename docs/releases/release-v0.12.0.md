# v0.12.0 · 2026-11-09

上一版：[v0.11.0](./release-v0.11.0.md) · 范围：V2.6 四项能力（组织委派 CRUD、SCIM 2.0、企业目录同步、租户 schema 隔离基础设施）。

**版本判定：MINOR（v0.11.0 → v0.12.0）。** 新增 14 个 protobuf RPC、9 条 SCIM 原始路由、2 个数据库迁移与相应界面，属于新增能力而非修复。**升级须先执行迁移 `015` 与 `016`**。租户物理隔离**默认关闭**，无需在升级时启用。

## 交付范围

| 阶段 | 内容 | 状态 |
|---|---|---|
| ① | 组织委派 CRUD（4 个端点）+「职责分离」页委派区（新建/编辑/撤销、全部或指定成员范围） | ✅ 完整 |
| ② | SCIM 2.0 用户/组供给 + 4 个凭据管理端点 + 凭据管理界面 | ✅ 完整（协议子集见 `docs/scim.md` §4） |
| ③ | 企业目录同步：LDAP/AD 与 JSON 网关连接器、同步引擎、对账、6 个管理端点 + 界面 | ✅ 完整（限制见 `docs/directory-sync.md` §7） |
| ④ | 租户物理隔离：独立 schema 路由、SQL 建表、`cmd/tenant-schema` / `cmd/tenant-migrate`、全量租户数据域 cutover | ✅ 完整 |
| — | 修正 README 中「组织委派仍延后」的过期表述；委派弹窗展示失败原因；补齐目标用户范围选择 | ✅ |

## 阶段① 组织委派

- `GET/POST /api/v1/orgs/{id}/iam/delegations`、`PATCH .../{delegation_id}`、`POST .../{delegation_id}:revoke`。
- 写入：`organization.iam.constraint.read/.manage`（读 owner+admin，写仅 owner）、Step-up、`reason`、`expected_revision` + `expected_policy_revision` 两道 CAS、组织审计、Outbox、policy revision bump。
- 角色必须同属本组织且 active；授权上限不得超过创建者在本组织持有的能力；跨租户 id 一律 404；平台管理员无入口（D7）。
- 实现期修正 F10：设计 §9 的「manager 必须在**创建者**活跃角色集合内」不在写入侧重复，该约束由求值侧 `checkOrgDelegation` 按**使用者**强制。写入侧重复会让 owner 只能以 `org_owner` 为 manager，委派分支永远不可达。
- **此前求值侧的委派分支在生产不可达**（无任何写入口），本次交付后可通过 HTTP 创建，HTTP 用例证明「创建后解锁分配、撤销后重新拒绝」。

## 阶段② SCIM 2.0

- `/scim/v2/{ServiceProviderConfig,ResourceTypes,Schemas,Users,Groups}`，支持 ListResponse 分页、闭合 filter 语法、PATCH 白名单、ETag/`If-Match`、SCIM Error 与 `scimType`。
- 凭据绑定唯一组织、只存 SHA-256 摘要、明文只返回一次；停用立即生效。
- 供给：`externalId` 权威匹配；跨租户邮箱 → `409`；`active=false` 只停用本组织成员资格并撤销其角色/委派；`DELETE` 保留全局账号与审计；组成员只允许本组织已供给用户。

## 阶段③ 企业目录同步

- 连接器：`ldap`（Simple Bind、分页、`whenChanged` 增量、`userAccountControl` 判定停用）与 `jsonfeed`（`since` 游标、显式 `deleted`、`full` 标记）。
- 凭据：`SecretBox`/AES-GCM 加密入库、只写不读、轮换 + `reason` + Step-up + 审计；明文协议仅回环地址、禁用重定向。
- 引擎：30s worker 按 `interval_seconds` 调度，`full`/`delta`/`dry_run`，`directory_objects` 映射与 `last_seen_at` 对账水位，`disable`/`delete`/`keep` 删除策略，`source_wins`/`local_wins` 冲突策略，逐对象报告与 `partial` 状态；`dry_run` 不写入、不推进游标。
- 供给复用 SCIM 路径，不存在第二套账号创建逻辑。

## 阶段④ 租户物理隔离

已交付：`conf.Data.Tenancy` 与 `TENANT_SCHEMA_ISOLATION`；按组织懒加载独立 `*gorm.DB`/`*sql.DB`；`platform/tenant` 从 URL 或 SCIM token 注入组织；`cmd/tenant-schema -org/-all/-list`；`scim_identities`/`scim_groups`/`scim_group_members`/`directory_objects`/`directory_sync_runs` 物理隔离；隔离关闭时沿用事务连接，避免单连接池互锁。

**实现要点**：MySQL 保持平台连接、把租户表名改写为 `schema.table`，因此组织事务与平台表仍是一个原子事务；SQLite 每组织独立数据库文件（开发/测试，租户写不在平台事务内）。租户建表全部执行 `internal/data/tenantddl/{mysql,sqlite}.sql`。`cmd/tenant-migrate` 完成存量数据搬迁（`-dry-run` 预演、`-purge` 清理平台副本），`scripts/dr/tenant-schemas.sh` 覆盖备份。账号、会话与平台策略按设计留在平台 schema，见 `docs/tenancy.md` §6。

## 兼容性与升级影响

| 项目 | 说明 |
|---|---|
| 数据库 | 必须先执行 `015_scim.sql` 与 `016_directory_sync.sql`；两者都是新增表，不改既有列 |
| HTTP 契约 | 新增 14 个 RPC；既有请求/响应不变 |
| 组织委派 | 新端点需要 owner + Step-up + reason；未创建委派时行为与升级前一致（只能授予自己已持有的能力） |
| SCIM | 新端点默认无凭据可用；未签发 token 时不存在可用入口 |
| 目录同步 | 默认无源、worker 空转；未配置时不产生任何外部请求 |
| 租户隔离 | 默认关闭；关闭时所有请求仍走平台连接池，行为与 v0.11.0 一致 |
| 依赖 | 新增 `github.com/go-ldap/ldap/v3`（含 `go-asn1-ber`、`Azure/go-ntlmssp`） |

## 升级步骤

1. 备份数据库。
2. 执行迁移：`go run ./cmd/migrate -config <config>`（应用 `015`、`016`）。
3. 滚动重启服务。默认不需要开启租户隔离。
4. 需要 SCIM 时，平台管理员在组织「设置」页签发凭据，配置 IdP 指向 `/scim/v2/`。
5. 需要目录同步时，在组织「设置」页新建目录源并手动触发一次 `dry_run` 核对，再执行 `full`。
6. 仅在完成 [`docs/tenancy.md`](../tenancy.md) §4 的 cutover 后，才设置 `TENANT_SCHEMA_ISOLATION=1`；启用前必须先运行 `cmd/tenant-schema -all`。

## 验证

| 项目 | 结果 |
|---|---|
| `gofmt -l .` | ✅ 无输出 |
| `go vet ./...` | ✅ 通过 |
| `go test ./...` | ✅ 通过（`internal/server` 约 58s） |
| `cd web && npm run typecheck` | ✅ 通过 |
| `cd web && npm test` | ✅ 20 文件 / 70 用例 |
| `./scripts/gen-check.sh` | ✅ generated code is up to date |
| 隔离开启回归 | ✅ `internal/server` 隔离用例与全量 `go test ./...` 通过 |
| MySQL 专属回归（`USER_CENTER_MYSQL_TEST_DSN`） | ⚠️ 本次未执行，CI 需提供隔离库 |

新增用例：组织委派 HTTP 2 组、SCIM HTTP 4 组、目录同步 HTTP 2 组、租户隔离 5 个（3 data + 2 HTTP）、委派界面 4 个。
