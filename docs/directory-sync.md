# 企业目录同步

> V2.6 阶段③。与 [SCIM 2.0](scim.md) 互补：SCIM 是 IdP **推送**用户/组，目录同步是本系统**拉取**企业目录。两者共用同一条用户供给路径。

## 1. 模型

一个目录源（source）绑定唯一组织，平台管理员通过管理面配置。目录对象通过 `externalId` 映射到本地账号，映射落在 `directory_objects`，供给则复用 `SCIMUsecase.CreateUser / PatchUser / DeleteUser`——不存在第二套账号创建逻辑，也就不会出现两套租户校验不一致。

供给时写入的 SCIM `externalId` 形如 `dir:<source_id>:<目录对象ID>`，因此同一目录对象在 SCIM 视图里也是稳定可识别的。

## 2. 连接器

| 类型 | 协议 | 增量 | 说明 |
|---|---|---|---|
| `ldap` | `ldap://` / `ldaps://` | `whenChanged>=<cursor>`（AD 通用时间格式） | go-ldap 客户端，Simple Bind，SimplePagedResultsControl 分页；`userAccountControl` bit 2 判定停用；属性映射可配 |
| `jsonfeed` | `http://` / `https://` | `?since=<cursor>`，响应带 `cursor` / `deleted` / `full` | 通用 JSON 网关，可对接 Entra ID / Okta / 飞书 / 企业微信的导出网关或自建适配层 |

两个连接器都实现同一个 `Fetch(ctx, cfg, secret, cursor) → DirectorySnapshot` 接口；新增目录源只需新增一个实现，不改同步引擎。

**SSRF 防护**：`https` / `ldaps` 可用于任意 host；明文的 `http` / `ldap` 只允许回环地址，且重定向被禁用。生产应使用 `ldaps` / `https`。

## 3. 凭据托管

`docs/api.md` 原本规定外部 provider 凭据只从环境变量读取、不入库，并写明「若未来入库，需要加密、轮换与审计设计，并先移除环境变量来源」。本次按该前置实现：

- 凭据用 `SecretBox`（AES-GCM，密钥由 `MFA_ENCRYPTION_KEY` 派生）加密后存 `directory_sources.secret_enc`。
- 任何读接口都**不回显**密文或明文；`config_json` 只放非敏感连接参数。
- 轮换需 `expected_revision` + `reason` + Step-up，写平台审计。
- 目录源不使用 OAuth provider 的环境变量凭据，不存在「两处同时生效」。

## 4. 同步引擎

独立 worker（30s ticker）扫描到期源，按 `interval_seconds`（默认 300，下限 30）串行执行；`TryLock` 防止同一进程内重入。也可通过管理面手动触发。

| 模式 | 行为 |
|---|---|
| `full` | 忽略游标拉取全量；`full` 快照中消失的对象按 `deletion_policy` 对账 |
| `delta` | 携带游标拉取增量，只处理响应中的对象与显式 `deleted` 列表 |
| `dry_run` | 只生成预演报告，**不写入、不推进游标**，且 `created_count/updated_count` 保持 0 |

每次运行生成一条 `directory_sync_runs` 记录，含 `fetched / created / updated / disabled / unchanged / failed`、游标前后值、逐对象的 `report_json` 与错误文本；状态为 `succeeded / partial / failed`。单个对象失败不会中断整批，也不会伪装成干净成功。

对账与冲突策略：

- `deletion_policy`：`disable`（默认，停用本组织成员资格并撤销其角色/委派）/ `delete`（移除成员与映射）/ `keep`（只记录，不处理）。
- 源端删除**不硬删除全局账号**，理由与 SCIM 相同：账号跨组织共享。
- `conflict_policy`：`source_wins`（默认，以目录为准更新）/ `local_wins`（已有对象只更新 `last_seen_at`，不覆盖本地资料）。
- 幂等：按 `(source_id, externalId)` 匹配；重跑全量不会重复建号。

## 5. 管理面

全部要求**平台管理员 + Step-up + `reason`**（写操作），并写平台审计：

| 方法 | 路径 |
|---|---|
| GET | `/api/v1/admin/directory-sources?organization_id=...` |
| POST | `/api/v1/admin/directory-sources` |
| PATCH | `/api/v1/admin/directory-sources/{id}` |
| POST | `/api/v1/admin/directory-sources/{id}:rotate-secret` |
| POST | `/api/v1/admin/directory-sources/{id}:sync` |
| GET | `/api/v1/admin/directory-sync-runs?source_id=...` |

前端在组织「设置」页（仅平台管理员可见）提供新建、同步、轮换凭据与最近一次运行摘要。

## 6. 数据模型（迁移 `016`）

| 表 | 用途 |
|---|---|
| `directory_sources` | 源配置、加密凭据、状态、游标、revision、`last_run_at` |
| `directory_sync_runs` | 每次运行的计数、报告、错误与游标 |
| `directory_objects` | `(source_id, external_id)` ↔ `local_id` 与 `last_seen_at` 对账水位 |

SQLite 由 `AutoMigrate` 建表，MySQL 由 `migrations/mysql/016_directory_sync.sql` 应用。**升级须先执行迁移 016 再启动服务。**

## 7. 已知限制（未做的不标成已完成）

- **只同步用户，不同步组/部门层级**：目录侧的 OU/组树不映射到 `organization_departments`；SCIM Group 是独立的供给视图。需要组层级同步时要先定映射规则。
- **LDAP 增量依赖 AD 的 `whenChanged`**：非 AD 目录（通常用 `modifyTimestamp`）需要改用全量模式或自行配置带时间条件的 `user_filter`。
- **没有 Entra Graph / 飞书 / 企业微信原生连接器**：这些源需要各自的鉴权与分页模型；当前通过 `jsonfeed` 网关对接。
- **worker 只在单进程内串行**：多实例部署时没有分布式租约，同一源可能被两个实例同时拉取。上线多副本前需要加跨实例锁（Redis 租约或 DB `SELECT ... FOR UPDATE`）。
- **只入站，不写回**：不会把本地账号变更推回企业目录。
- **不支持 SCIM `/Bulk` 式的批量事务**：每个对象独立提交，因此 `partial` 是预期状态而非异常。
- 账号本身仍全局共享；账号级物理隔离属于阶段④。
