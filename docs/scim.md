# SCIM 2.0 用户与组供给

> V2.6 阶段②。协议依据 RFC 7643（schema）与 RFC 7644（protocol）。

## 1. 租户边界

SCIM 凭据（bearer token）**绑定唯一一个组织**，这个绑定是 `/scim/v2/*` 请求唯一的租户选择器：

- 请求体里没有 `organization_id`、`context_type` 等字段；即使传入也会被忽略。
- 所有资源 id 都必须先经过该组织的 `(organization_id, kind, local_id)` 映射表解析；其他租户的 id 一律 `404`，不是 `403`（避免确认 id 存在）。
- 只保存 token 的 SHA-256 摘要，明文只在签发/轮换时返回一次；列表接口不回显。
- 停用凭据立即拒绝该 IdP 的全部请求；组织被归档时凭据同样失效。
- `/scim/v2/` 前缀不在 `/api/v1/` 下，因此不受浏览器 CSRF 规则约束；处理器对**每个**请求自行做 Bearer 鉴权，不存在未鉴权分支。

一个 IdP 需要供给多个组织时，为每个组织各签一个凭据。

## 2. 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/scim/v2/ServiceProviderConfig` | 能力声明（PATCH/filter/ETag 支持，Bulk/sort 不支持） |
| GET | `/scim/v2/ResourceTypes`、`/ResourceTypes/{id}` | User / Group 资源类型 |
| GET | `/scim/v2/Schemas`、`/Schemas/{id}` | User / Group schema URN |
| GET | `/scim/v2/Users` | 列表，支持 `filter`、`startIndex`、`count`、`attributes`、`excludedAttributes` |
| POST | `/scim/v2/Users` | 创建（供给） |
| GET/PUT/PATCH/DELETE | `/scim/v2/Users/{id}` | 读取 / 全量替换 / 部分更新 / 回收 |
| GET | `/scim/v2/Groups` | 组列表，支持 `filter` 与分页 |
| POST | `/scim/v2/Groups` | 创建组 |
| GET/PUT/PATCH/DELETE | `/scim/v2/Groups/{id}` | 组读写与成员增删 |

响应 `Content-Type: application/scim+json`；单资源带 `ETag: W/"<revision>"`，PUT/PATCH/DELETE 支持 `If-Match`（不匹配返回 `412` + `scimType: preCondition Failed`）。错误统一为 SCIM `Error` 消息，带 `status` 与 `scimType`。

管理面（浏览器，平台管理员 + Step-up + `reason`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/admin/scim/tokens?organization_id=...` | 列出该组织凭据 |
| POST | `/api/v1/admin/scim/tokens` | 签发 |
| POST | `/api/v1/admin/scim/tokens/{id}:rotate` | 轮换（带 `expected_revision`） |
| POST | `/api/v1/admin/scim/tokens/{id}:disable` | 停用（带 `expected_revision`） |

## 3. 身份映射与冲突策略

`scim_identities` 以 `(organization_id, kind, external_id)` 为唯一键，把 IdP 的稳定标识映射到本地 `users.id` 或 `scim_groups.id`。`externalId` 是匹配权威，改名/换邮箱不会造成重复账号。

供给用户时：

1. `externalId` 已存在 → `409` + `scimType: uniqueness`。
2. 邮箱对应的本地账号**已存在且是本组织活跃成员** → 复用该账号，只建立映射（幂等重新供给）。
3. 邮箱对应的本地账号存在但**不属于本组织** → `409`，不静默跨租户绑定。否则一个租户的凭据可以靠猜邮箱把别的租户用户拉进自己的目录。
4. 账号不存在 → 创建本地账号并加入本组织。账号使用随机不可知密码，只能通过联邦登录或管理员重置使用；不会生成可猜测的初始口令。

`active=false` **只停用本组织的成员资格**（软失效并撤销其组织角色与委派），不改全局账号状态——全局账号被多个组织共享，禁用会连带锁死其他租户。`DELETE /Users/{id}` 同理：移除成员资格与映射，保留全局账号与审计历史。

组的成员必须是通过 SCIM 供给到**本组织**的用户；传入其他租户的用户 id 返回 `400`。

## 4. 明确支持的子集（未支持的会显式拒绝，不会静默忽略）

| 能力 | 状态 |
|---|---|
| `filter`：`userName / externalId / id / active / emails.value / emails[type eq "work"].value eq "value"`，多条件用 `and` | ✅ |
| `filter` 其它操作符（`sw`、`co`、`pr`、`or`、括号） | ❌ `400 invalidFilter` |
| PATCH path：`active`、`displayName`、`userName`、`externalId`、`emails`、`emails.value`、`name.formatted`、无 path 整体对象 | ✅ |
| PATCH Group：`displayName`、`members`（add/remove）、`members[value eq "x"]`（remove） | ✅ |
| 其它 PATCH path / value-path | ❌ `400 invalidValue` |
| `attributes` / `excludedAttributes` 顶层字段投影 | ✅ |
| 嵌套投影路径（如 `name.givenName`） | ❌ 返回完整资源，不假装支持 |
| `startIndex` / `count`（`count` 上限 1000） | ✅ |
| `sortBy` / `sortOrder` | ❌ `400 invalidFilter` |
| `ETag` / `If-Match` | ✅ |
| `/Bulk`、`/Me` | ❌ `404`，ServiceProviderConfig 明确声明不支持 |
| SAML、IdP 发起的目录拉取、增量游标 | ❌ 不属于 SCIM，见企业目录同步（阶段③） |

`schemas` 校验：POST/PUT 必须包含对应资源 URN，PATCH 必须包含 `PatchOp` URN，否则 `400`。请求体上限 1 MiB（SCIM 路径不在全局 `/api/v1/` 限流范围内，由处理器自行限制）。

## 5. 数据模型（迁移 `015`）

| 表 | 用途 |
|---|---|
| `scim_tokens` | 凭据摘要、组织绑定、状态、凭据版本、`last_used_at` |
| `scim_identities` | `(organization_id, kind, external_id)` ↔ `local_id` |
| `scim_groups` | 组（与 `organization_departments` 独立；SCIM 没有部门的 code/parent 层级概念） |
| `scim_group_members` | 组 ↔ 用户 |

SQLite（开发/测试）由 `AutoMigrate` 建表，MySQL 由 `migrations/mysql/015_scim.sql` 应用。**升级须先执行迁移 015 再启动服务。**

## 6. 审计

所有供给写操作写入组织审计（`scim.user.created/updated/deleted`、`scim.group.*`），主体标记为 `scim` 服务而非个人账号；凭据签发/轮换/停用写入平台审计并强制 `reason`。

## 7. 已知限制

- 全局账号仍在所有租户间共享，SCIM 只隔离成员资格与外部标识映射；账号级别的物理隔离属于阶段④。
- SCIM Group 不改变组织内置角色或部门归属，只是供给视图。
- 不支持 SCIM 密码写入（`password` 属性被忽略）；需要本地密码时走管理员重置。
- 未实现 SCIM `/Bulk`，大批量供给需由 IdP 逐条调用；`count` 与分页可避免单次响应过大。
- 没有内置企业目录连接器；从 LDAP/AD/Entra/飞书等源拉取数据是阶段③的独立能力。
