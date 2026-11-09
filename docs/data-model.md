# 数据模型

所有时间字段使用 UTC；MySQL 列类型 `DATETIME(3)`。修订号（revision）为乐观并发控制版本，单调递增。用户 ID 保留原系统的数值 ID 语义，对 JSON 以字符串输出。

## 1. 身份与安全

### `users`

| 列 | 说明 |
|---|---|
| `id` | 主键，保持稳定，供业务系统关联 |
| `username` / `username_normalized` | 显示名与唯一规范名（小写）；唯一索引 |
| `display_name` | 昵称，可修改 |
| `email` / `email_normalized` | 可空；规范值唯一；历史重复邮箱需先治理 |
| `email_verified_at` | 非空表示已验证 |
| `status` | `enabled` / `disabled` / `archived` |
| `revision` | 资料 CAS 版本 |
| `identity_version` | 身份变更版本；会话校验用 |
| `created_at` / `updated_at` / `archived_at` | 时间 |

索引：`username_normalized` 唯一、`email_normalized` 唯一、`(status,id)`、`(created_at,id)`。

### `user_credentials`

`user_id` 唯一；`password_hash`（bcrypt）、`algorithm`、`password_version`、`must_change_password`、`revision`、`updated_at`。普通用户查询永不返回该表内容。

### `identity_mfa`

`secret_ciphertext`（AES-GCM）、`key_version`、`pending_secret` / `pending_session` / `pending_until`（设置流程）、`recovery_hashes`（SHA-256，逗号分隔）、`last_step`（TOTP 防重放）、`failures` / `locked_until`（锁定）、`revision`。

### `user_oauth_identities`

`(provider, issuer, provider_subject)` 唯一；同邮箱不自动合并账号。GitHub/Google 登录与绑定已实现（见 `docs/api.md`）。

### `auth_flow_completions`

`(challenge_id, purpose)` 主键。用于注册/重置/换邮箱/邮箱验证的数据库幂等完成记录，防止验证码重复消费导致重复写入。

### `security_events`

`event_id`、`user_id`、`session_id`、`kind`、`result`、`ip_masked`、`user_agent_summary`、`request_id`、`occurred_at`。仅保存脱敏网络信息。

### `auth_settings` / `auth_email_settings`

`key` 主键 + JSON `value` + `revision`；邮件密钥单独加密存放在 `secret`，读取接口只返回 `password_configured`。

## 2. 会话

### `iam_sessions`

| 列 | 说明 |
|---|---|
| `id` | 会话 ID（UUID），审计引用 |
| `user_id` | 归属用户 |
| `application_code` | 应用标识（V1 为 `user-center`） |
| `credential_hash` | 会话令牌 SHA-256，唯一 |
| `user_agent` / `ip_masked` | 设备与脱敏 IP |
| `issued_at` / `last_seen_at` / `expires_at` / `idle_expires_at` | 生命周期 |
| `revoked_at` | 撤销时间 |
| `identity_version` | 签发时的身份版本 |
| `revision` | 会话角色切换 CAS |

### `iam_session_roles`

`(session_id, role_id)` 主键；当前会话激活的角色集合。授权只读取该集合。

## 3. IAM

| 表 | 关键列 | 不变量 |
|---|---|---|
| `iam_policy_state` | `policy_revision`、`catalog_revision`、`authorization_mode`、`cutover_state` | 单行 `id=1`；每次 IAM 写提升 policy revision |
| `iam_resources` | `code` 唯一、`owner`、`enabled` | 业务资源目录 |
| `iam_permissions` | `code` 唯一、`resource_id`、`status`、`binding`、`supported_scopes` JSON、`protected`、`revision` | 未绑定执行点的权限不可生效 |
| `iam_roles` | `(context_type, context_id, code)` 唯一、`builtin`、`status`、`max_members`、`revision` | 平台角色 `context_id=0`；组织角色 `context_type='organization'` 且 `context_id=组织 ID`；内置组织角色不可修改/归档 |
| `iam_role_permissions` | `(role_id, operation)` 主键、`effect`、`scope` JSON | 每个角色每个操作一条 grant |
| `iam_role_inheritance` | `(role_id, inherits_role_id)` 主键 | 禁止自环与循环，写入前验证 |
| `iam_user_roles` | `user_id`、`role_id`、`context_type`/`context_id`、`boundary` JSON、`starts_at`/`expires_at`、`status`、`origin`、`revision` | 分配 = 上下文 + 角色 + 边界 + 有效期；撤销保留行；查询必须带上下文 |
| `iam_role_constraints` | `kind`、`role_ids` JSON、`max_count`、`enabled`、`revision` | `mutual_exclusion` / `max_roles` |
| `iam_delegations` | `manager_role_id`、`target_role_id`、`target_kind`、`actions` JSON、`target_user_scope` JSON、`grant_ceiling` JSON、`can_redelegate`、有效期、`revoked_at`、`revision` | 只授权分配/撤销角色，不授予策略修改 |
| `iam_menu_items` | `route_key` 唯一、`required_all/any`、`enabled` | 仅展示投影，不参与 API 鉴权 |
| `iam_audit_events` | `event_id`、actor、action、target、before/after/diff、result、reason、request_id、versions、`organization_id`、occurred_at | 只追加；不对用户删除级联；`organization_id>0` 表示租户事件 |

`iam_policy_state` 同时承担迁移状态与策略版本；`iam_user_roles.origin` 取值为 `default` / `bootstrap` / `explicit` / `legacy_candidate` / `organization_membership`，用于识别迁移与同步来源。

V2.3 起角色/分配合法上下文为 `platform` 与 `organization:{id}`：零值按平台处理以兼容存量行，组织查询在 SQL 中固定携带 `context_type/context_id`，跨上下文的行等同不存在。

## 4. 集成与运维

| 表 | 说明 |
|---|---|
| `event_outbox` | 与业务写同事务；`event_id` 唯一；`aggregate_revision` 用于消费端拒绝旧版本覆盖 |
| `event_deliveries` | `(event_id, subscriber_id)` 唯一；`attempts`、`next_retry_at`、`status`、`last_error` |
| `integration_clients` | `client_id`、`code`、`service_owner`、`credential_hash`、`credential_version`、`allowed_methods` JSON、`event_subscriptions` JSON、`callback_url`、`expires_at`、`revision` |
| `legacy_import_batches` | `batch_id`、`source_commit`、`snapshot_position`、`counts`、`fingerprint`、`state`、`error`、`completed_at` |
| `oidc_clients` | `client_id` 唯一、`name`、`service_owner`、`status`、`secret_hash`、`redirect_uris` JSON、`scopes` JSON、`public`、`require_pkce`、access/refresh TTL、`revision` |
| `oidc_authorization_codes` | `code_hash` 主键、`client_id`、`user_id`、`redirect_uri`、`scope`、`nonce`、`code_challenge`/method、`auth_time`、`expires_at`、`consumed_at` |
| `oidc_refresh_tokens` | `token_hash` 主键、`client_id`、`user_id`、`scope`、`auth_time`、`expires_at`、`revoked_at` |
| `organizations` | `code` 唯一、`name`、`status`、`revision`、`created_by`、`archived_at` | 组织是成员、部门与 IAM 策略的边界；平台管理员可见全部 |
| `organization_members` | `(organization_id,user_id)` 唯一、`role` (`owner/admin/member`)、`department_id`、`status`、`revision`、`joined_at` | 成员角色是内置组织角色（`org_owner/org_admin/org_member`）的投影；至少保留一名 owner |
| `organization_departments` | `(organization_id,code)` 唯一、`parent_id`、`name`、`status`、`revision` | 部门树禁止环；成员可挂接部门 |
| `export_jobs` | 导出任务；`scope_snapshot`、字段、状态、制品名、过期时间；下载时重新鉴权 |
| `schema_migrations` | `cmd/migrate` 维护的已执行版本 |
| `legacy_import_batches` | `cmd/import-legacy` 的批次记录；保留源提交、位点、计数、指纹与终态 |
| `scim_tokens` | SCIM bearer 凭据摘要、`organization_id` 绑定、状态、凭据版本与 `last_used_at`；明文永不入库 |
| `scim_identities` | `(organization_id, kind, external_id)` ↔ `local_id` 映射；IdP 稳定标识是供给匹配的权威 |
| `scim_groups` / `scim_group_members` | SCIM 组与成员；与 `organization_departments` 独立，见 `docs/scim.md` |

## 5. Revision 语义

| Revision | 作用域 | 冲突响应 |
|---|---|---|
| `users.revision` | 单个用户资料 | 409 `REVISION_CONFLICT` + `current_revision` |
| `iam_policy_state.policy_revision` | 全局授权策略 | 409 `POLICY_CONFLICT` + `current_policy_revision` |
| `iam_roles.revision` | 单个角色的名称/描述/权限/继承 | 409 `REVISION_CONFLICT` |
| `iam_user_roles.revision` | 单条分配 | 409 `REVISION_CONFLICT` |
| `iam_sessions.revision` | 会话角色切换 | 409 `REVISION_CONFLICT` |

资料版本与策略版本不可混用；预览只用于展示，提交时必须重新读取并再次校验。

## 6. 保留与删除

- 归档 = `status=archived` + `archived_at`，禁止登录，保留 ID、审计与业务关联。
- 不提供物理删除；历史账单/审计/授权记录不级联删除。
- 导出制品默认 24 小时过期，仅存本地受限目录，文件名使用随机 UUID。
- 审计事件永久保留；安全事件按部署策略清理（当前无自动清理任务）。
