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

`(provider, issuer, provider_subject)` 唯一；同邮箱不自动合并账号。表已建立，第三方登录提供方接入在 V1.1。

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
| `iam_roles` | `code` 唯一、`builtin`、`status`、`max_members`、`revision` | `root/admin/member` 内置；内置 root 不可归档/停用 |
| `iam_role_permissions` | `(role_id, operation)` 主键、`effect`、`scope` JSON | 每个角色每个操作一条 grant |
| `iam_role_inheritance` | `(role_id, inherits_role_id)` 主键 | 禁止自环与循环，写入前验证 |
| `iam_user_roles` | `user_id`、`role_id`、`boundary` JSON、`starts_at`/`expires_at`、`status`、`origin`、`revision` | 分配 = 角色 + 边界 + 有效期；撤销保留行 |
| `iam_role_constraints` | `kind`、`role_ids` JSON、`max_count`、`enabled`、`revision` | `mutual_exclusion` / `max_roles` |
| `iam_menu_items` | `route_key` 唯一、`required_all/any`、`enabled` | 仅展示投影，不参与 API 鉴权 |
| `iam_audit_events` | `event_id`、actor、action、target、before/after/diff、result、reason、request_id、versions、occurred_at | 只追加；不对用户删除级联 |

`iam_policy_state` 同时承担迁移状态与策略版本；`iam_user_roles.origin` 取值为 `default` / `bootstrap` / `explicit` / `legacy_candidate`，用于识别迁移来源。

## 4. 集成与运维

| 表 | 说明 |
|---|---|
| `event_outbox` | 与业务写同事务；`event_id` 唯一；`aggregate_revision` 用于消费端拒绝旧版本覆盖 |
| `event_deliveries` | `(event_id, subscriber_id)` 唯一；`attempts`、`next_retry_at`、`status`、`last_error` |
| `export_jobs` | 导出任务；`scope_snapshot`、字段、状态、制品名、过期时间；下载时重新鉴权 |
| `schema_migrations` | `cmd/migrate` 维护的已执行版本 |
| `legacy_import_batches` | 设计文档要求；离线导入工具交付时启用（当前未建表） |

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
