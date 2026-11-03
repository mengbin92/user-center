# 从 `micro-one-api` 迁移

基线：`micro-one-api` 提交 `4116899a`。本仓库是**新库、新迁移、新运行账号**，不复用原库的 `schema_migrations`。

## 1. 数据所有权

| 数据 | 归属 | 迁移动作 |
|---|---|---|
| 用户 ID、用户名、昵称、邮箱、邮箱验证、状态 | 用户中心 | 迁移；ID 不变 |
| 密码摘要、密码版本 | 用户中心 | 迁移 bcrypt 摘要；不重算 |
| TOTP 密文、恢复码摘要、失败锁定 | 用户中心 | 迁移并重新加密（如密钥不同） |
| 外部身份绑定 | 用户中心 | 迁移 `provider/issuer/subject` |
| 浏览器会话 | 用户中心 | **不迁移**；正式切换要求重新登录 |
| 角色、权限、继承、分配、约束、审计 | 用户中心 | 迁移关系表，保留原 ID 或建立映射 |
| API Key、额度、路由组、余额、订阅 | 原系统 | 不进入用户中心；以用户 ID 关联 |
| 定向公告、模型可用状态 | 原系统 | 不迁移 |

## 2. 字段映射

### `users`

| 原字段 | 新字段 | 说明 |
|---|---|---|
| `id` | `id` | 原样保留；导入后重置 AUTO_INCREMENT |
| `username` | `username` / `username_normalized` | 规范名先做冲突清单，不偷偷改名 |
| `display_name` | `display_name` | 空则回填 username |
| `email` | `email` / `email_normalized` | 空串转 NULL；重复/未验证邮箱进入冲突清单 |
| `status` (1/2) | `status` (`enabled`/`disabled`) | 归档为新状态 |
| `password_hash` | `user_credentials.password_hash` | bcrypt 原样；`algorithm=bcrypt` |
| `password_changed_at` | `user_credentials.password_version` + `users.identity_version` | 毫秒时间戳不能直接当版本；迁移时建立单调版本 |
| 角色/组/邀请码/余额/路由 | 不迁移 | 角色由 IAM 分配；其余留在原系统 |

### IAM

尽量保留原表结构与 ID：

- `iam_policy_state`、`iam_resources`、`iam_permissions`、`iam_roles`、`iam_role_permissions`、`iam_role_inheritance`、`iam_user_roles`、`iam_sessions`（归档旧会话）、`iam_session_contexts`、`iam_session_roles`、`iam_role_constraints`、`iam_menu_items`、`iam_audit_events`。
- 原 `iam_user_roles.allow_boundary` 的 `routing_group_ids` 不能直接变成 `all`。迁移时按目标用户集合解析为 `user_ids` 范围，或保留原 owner 适配并记录未完成重算；未重算前拒绝依赖该范围的敏感操作。
- 旧会话使用 JWT JTI；新会话使用随机不透明凭据。旧 JWT 密钥不复制为“迁移完成”。
- 旧的数值角色 `role >= 10` 不映射为管理员授权；必须通过 IAM 角色与权限分配。

## 3. 迁移步骤

1. **盘点**：导出用户、邮箱、用户名冲突、重复邮箱、root 账号、IAM 关系、依赖用户 ID 的业务表。
2. **建库**：新 MySQL 实例/库、独立账号；`cmd/migrate` 从 `001` 开始执行，写入权限目录与内置角色。
3. **离线导入**：按用户 → 凭据 → 外部身份 → 角色/权限/继承 → 分配 → 约束 → 菜单 → 审计顺序；每批记录 `legacy_import_batches`、源提交、快照位点、计数与指纹。
4. **校验**：
   - 用户数、启停数、管理员数、root 唯一性；
   - 每个用户至少一种登录方式；密码摘要可验证；
   - 角色继承无环、分配无孤儿、约束可满足；
   - 受限管理员的有效目标集合与旧数据范围一致（差异需人工确认）；
   - 旧 API Key 仍归原系统，`user_id` 关联有效。
5. **切换**：用户中心上线 → 原系统 BFF 切换到新 `ValidateSession` / `GetUser` / `GetSessionAuthorization` → 关闭旧写入路径 → 保留只读窗口。
6. **回退**：切换前保留原库快照；回退时停止新写入、恢复 BFF 旧路径、以原库为准。用户中心写入产生的账号变更需要人工对账，不能假设双向同步。

## 4. 迁移期约束

- 身份数据只能有一个权威写入点。切换窗口内禁止双写用户/密码/状态。
- 禁用/归档必须在用户中心执行，原系统不得用“本地用户仍启用”覆盖。
- 密码重置、MFA 重置、邮箱换绑在用户中心完成后，原系统只消费事件/查询，不复制凭据。
- 事件消费端以 `event_id` 去重，并拒绝旧 `aggregate_revision` 覆盖新状态。

## 5. 接入原系统

推荐顺序：

1. 原系统 BFF 增加适配器：浏览器 Cookie → 服务端调用 `ValidateSession`；不把会话令牌透传给浏览器 JS。
2. `GetUser` / `BatchGetUsers` 替换直接读 `users` 的只读路径；邮箱默认不返回，按需单独授权。
3. 资源 owner 调用 `GetResourceAuthorization`，携带执行点、操作与 owner 已验证的资源事实；不能接受浏览器自报的 scope。
4. API Key 校验：原系统本地校验 Key 状态 + 调用 `ValidateSubject` 组合用户启停与身份版本。
5. 用户中心事件（`user.status.changed`、`session.revoked` 等）用于投影与缓存失效；即时拒绝仍以 `ValidateSession` / `ValidateSubject` 为准。

## 6. 离线导入工具

`cmd/import-legacy` 已交付，默认 dry-run：

```bash
go run ./cmd/import-legacy -config configs/config.local.yaml -file legacy.json
go run ./cmd/import-legacy -config configs/config.local.yaml -file legacy.json -apply
```

输入格式：

```json
{
  "source_commit": "4116899a",
  "snapshot_position": "mysql-bin.000123:4567",
  "users": [
    {
      "id": 42, "username": "legacy.user", "display_name": "Legacy",
      "email": "legacy@example.com", "email_verified": true,
      "status": "1", "password_hash": "$2a$...", "role_codes": ["member"]
    }
  ]
}
```

行为：

- `status` 支持 `1/2` 或 `enabled/disabled/archived`；
- 保留用户数值 ID 与 bcrypt 摘要；不导入会话、API Key、余额、路由组；
- 按 `role_codes` 建立 `legacy_candidate` 分配：仅 `member` 在 `self` 边界内默认生效，其余角色均为 `pending`，不产生治理权限；原始快照缺少分配边界，必须在迁移核对后通过管理授权流程明确范围、原因和版本重新授予；
- 快照 JSON 上限 4 MiB；拒绝未知字段、重复键及尾随内容，防止把 MFA/外部身份字段静默丢弃；
- 必须提供 `source_commit`，`batch_id` 默认使用 UUID，dry-run 不修改输入快照；
- 冲突（重复 ID/用户名/邮箱/角色、未知角色、无登录凭据、bcrypt 格式/成本无效、非法邮箱或超长字段）在 dry-run 列出，存在冲突时不写入；
- 此工具目前只导入密码登录账号；含 MFA 或外部身份的账号必须先完成对应凭据迁移方案，不能用空密码伪造已完成导入；
- 成功后写 `legacy_import_batches`（源提交、位点、计数、指纹、终态）；
- 不自动合并重复邮箱，不替用户改名。

导入后仍需执行第 3 节第 4 步的校验与受限管理员范围重算。