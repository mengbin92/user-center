# v0.5.0 · 2026-11-04

上一版：[v0.4.0](./release-v0.4.0.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.5.0)

## V2.3：组织域 IAM 与多租户隔离

- 授权上下文：`platform` 与 `organization:{id}`。Grant 只在签发它的上下文生效；
  权限的 `context_types` 不含请求上下文时直接拒绝，不会回退到平台策略。
- 组织内置角色 `org_owner/org_admin/org_member` 随组织创建落地；成员角色
  （owner/admin/member）是它们的投影，变更成员角色即替换内置分配，移除/退出
  撤销该组织全部分配。
- 组织自定义角色：`/api/v1/orgs/{id}/iam/roles` 创建/改名/归档，`/permissions`
  覆盖 Grant；只能授予 `context_types` 含 `organization` 的权限，只支持 allow；
  `org_` 前缀与内置角色不可修改。
- 组织授权：`/iam/assignments` 列出/分配/撤销本组织角色，内置角色必须走成员角色
  接口，因此"最后一名 owner"保护仍然成立。
- 租户审计：`iam_audit_events.organization_id` 记录归属，`/api/v1/orgs/{id}/audits`
  只返回本组织事件；平台审计仍保留全量可见性。
- 组织端点改为权限驱动（`organization.member.*`、`department.*`、`iam.*`、
  `audit.read`、`settings.update`、`archive`），不再只比较成员角色字符串。

## 隔离与边界

| 场景 | 行为 |
|---|---|
| 平台角色访问组织端点 | 只有 `root/admin` 显式治理覆盖；普通平台角色无组织内权限 |
| 组织角色访问平台接口 | 组织上下文不外溢，平台查询固定过滤 `context_type='platform'` |
| URL/请求体传入其他组织的角色或分配 ID | `RESOURCE_NOT_FOUND` |
| 组织 SQL 查询 | 强制携带 `context_type/context_id`，跨租户行不可见、不可写 |
| 组织审计 | 按 `organization_id` 过滤，租户之间互不可见 |

组织成员、部门仍以 `organization_id` 逻辑分区，尚未做独立库/表分区或 RLS；平台
管理员跨租户访问是设计内的治理能力，会保留审计。

## 修复

- 组织成员列表返回零值 `id/role/status`：查询扫描到不可导出的内嵌 PO，GORM 无法
  填充。改为显式字段扫描后，成员列表与依赖成员的界面恢复正常（V2.2 回归）。

## 兼容性/升级

- 新增 MySQL 迁移 `006_org_iam.sql`：`iam_roles`/`iam_user_roles` 增加
  `context_type`/`context_id`，`iam_roles.code` 唯一键改为
  `(context_type, context_id, code)`；`iam_audit_events` 增加 `organization_id`。
- `cmd/migrate` 在种子后执行 `BackfillOrganizationIAM`，为存量组织补齐内置角色与
  内置分配；幂等，可重复执行。未回填时首次访问组织端点也会懒回填。
- 新增 11 个组织域权限（`organization.member.*`、`organization.department.*`、
  `organization.iam.*`、`organization.audit.read`、`organization.settings.update`、
  `organization.archive`），种子自动登记。
- 无 breaking API 变更；平台 IAM 行为不变。

## 验证

- Go 全量测试：域层上下文隔离、数据层跨上下文不可读写、HTTP 层跨租户拒绝、
  自定义角色授权生效、内置角色不可变、成员角色同步、租户审计过滤、存量组织回填。
- `go vet ./...`、`go test ./...`、前端 `npm test`（57 项）与 `npm run build`。
- MySQL 迁移测试（`USER_CENTER_MYSQL_TEST_DSN`）覆盖 006 的列与索引；本地 SQLite
  AutoMigrate 与迁移脚本保持一致。
