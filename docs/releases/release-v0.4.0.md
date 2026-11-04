# v0.4.0 · 2026-11-04

上一版：[v0.3.0](./release-v0.3.0.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.4.0)

## V2.2：组织、部门与成员

- 组织创建/列表/详情/改名/归档；创建者自动成为 owner。
- 组织成员角色 `owner/admin/member`，支持按用户名/邮箱添加、部门挂接、角色调整、移除和主动退出。
- 最后一名 owner 不能被降级、移除或退出。
- 部门树：创建/改名/归档、父部门校验、防止成环、成员部门分配。
- 平台 root/admin 可查看全部组织并归档。
- 普通 member 查看成员列表时不返回邮箱；owner/admin/platform 可见。
- 组织/成员/部门变更写审计事件；组织归档与成员增改删要求近期 Step-up。

## 前端

- 账户顶栏组织切换器与“组织”入口。
- `/orgs` 组织列表/创建。
- `/orgs/:id` 概览/成员/部门/设置。
- `/admin/organizations` 平台组织目录与归档。

## 边界

组织角色独立于平台 IAM 角色；组织域 IAM 上下文（`organization:{id}`）、组织级资源策略与多租户数据隔离是 V2.3。当前没有邀请接受流程，管理员直接添加现有启用账号。

## 兼容性/升级

- 新增 MySQL 迁移 `005_organizations.sql`，执行 `cmd/migrate`。
- 新增权限 `organization.admin.read/update` 与菜单 `admin/organizations`。
- 无 breaking API 变更。

## 验证

- Go 全量测试（组织生命周期、越权拒绝、最后 owner、部门、MySQL 005）。
- 前端构建与测试（组织路由/成员角色规则）。
- Docker/CI 三任务。
