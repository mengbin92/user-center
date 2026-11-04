# v0.5.1 · 2026-11-04

上一版：[v0.5.0](./release-v0.5.0.md) · [GitHub Release](https://github.com/mengbin92/user-center/releases/tag/v0.5.1)

## 修复

- **组织接口未登录访问导致 panic**：`/api/v1/orgs*` 缺少 actor 校验（`/me` 与管理端都有），
  未登录请求会以零值 `ActorContext` 进入用例并解引用 `actor.User`，连接被直接断开而不是返回
  401。现在组织与组织域 IAM 的全部 RPC 入口统一 `requireActorMeta` 前置校验，失败返回 401，
  同时保留租户审计需要的 request id 与客户端信息。
- 新增回归：未登录访问 `/orgs`、`/orgs/{id}`、成员、IAM 角色/授权、审计 6 条路径均返回 401。

## 验证

- `go vet ./...`、`go test ./...` 全绿；前端 `npm test`（57 项）与 `npm run build` 通过。
- 本地 Docker 全流程（独立 compose project，MySQL 8.4 + Redis + migrate + 镜像）：
  - 迁移 `001..006` 全部应用，V2.3 上下文列与 `organization_id` 存在；
  - 31 项 API 断言全部通过：登录、组织创建、内置角色（3 个 / owner 11 条 Grant）、
    权限目录、授权列表、租户审计、MFA 注册与 TOTP Step-up、自定义角色、重复角色 409、
    平台权限拒绝、内置角色不可变、跨租户分配 404、平台视图与 `/me` 不含组织角色；
  - 数据库抽查：平台上下文 3 个角色、每组织 4 个角色（3 内置 + 1 自定义）、组织分配与
    `organization_id>0` 审计按预期落库；成员列表返回非零 `id/role/status`；日志无 panic。
- 代码审查记录：[code-review-v23-2026-11-04](../code-review-v23-2026-11-04.md)。

## 兼容性

无 API、配置或迁移变更；直接替换镜像即可。
