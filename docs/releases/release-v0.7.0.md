# v0.7.0 · V2.4 W3（波次附记 · 未单独打标）

> 状态：**波次追溯记录，不打 tag**。V2.4 全部波次统一发布为 [v0.6.0](./release-v0.6.0.md)（见该文件的版本判定与决策说明）。本文件保留 W3 的变更细节。

上一版：[v0.6.0](./release-v0.6.0.md)

本版包含 V2.4 路线图 W3（集成面与治理体验）共 6 个工作项：R7–R12。

## 契约变更

- `integration.proto` 新增 `Authenticate` / `CompleteMFA`；`me.proto` 新增 `UpdateUsername`；`iam.proto` 新增 `PreviewAssignment`；`settings.proto` 新增 provider 只读视图与组织配额设置组。
- `009_org_quota.sql`：`organizations(created_by, status)` 索引，用于配额事务的行锁范围收敛。
- `settings.auth.update` 现在推进 policy revision，使 provider 启停与既有导出/授权快照语义一致。

## 集成面

- **R7 内部 gRPC 登录**：调用方必须是方法白名单中的接入客户端；凭据只在服务端 gRPC 传输；复用 HTTP 登录的限流与失败计数（不能形成绕过通道）；MFA 挑战绑定应用与身份版本、单次消费，HTTP 挑战不能被 gRPC 消费；会话 `ApplicationCode` 绑定调用方应用，`ValidateSession` 语义不变；成功审计记录 `actor_service_id`。
- **R8 审计详情页**：`/admin/audits/:id` 展示 actor/action/target/result/reason/request_id/before/after/diff/版本；长 JSON 可折叠、空 diff 降级提示；返回列表保留原筛选条件。

## 体验与治理

- **R9 provider 配置页**：`/admin/settings/providers` 只读展示 GitHub/Google 的启用状态、凭据来源（env）、是否已配置、回调地址与所需环境变量；未配置给出引导且不允许启用；凭据不回显。决策已写入 [API 契约](../api.md)：凭据来源单一化，入库需另行设计加密/轮换/审计并先移除 env 来源。
- **R10 用户名修改**：`POST /api/v1/me/username:update` 要求 Step-up + `expected_revision` + 当前密码；归一化唯一性与保留字/格式校验与注册路径共用；冲突返回 `USERNAME_EXISTS`/`REVISION_CONFLICT`；旧用户名不能登录；审计记录前后值。**管理端不提供改名接口**，结论已写入 API 文档。
- **R11 单条分配预览**：`POST /api/v1/admin/iam/assignments:preview` 复用 `PreviewBatch` 的资格计算与 `EffectivePermissions` 的权限求值，返回将获得的权限、deny 来源、scope 交集、有效期与角色状态/上限；不写库。
- **R12 组织创建配额**：默认关闭，开启后每用户默认 5 个（1–1000 可配）；超限返回 `ORGANIZATION_QUOTA_EXCEEDED`（HTTP 409）；计数在事务内并对该用户组织行加锁；拒绝写审计；平台管理员豁免并已在页面/文档说明。

## 验证

`go vet ./...`、`go test ./...`、`cd web && npm test && npm run build` 全部通过；新增用例覆盖 gRPC 登录成功/错误密码/停用账号/未授权 app/会话 audience/MFA 挑战重放、用户名保留字/冲突/Step-up/旧名登录失败、单条预览、配额上限与豁免、provider 只读、审计详情渲染与空 diff 降级。

## 未执行 / 已知限制

- 迁移真跑已在临时 `mysql:8.4` 容器通过；**本地 compose 全流程冒烟未执行**，HTTP 级验证基于 SQLite 集成测试。
- 路线图 §6 工程前置（把 v0.5.1 Docker E2E 脚本收进 `scripts/e2e/`）本次未做。
- R13 WebAuthn/Passkey 与 R14 个人信息保留清理按路线图分别滑动到 V2.5 / 未排期，未纳入本版。
