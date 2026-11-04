# V2.3 代码审查记录（2026-11-04）

审查范围：v0.4.0..v0.5.0 全部变更——授权上下文域模型、租户隔离数据层、组织域 IAM
业务/接口层、组织端点权限化改造、前端组织角色与审计页签。审查发现的问题均已修复，
并回归验证。

## 主要发现与修复

| 优先级 | 原问题及影响 | 修复与验证 |
|---|---|---|
| P1 | 组织角色泄漏到平台视图：`RolesForUser` 未过滤上下文，组织分配的角色（`org_owner`、自定义角色）会出现在 `/me`、用户详情、导出、OIDC 用户角色等与平台用户相关的响应中，破坏多租户隔离 | 查询固定附加 `context_type='platform' AND context_id=0`；`CountsByRole` 同步过滤；HTTP 用例验证平台角色目录、`/me` 不含组织角色，且普通成员无法读取平台角色目录 |
| P1 | 未登录访问组织接口直接 panic：`OrganizationService` 未校验 actor，HTTP 层也没有对 `/api/v1/orgs` 做统一鉴权，零值 actor 在 `Create` 等用例解引用 `actor.User` 触发空指针（Go 连接被中断，返回空响应而不是 401/403）；同路径下的 `DELETE`/`POST` 同样受影响 | 组织服务全部 RPC 入口改为 `requireActor` 前置校验，返回 401；新增未登录访问 `/orgs`、`/orgs/{id}`、成员、IAM、审计共 6 条路径的回归断言；Docker 冒烟中未登录探测均返回 401 且日志无 panic |
| P1 | **未绑定 MFA 的账号无法完成任何 Step-up**：`SecurityUsecase.Verify` 无条件调用 `verifyMFA`，未启用 MFA 时直接返回"尚未启用多因素认证"，导致非 MFA 的组织管理员（以及关闭管理员 MFA 策略后的账号）永远无法执行成员增改删、角色/授权、组织归档等受保护操作，E2E 中表现为 `STEP_UP_REQUIRED` 死循环 | Step-up 改为"有第二因素则必须校验，无第二因素则以重新输入主密码作为证明"；已绑定 MFA 时仅密码仍然被拒（`CHALLENGE_INVALID`），错误密码永远不通过。新增 3 条回归测试，并在 Docker E2E 中用无 MFA 的普通租户管理员验证了添加成员与创建部门 |
| P1 | 组织角色创建的并发竞态：并发创建同名组织角色时，唯一键冲突直接返回驱动错误（HTTP 500）；首次并发访问存量组织时，懒回填可能双写失败 | 仓储层把重复键映射为 `ORGANIZATION_ROLE_EXISTS`（409）；回填时先按 code 重查，对已存在但无 Grant 的角色自愈补齐，不再因并发创建失败而中断请求 |
| P1 | 成员角色同步非幂等：重复调用（如成员部门调整）会先撤销再重建同一内置角色分配，产生无意义的分配历史 | 同步逻辑先检查活跃的目标内置分配，存在则直接跳过；HTTP 用例覆盖"成员角色变更→内置分配替换→移除→全部撤销" |
| P2 | 已归档的组织角色仍可改名/改权限 | 归档角色拒绝修改（`VALIDATION_FAILED`） |
| P2 | CHANGELOG 的租户审计接口路径写成 `/organizations/{id}/audits`，与实际路由不一致 | 更正为 `/api/v1/orgs/{id}/audits` |
| P2 | 平台角色列表用例缺少"组织角色不出现"的断言 | 补充断言：平台目录不含 `org_owner`、自定义组织角色 |

## 确认无误的设计点

- 授权上下文在域层绑定：GrantSource 与决策上下文不一致时忽略；`context_types` 不匹配返回 `CONTEXT_UNSUPPORTED`，不回退到平台策略。
- 仓储层所有组织查询在 SQL 中强制携带 `context_type/context_id`；跨租户 ID 返回 `RESOURCE_NOT_FOUND`。
- 平台管理员跨租户访问是显式治理覆盖，会保留审计；平台审计仍可见租户事件，租户审计按 `organization_id` 过滤。
- 组织域决策不使用会话角色激活，避免平台会话角色借用。
- 自定义组织角色只能授予 `context_types` 含 `organization` 的权限、只允许 allow；`org_` 前缀与内置角色不可修改，最后一名 owner 保护不受影响。
- 组织端点已由权限驱动（`organization.member/department/iam/audit/settings/archive`），不再依赖成员角色字符串；owner 专属不变量（最后 owner、owner 授予）保留。

## 验证

- `go vet ./...`、`go test ./...`、`go test -race ./domain/... ./internal/biz/ ./internal/data/` 通过。
- 前端 `npm test`（57 项）与 `npm run build` 通过。
- 新增回归：组织角色不进入平台角色目录与 `/me`；同名组织角色重复创建返回 409；未登录访问组织接口返回 401；无 MFA 账号可用密码完成 Step-up、有 MFA 时必须提供动态码。
- 本地 Docker 全流程验证（独立 compose project，MySQL 8.4 + Redis + migrate + 镜像构建）：
  - 迁移 `001..006` 全部应用，`iam_roles/iam_user_roles` 的 `context_type/context_id` 与
    `iam_audit_events.organization_id` 存在；
  - 31 项 API 断言全部通过：登录、组织创建、内置角色（3 个/owner 11 条 Grant）、组织权限目录、
    授权列表、租户审计、MFA 注册与 Step-up、自定义角色、重复角色 409、平台权限拒绝、
    内置角色不可变、跨租户分配 404、平台视图不含组织角色、`/me` 不含组织角色；
  - 数据库抽查：平台上下文 3 个角色、每个组织 4 个角色（3 内置 + 1 自定义）、
    组织上下文分配与 `organization_id>0` 的审计事件均按预期落库；
  - 成员列表返回非零 `id/role/status`（V2.2 回归修复在真实 MySQL 上生效）；
  - 运行日志无 panic。
- 第二轮角色生命周期与账号治理 E2E（15 项断言）：角色改名/改权限/归档、归档角色拒绝修改、
  陈旧 revision 409、组织归档后 404、用户禁用后登录 401、恢复后可登录、审计/导出/分配/
  委派/约束只读接口均正常。
