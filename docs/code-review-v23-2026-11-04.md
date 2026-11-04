# V2.3 代码审查记录（2026-11-04）

审查范围：v0.4.0..v0.5.0 全部变更——授权上下文域模型、租户隔离数据层、组织域 IAM
业务/接口层、组织端点权限化改造、前端组织角色与审计页签。审查发现的问题均已修复，
并回归验证。

## 主要发现与修复

| 优先级 | 原问题及影响 | 修复与验证 |
|---|---|---|
| P1 | 组织角色泄漏到平台视图：`RolesForUser` 未过滤上下文，组织分配的角色（`org_owner`、自定义角色）会出现在 `/me`、用户详情、导出、OIDC 用户角色等与平台用户相关的响应中，破坏多租户隔离 | 查询固定附加 `context_type='platform' AND context_id=0`；`CountsByRole` 同步过滤；HTTP 用例验证平台角色目录、`/me` 不含组织角色，且普通成员无法读取平台角色目录 |
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
- 新增回归：组织角色不进入平台角色目录与 `/me`；同名组织角色重复创建返回 409。
