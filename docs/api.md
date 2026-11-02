# API 契约

契约来源：`api/usercenter/v1/*.proto`，生成物包括 `*.pb.go`、`*_grpc.pb.go`、`*_http.pb.go` 与根目录 `openapi.yaml`。前端类型从 OpenAPI 生成，不手写第二套响应结构。

## 1. 通用约定

- 前缀：`/api/v1`；公开认证在 `/api/v1/auth/*`。
- JSON：`snake_case`；枚举使用小写字符串（`enabled`、`disabled`、`archived`、`allow`、`deny`）。
- ID、revision、计数：十进制字符串。前端不得先转 `Number` 再转回字符串。
- 时间：RFC 3339 UTC（例：`2026-11-02T08:00:00Z`）。
- 成功：资源对象直接返回；列表 `{items, meta:{next_page_token,total_size}}`。
- 失败：使用 HTTP 状态码，响应体 `{code, reason, message, metadata}`；不再使用 HTTP 200 + `success=false`。
- 分页：`page_size` 默认 20、上限 100；`page_token` 不透明并绑定筛选条件。
- 并发：敏感写操作必须携带 `expected_revision`；策略写操作携带 `expected_policy_revision`；冲突返回 409 + `current_revision` / `current_policy_revision`。
- 审计：管理写操作必须携带 `reason`；高风险操作要求近期 Step-up。

## 2. Cookie 与 CSRF

| Cookie | 属性 | 用途 |
|---|---|---|
| `uc_session` | HttpOnly, SameSite=Lax, Secure（生产） | 浏览器会话 |
| `uc_csrf` | 非 HttpOnly, SameSite=Lax | 双提交 CSRF 令牌 |

所有 `POST`/`PATCH`/`PUT`/`DELETE` 到 `/api/v1` 的请求必须带 `X-CSRF-Token`，其值等于 `uc_csrf` Cookie。首次访问 `GET /api/v1/auth/context` 会下发 Cookie。`Authorization: Bearer` 不用于浏览器接口。

## 3. 认证流程

```text
GET  /auth/context                      → 注册开关、提供方、csrf_token、密码策略
POST /auth/registration-challenges      {email} → {challenge_id, expires_at}
POST /auth/register                     {username,email,password,code,challenge_id,terms_version}
POST /auth/login                        {username,password} → authenticated | mfa_required
POST /auth/mfa/complete                 {challenge_id,code} → authenticated + Set-Cookie
POST /auth/logout                       撤销当前会话 + 清 Cookie
POST /auth/password-reset-challenges     {identifier} → 统一响应，不泄露账号是否存在
POST /auth/password-reset                {challenge_id,code,new_password}
GET  /auth/providers/{provider}/start    ?mode=login|bind → 302 到提供方
GET  /auth/providers/{provider}/callback ?state&code → 302 / Set-Cookie
```

登录成功后服务端设置 Cookie；响应不返回任何 bearer token。MFA 登录时先返回短期 challenge，不建立完整会话。`LoginReply` 还包含 `password_change_required` 和 `mfa_enrollment_required`：前者要求先改初始密码，后者要求管理员先绑定 TOTP。

OAuth 使用单次 `state`（Redis）与 HttpOnly state Cookie；`mode=bind` 必须已登录。回调只接受服务端交换，不把 provider access token 返回浏览器。未绑定账号登录返回 `OAUTH_NOT_BOUND`，不回退为按邮箱自动合并。若账号已启用 MFA，OAuth 登录不会直接建立会话，而是重定向到 `/login?mfa_challenge=...` 完成第二因素。

## 4. 本人接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/me` | 本人资料（含邮箱、角色、MFA 状态） |
| PATCH | `/me` | `display_name`、`update_mask`、`expected_revision` |
| POST | `/me/password:change` | 当前密码 + 新密码；成功后其他会话撤销 |
| POST | `/me/email-challenges` | 新邮箱 + 当前密码；验证码发往新邮箱 |
| POST | `/me/email:confirm` | 完成换绑；提升身份版本 |
| GET | `/auth/providers/{provider}/start` | 第三方登录/绑定入口（`?mode=bind` 需登录） |
| GET | `/auth/providers/{provider}/callback` | 服务端 code 交换、绑定或建立会话 |
| GET | `/me/external-identities` | 绑定列表（subject 脱敏） |
| DELETE | `/me/external-identities/{id}` | 不能移除最后一种登录方式；要求 Step-up |
| GET | `/me/security` | MFA/密码可用性/恢复码数量/Step-up 状态 |
| POST | `/me/mfa:setup` | 当前密码 → 一次性 secret + otpauth URI |
| POST | `/me/mfa:confirm` | 首个 TOTP → 返回 8 个恢复码（仅本次） |
| POST | `/me/mfa:disable` | 密码 + TOTP/恢复码 |
| POST | `/me/mfa/recovery-codes:rotate` | 密码 + TOTP → 新恢复码 |
| POST | `/me/security:verify` | 密码 + TOTP → Step-up 证明（5 分钟） |
| GET | `/me/sessions` | 本人会话，不返回令牌 |
| DELETE | `/me/sessions/{id}` | 撤销本人会话 |
| POST | `/me/sessions:revoke-others` | 撤销除当前外全部会话 |
| GET/PUT | `/me/session-roles` | 查看/切换激活角色（动态互斥） |
| GET | `/me/authorization` | 当前权限投影 + 菜单键 + 版本 |
| GET | `/me/security-events` | 本人登录/安全事件 |

## 5. 管理用户接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/admin/overview` | 受 `identity.user.list` 范围约束的统计 |
| GET | `/admin/users` | `keyword/status/role_id/mfa_enabled/page_size/page_token` |
| POST | `/admin/users` | 创建；默认 `member`；可发激活邮件；禁止客户端指定 balance/group |
| GET | `/admin/users/{id}` | 核心资料 + 角色 + MFA 状态 |
| PATCH | `/admin/users/{id}` | 仅资料字段；CAS + reason |
| POST | `/admin/users/{id}:set-status` | enabled/disabled；禁用会撤销全部会话 |
| POST | `/admin/users/{id}:archive` | 归档；要求 Step-up；root 受保护 |
| POST | `/admin/users/{id}/password-reset-requests` | 发送重置链接；不返回密码 |
| POST | `/admin/users/{id}/mfa:reset` | 要求 Step-up；提升身份版本 |
| POST | `/admin/users/{id}/email-changes` | 新邮箱变更挑战；要求 Step-up；验证码发往新邮箱 |
| POST | `/admin/users/{id}/email-changes:confirm` | 校验验证码、更新邮箱、撤销该用户会话 |
| GET | `/admin/users/{id}/sessions` | 范围受限的会话读取 |
| POST | `/admin/users/{id}/sessions:revoke` | 指定或全部撤销，写审计 |
| GET | `/admin/users/{id}/effective-permissions` | 角色、继承、Scope、拒绝解释 |
| POST | `/admin/users:export` | 生成 CSV；字段白名单 |
| GET | `/admin/exports/{id}` | 只能访问有权限的任务 |
| GET | `/admin/exports/{id}/download` | 再次验证会话、任务归属与过期 |

邮箱仅在调用者拥有 `identity.user.contact.read` 时返回；否则列表与详情中的邮箱为空字符串。前端遮罩不是安全边界。

## 6. IAM 接口

| 接口族 | 路径 |
|---|---|
| 资源/权限 | `GET /admin/iam/resources`；`/admin/iam/permissions` list/get/create/patch；`{id}:set-status`、`{id}:archive`、`{id}/references` |
| 角色 | `/admin/iam/roles` list/create/get/patch；`{id}:copy`、`{id}:set-status`、`{id}:archive`、`{id}/members` |
| 角色关系 | `GET/PUT /admin/iam/roles/{id}/permissions`、`/inheritance`；`POST /admin/iam/roles/{id}:preview` |
| 分配 | `GET /admin/users/{id}/roles`；`GET /admin/iam/assignments`（用户/角色/状态筛选）；`POST /admin/iam/assignments`；`{id}:revoke`；`assignments:batch-preview`、`assignments:batch-assign`（≤100，整批原子） |
| 委派 | `GET/POST /admin/iam/delegations`；`PATCH /{id}`；`POST /{id}:revoke`（目标角色、用户范围、assign/revoke、有效期；V1 列表不分页） |
| 约束 | `GET/POST /admin/iam/constraints`；`PATCH/DELETE /admin/iam/constraints/{id}` |
| 菜单 | `GET/POST /admin/iam/menus`；`PATCH /admin/iam/menus/{id}`；`{id}:archive` |
| 解释/模拟 | `POST /admin/iam/authorization:explain`、`authorization:simulate` |

写操作要求 `reason`；角色/分配/约束变更要求 Step-up（按实现中的 operation 集合）。

## 7. 内部 gRPC

`IntegrationService` 仅注册在 `:9090`，不注册浏览器 HTTP 方法。若设置 `USER_CENTER_INTEGRATION_TOKEN`，调用方必须携带 `authorization: Bearer <token>`。

| RPC | 语义 |
|---|---|
| `ValidateSession` | 校验原始会话令牌、应用、身份版本、状态、有效期 |
| `ValidateSubject` | 只读用户启停与身份版本，供 API Key owner 组合本地状态 |
| `GetUser` / `BatchGetUsers` | 最小核心资料，批量 ≤100 |
| `GetSessionAuthorization` | 当前应用可见的权限投影 + 菜单键 |
| `GetResourceAuthorization` | 给定操作与资源 owner 事实返回 allow/deny |
| `RevokeSession` | 幂等撤销 |

## 8. 错误码

| HTTP | reason | 前端行为 |
|---|---|---|
| 400 | `VALIDATION_FAILED`、`CHALLENGE_INVALID` | 字段提示；挑战失败不区分账号存在性 |
| 401 | `UNAUTHENTICATED`、`SESSION_REVOKED`、`INVALID_CREDENTIALS` | 清缓存并登录 |
| 403 | `PERMISSION_DENIED`、`PROTECTED_ACCOUNT`、`ROOT_PROTECTED` | 明确无权；不降级为旧角色模式 |
| 403 | `STEP_UP_REQUIRED`、`MFA_ENROLLMENT_REQUIRED`、`PASSWORD_CHANGE_REQUIRED` | 进入验证/改密流程 |
| 403 | `DELEGATION_REQUIRED` | 当前角色未被委派覆盖该目标/动作 |
| 404 | `USER_NOT_FOUND`、`RESOURCE_NOT_FOUND` | 无权获知存在性的对象统一不存在 |
| 409 | `REVISION_CONFLICT`、`USERNAME_EXISTS`、`ROLE_CONSTRAINT_VIOLATION`、`POLICY_CONFLICT`、`OAUTH_NOT_BOUND`、`OAUTH_ALREADY_BOUND` | 回读、展示差异、重新提交 |
| 401 | `INTEGRATION_AUTH_FAILED`（gRPC 映射为 Unauthenticated） | 检查接入客户端凭据、允许方法与有效期 |
| 429 | `RATE_LIMITED`、`MFA_LOCKED` | 使用 Retry-After/倒计时，不高速重试 |
| 503 | `DEPENDENCY_UNAVAILABLE`、`AUTHORIZATION_UNAVAILABLE` | 显示服务异常并保持拒绝，不显示空权限 |

## 9. 示例

```json
{
  "id": "12345",
  "username": "demo.user",
  "display_name": "演示用户",
  "email": "demo@example.com",
  "email_verified": true,
  "status": "enabled",
  "revision": "8",
  "identity_version": "4",
  "created_at": "2026-11-02T08:00:00Z",
  "mfa_enabled": false,
  "roles": [{"id": "3", "code": "member", "name": "普通成员"}]
}
```

```json
{
  "code": 409,
  "reason": "REVISION_CONFLICT",
  "message": "数据已被更新，请刷新后重试",
  "metadata": {"request_id": "req_example", "current_revision": "9", "conflict_type": "target"}
}
```
