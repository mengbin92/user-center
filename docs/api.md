# API 契约

契约来源：`api/usercenter/v1/*.proto`，生成物包括 `*.pb.go`、`*_grpc.pb.go`、`*_http.pb.go` 与根目录 `openapi.yaml`。前端类型从 OpenAPI 生成，不手写第二套响应结构。

## 1. 通用约定

- 前缀：`/api/v1`；公开认证在 `/api/v1/auth/*`。
- JSON：ProtoJSON，`snake_case`；保留空集合与 false，拒绝未知字段；枚举使用小写字符串（`enabled`、`disabled`、`archived`、`allow`、`deny`）。
- ID、revision、计数：十进制字符串。前端不得先转 `Number` 再转回字符串。
- 时间：RFC 3339 UTC（例：`2026-11-02T08:00:00Z`）。
- 成功：资源对象直接返回；列表 `{items, meta:{next_page_token,total_size}}`。
- 失败：使用 HTTP 状态码，响应体 `{code, reason, message, metadata}`；不再使用 HTTP 200 + `success=false`。
- 分页：`page_size` 默认 20、上限 100；`page_token` 不透明并绑定筛选条件。
- 并发：敏感写操作必须携带 `expected_revision`；策略写操作携带 `expected_policy_revision`；冲突返回 409 + `current_revision` / `current_policy_revision`。
- 审计：管理写操作必须携带非空 `reason`（≤512 字符），不自动填充默认理由；缺失时返回 400 `VALIDATION_FAILED`。高风险操作要求近期 Step-up。
- 请求大小：JSON 请求体最多 1 MiB，超限返回 413。更新掩码逐字段匹配，未列入掩码的字段保持不变。

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
GET  /auth/providers/{provider}/start    ?mode=login|bind|verify → 302 到提供方
GET  /auth/providers/{provider}/callback ?state&code → 302 / Set-Cookie
```

登录成功后服务端设置 Cookie；响应不返回任何 bearer token。MFA 登录时先返回短期 challenge，不建立完整会话。`LoginReply` 还包含 `password_change_required` 和 `mfa_enrollment_required`：前者要求先改初始密码，后者要求管理员先绑定 TOTP。

OAuth 使用单次 `state`（Redis）与 HttpOnly state Cookie；`mode=bind` 必须已登录。回调只接受服务端交换，不把 provider access token 返回浏览器。未绑定账号登录返回 `OAUTH_NOT_BOUND`，不回退为按邮箱自动合并。若账号已启用 MFA，OAuth 登录不会直接建立会话，而是重定向到 `/login?mfa_challenge=...` 完成第二因素。

纯 OAuth 账号可用 `mode=verify` 重新认证已经绑定的外部身份。state 绑定当前用户、会话和身份版本，回调 subject 必须仍属于当前用户；成功后服务端保存 5 分钟主认证证明。该证明允许设置首个本地密码或开始 MFA 设置，不替代已经启用的第二因素。已有 MFA 时，先完成 `/me/security:verify`，再设置首个本地密码。证明不返回给浏览器，跨会话、过期、身份变更及 state 重放均被拒绝。

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
| POST | `/admin/users` | 仅创建默认 `member`；其他角色走独立分配；设置初始密码另需 credential.update + Step-up；禁止 balance/group |
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
| GET | `/admin/exports/{id}/download` | 再次验证当前会话、任务归属、权限版本与授权有效期 |

用户管理创建/更新/启停/归档及安全动作必须携带 `expected_policy_revision`；操作已有用户还需 `expected_revision`。非 root 管理员不能变更 root 凭据、邮箱或 MFA。接入客户端轮换和停用也要求目标 revision。

邮箱仅在调用者拥有 `identity.user.contact.read` 时返回；否则列表与详情中的邮箱为空字符串。邮箱关键词检索还要求完整范围的联系方式读取权限，避免通过筛选推断被隐藏的邮箱。前端遮罩不是安全边界。

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
| 解释/模拟 | `POST /admin/iam/authorization:explain`、`authorization:simulate`；`resource_id` 非空时返回 400，资源级解释需在资源 owner 执行 |

所有 IAM 管理写必须携带 `reason` 与 `expected_policy_revision`，修改/复制/撤销已有资源还需其 `expected_revision`；角色/分配/约束变更要求 Step-up。

## 6.1 组织、部门、成员与组织域 IAM（V2.2 / V2.3）

| 接口 | 说明 |
|---|---|
| `GET/POST /api/v1/orgs` | 我的组织 / 创建组织（创建者为 owner） |
| `GET/PATCH /api/v1/orgs/{id}`；`{id}:archive` | 组织详情/改名/归档；归档要求 owner 或平台管理员 |
| `GET/POST /api/v1/orgs/{id}/members` | 成员列表/添加（用户名或邮箱、角色、部门） |
| `PATCH/DELETE /api/v1/orgs/{id}/members/{user_id}` | 修改角色/部门、移除；要求当前 revision |
| `POST /api/v1/orgs/{id}/members:leave` | 主动退出；最后一名 owner 不能退出 |
| `/api/v1/orgs/{id}/departments*` | 部门列表/创建/修改/归档；禁止父子成环 |
| `GET /api/v1/admin/organizations`；`{id}:archive` | 平台 root/admin 查看/归档全部组织 |

组织角色规则：

- `owner` 可管理成员与部门、授予/撤销 owner；最后一名 owner 不能被降级、移除或退出。
- `admin` 可管理 member、添加 admin，但不能修改 owner 或其他 admin。
- `member` 只读组织与部门；成员列表中的邮箱对普通 member 隐藏。
- 平台 `root/admin` 对组织拥有 `platform` 角色，可查看与归档全部组织。
- 组织归档、成员添加/角色变更/移除和平台归档要求近期 Step-up（MFA）；成员退出、创建组织与部门维护不要求 Step-up。
- 组织角色与平台 IAM 角色相互独立；组织域 IAM 在 `organization:{id}` 上下文求值，平台角色不会获得组织内权限。

组织域 IAM（V2.3）：

| 接口 | 说明 |
|---|---|
| `GET /api/v1/orgs/{id}/iam/roles` | 本组织角色（含内置 `org_owner/org_admin/org_member`）与 Grant |
| `GET /api/v1/orgs/{id}/iam/permissions` | 可授予的组织域权限目录（`context_types` 含 `organization`） |
| `POST /api/v1/orgs/{id}/iam/roles` | 创建自定义角色（`org_` 前缀保留；仅 allow；scope 受权限支持范围约束） |
| `PATCH /api/v1/orgs/{id}/iam/roles/{role_id}` | 修改名称/描述；要求 `expected_revision` |
| `PUT /api/v1/orgs/{id}/iam/roles/{role_id}/permissions` | 覆盖角色 Grant；要求 `expected_revision` |
| `POST /api/v1/orgs/{id}/iam/roles/{role_id}:archive` | 归档自定义角色；仍被分配时返回 `ORGANIZATION_ROLE_IN_USE` |
| `GET /api/v1/orgs/{id}/iam/assignments` | 本组织授权列表（含成员、角色、来源、有效期） |
| `POST /api/v1/orgs/{id}/iam/assignments` | 给本组织成员分配自定义角色；内置角色必须经成员角色接口调整 |
| `DELETE /api/v1/orgs/{id}/iam/assignments/{assignment_id}` | 撤销授权；`expected_revision`、`reason` 走 query |
| `GET /api/v1/orgs/{id}/audits` | 本组织审计（`action`/`from`/`to`/`offset`/`page_size`） |

租户隔离语义：

- `{id}` 是唯一租户选择器，请求体不能覆盖；其他组织的角色/分配/事件 ID 一律按不存在处理。
- 组织操作要求有效成员身份；平台 `root/admin` 保留显式覆盖，用于治理与支持。
- 自定义角色不能授予平台权限（`identity.*`、`iam.*`、`settings.*` 等），内置角色不可修改或归档。
- 组织审计只返回 `organization_id` 匹配的事件；平台审计仍保留全量可见性。
- 创建/修改/归档角色、分配/撤销角色与成员增改删要求近期 Step-up。

## 6.2 OIDC Provider（V2）

标准授权码 + PKCE 流程：

```text
GET  /.well-known/openid-configuration   issuer、端点、支持的 scope/算法
GET  /oidc/jwks                          RSA 公钥（kid）
GET  /oidc/authorize                     需浏览器会话；redirect_uri 必须精确注册
POST /oidc/token                         authorization_code / refresh_token
GET  /oidc/userinfo                      Bearer access token
```

- 支持 `openid profile email offline_access`；`offline_access` 才返回 refresh token。
- PKCE 仅支持 `S256`；public client 强制 PKCE。
- ID/access token 使用 RS256；`kid` 对应 JWKS。生产必须通过 `OIDC_SIGNING_KEY_PATH`/`OIDC_SIGNING_KEY_PEM` 提供稳定 RSA 私钥，否则重启后 token 失效。
- 客户端管理：`GET/POST /admin/oidc-clients`、`PATCH /{id}`、`{id}:rotate-secret`、`{id}:disable`；密钥只返回一次。
- 当前 V2.1 对管理员预先注册的客户端自动同意授权，未提供交互式 consent 页面；如需用户逐次同意，在 V2.2 增加 consent UI 与 `prompt=consent` 持久化。

## 7. 内部 gRPC

`IntegrationService` 仅注册在 `:9090`，不注册浏览器 HTTP 方法。调用方必须携带数据库接入客户端的 `authorization: Bearer <client_id.secret>`；凭据状态/有效期/方法白名单逐次校验。旧 `USER_CENTER_INTEGRATION_TOKEN` 旁路已移除。

| RPC | 语义 |
|---|---|
| `ValidateSession` | 校验原始会话令牌、应用、身份版本、状态、有效期；application_code 必填且等于签发值（V1 为 user-center） |
| `ValidateSubject` | 只读用户启停与身份版本，供 API Key owner 组合本地状态 |
| `GetUser` / `BatchGetUsers` | 最小核心资料，批量 ≤100 |
| `GetSessionAuthorization` | 校验应用后，仅返回调用方 service_owner 拥有资源的权限投影 + 菜单键 |
| `GetResourceAuthorization` | execution_point 等于 operation；提供真实 owner_user_id/resource_id；调用方匹配资源 owner；返回该对象最小范围与 valid_until |
| `RevokeSession` | 携带 session_token 用户证明与 reason，只撤销同用户/同应用会话；审计与撤销同事务 |

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
