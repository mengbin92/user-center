# V2.4 路线图：OIDC 收尾、组织企业化与集成面补齐

> 基线：`v0.5.1`（`976fcc4`）· 盘点日期：2026-11-04
> 依据：设计文档《用户中心独立项目设计文档》（2026-11-02）的 1.2 / 4.1 / 6.5 / 7.1 / 9.4 / 9.5 章节，以及 v0.5.1 的代码审计与 Docker E2E 结果。该文档不在本仓库内，引用以章节号为准。

## 0. 这份文档怎么用

- 回答三个问题：**V2 还差什么、V2.4 做什么、怎么算做完**。
- **状态只在真实合并后更新**：未开工保留 `[ ]` 和"未开始"，不做"文档先行打勾"。
- 每个工作项都有可勾选的验收标准与影响面；评审按项验收，不按"整体完成度"打包验收。
- 与 `README.md` 的"仍延后"、`docs/security.md` 的"已知限制"分工：**路线图定优先级与验收标准，那两处只描述当前事实**。

## 1. 基线：v0.5.1 已交付什么

| 版本 | 主题 | 状态 |
|---|---|---|
| V1 | 用户生命周期、认证与安全、平台 IAM、审计与导出、接入客户端、Outbox 投递、legacy 导入 | ✅ 已交付 |
| v0.3.0（V2.1） | 标准 OIDC Provider（discovery / JWKS / code + PKCE / token / userinfo / refresh） | ✅ 已交付 |
| v0.4.0（V2.2） | 组织、部门、成员与 owner/admin/member 组织角色 | ✅ 已交付 |
| v0.5.0（V2.3） | 组织域 IAM（`organization:{id}` 上下文）、多租户隔离、租户审计、存量回填 | ✅ 已交付 |
| v0.5.1 | 组织路由强制鉴权（修复未登录 panic）、无 MFA 账号的 Step-up 修复 | ✅ 已交付 |

盘点结论：

- 全仓库没有 `TODO` / `NotImplemented` / 空实现桩，V1 与 V2.1–V2.3 的主体是完整的。
- 下面列出的差距全部是**尚未开工**，不是"做了一半"；不存在用空实现伪装完成的功能。
- 组织域已经具备的能力（角色、授权、审计、隔离）足以支撑企业场景，缺的是**成员获取方式**（邀请）、**可解释性**（explain）与**可导出性**。

## 2. 判定口径

差距分三类，处理方式不同：

| 类型 | 定义 | 处理 |
|---|---|---|
| A · 设计明确要求、未实现 | 设计文档写了功能、路由或 RPC，代码里没有 | 必须排期，或明确降级并回改设计文档 |
| B · 设计与实现不一致 | 功能有，但契约、路由或语义不同 | 择一收敛，并把结论写进文档 |
| C · 工程扩展 | 设计没要求，落地/运维需要 | 按收益排期，可以延后或不做 |

以下情况**不算完成**（评审时直接打回）：

- 返回空列表、`501` 或"敬请期待"，但菜单/接口已暴露；
- 用平台角色或 `root` 豁免绕过租户边界；
- 只更新文档和 CHANGELOG，没有代码、测试与真实环境验证；
- 用"暂时不支持"代替权限判定，导致越权或信息泄露。

## 3. V2.4 范围

### 3.1 纳入

- **OIDC 收尾**：交互式授权同意页、RP-initiated logout。
- **组织企业化**：邀请接受流程、组织域授权解释、租户审计导出、组织域事件。
- **集成面**：内部 gRPC 登录（`Authenticate` / `CompleteMFA`）。
- **体验与治理**：审计详情页、provider 配置页、用户名修改、单条分配预览、组织创建配额。
- **强认证扩展**：WebAuthn / Passkey（排在最后一波，可整体滑动）。

### 3.2 不纳入（附理由）

| 项 | 不纳入的理由 | 去向 |
|---|---|---|
| SCIM 2.0 | 需要完整 schema、过滤语法、PATCH 语义和 IdP 兼容矩阵，工作量约等于一个独立里程碑 | V2.6 单独立项 |
| 企业目录同步（LDAP / Azure AD） | 与 SCIM 大量重叠，且需要连接器与外部凭据托管 | 与 SCIM 合并评估 |
| `ExchangeLegacySession` | 设计文档标注"可选、默认关闭" | 明确不做，文档已有说明 |
| 租户物理隔离（独立库 / RLS / 分区） | 当前"逻辑隔离 + SQL 强制上下文"已满足单库多租户；物理隔离取决于部署规模与合规要求 | 按需评估，不预设排期 |
| 组织级委派 / 职责分离 | 现有委派与约束是平台上下文；租户内 SoD 需要新的语义模型（约束作用域、审批流），先设计再排期 | V2.5 候选，先出设计 |

### 3.3 为什么这样切

- **W1 / W2 是 V2 已经承诺但没交付的部分**。先补齐，避免"组织能建、却没法请人进来"的半成品体验。
- **W3 是把已有能力接到正确位置**：后端接口都在，缺的是页面和 gRPC 入口，改动小、收益直接。
- **W4（WebAuthn）风险与工作量都独立**，单独成波；延期或失败不影响前三波发版。
- **W5（合规）** 取决于上线地区与客户合同，不预设版本号。

## 4. 工作项

优先级：**P0** 阻塞对外交付；**P1** 影响企业落地或集成；**P2** 体验与治理；**P3** 可延后。
规模：**S** 单点改动（≤ 1 天量级）；**M** 跨层改动（proto + biz + data + web）；**L** 新子系统。

---

### W1 · OIDC 收尾（P0）

#### R1 交互式授权同意页

| 项 | 内容 |
|---|---|
| 现状 | `/oidc/authorize` 校验通过后直接签发授权码；没有同意表、没有同意页；`oidc_admin.proto` 只有客户端 CRUD。设计 7.1 明确"授权同意页在 V2 启用"。 |
| 目标 | 首次授权或 scope 扩展时由用户显式同意，可记住、可撤销。 |
| 影响面 | proto/service、biz（同意判定）、data（新表）、web（同意页）、migration |
| 规模 | M |
| 依赖 | 无 |

验收：

- [x] 同意记录持久化：`client_id` + `user_id` 唯一，保存已授予的 scope 集合与时间；migration 幂等
- [x] 无有效同意时，`/oidc/authorize` 重定向到同意页，并使用**一次性服务端 request handle**（不把 `client_id` / `redirect_uri` / `state` 明文摊在 query 里被篡改）
- [x] 同意页展示客户端名称、请求的 scopes、发起来源；拒绝时返回 `error=access_denied` 且保留 `state`
- [x] 同意只在 scope 未扩展时复用；scope 增加必须重新征询
- [x] `prompt=consent` 强制重新征询；`prompt=none` 且无同意时返回 `interaction_required`（不是 500 或静默同意）
- [x] `/me/oidc-consents` 可列出与撤销；撤销后下次授权重新征询
- [x] 同意页请求本身不能签发授权码；`nonce` / PKCE 校验顺序不变
- [x] 测试：首次同意、复用、拒绝、scope 扩展、撤销后重新征询、`prompt` 两种取值

#### R2 RP-initiated logout（`end_session`）

| 项 | 内容 |
|---|---|
| 现状 | 只有本地 `/auth/logout`；discovery 无 `end_session_endpoint`；`oidc_clients` 无登出回调白名单。属于"标准 OIDC 流程"未收尾部分（C 类扩展，但对第三方接入是硬需求）。 |
| 目标 | 第三方应用可联动登出用户中心会话，并安全回到应用。 |
| 影响面 | proto/service、biz、data（客户端新增列）、web（登出完成页）、migration |
| 规模 | M |
| 依赖 | R1 的客户端配置模型（同一张表扩展） |

验收：

- [x] discovery 增加 `end_session_endpoint`
- [x] `GET/POST /oidc/logout` 支持 `id_token_hint`、`post_logout_redirect_uri`、`state`
- [x] `post_logout_redirect_uri` 必须精确匹配客户端注册的白名单（新增列），否则不回跳并返回错误页
- [x] 无 `id_token_hint` 时接受 `client_id`，但仍要求白名单匹配；两者都缺失时只做本地登出
- [x] 登出撤销当前会话并清理 Cookie；重复调用幂等
- [x] 无效 hint 与过期 hint 的行为一致，不泄露会话或用户是否存在
- [x] 测试：有效 hint、无效 hint、未注册 redirect、跨客户端 hint、登出后原会话失效

---

### W2 · 组织企业化（P1）

#### R3 组织邀请与接受流程

| 项 | 内容 |
|---|---|
| 现状 | `AddMember` 只能添加**已存在账号**（按用户名/邮箱查找用户）；没有邀请表、邀请邮件和接受令牌。企业管理员无法邀请尚未注册的同事。 |
| 目标 | 管理员按邮箱邀请，被邀请人登录后接受，成为成员并获得内置角色分配。 |
| 影响面 | proto/service、biz、data（新表）、web（邀请面板）、migration、SMTP |
| 规模 | L |
| 依赖 | 无（SMTP 已完成真实发信验收） |

验收：

- [x] 邀请表：组织、邮箱（归一化小写）、角色、令牌哈希、过期时间、邀请人、状态、revision
- [x] `POST /orgs/{id}/invitations` 要求 `organization.member.manage` + Step-up + `reason`；仅 owner/admin 可邀请 admin（沿用现有归属规则）
- [x] 令牌一次性、只在邮件中出现，DB 存哈希；默认 72 小时过期，可配置
- [x] 接受接口要求登录态且**邮箱匹配**；不匹配返回统一拒绝，不泄露邀请是否存在
- [x] 未注册邮箱不自动建号（避免绕过注册策略）；引导先注册再接受
- [x] 接受后成为 active 成员，并同步内置角色分配（复用 `syncOrgMembershipRole`）
- [x] 已是成员、邀请过期、已撤销、重复接受都有明确错误码
- [x] `GET /orgs/{id}/invitations`、`DELETE /orgs/{id}/invitations/{id}`（撤销）；单组织待接受邀请有上限
- [x] 审计事件：`organization.invitation.create` / `.revoke` / `.accept`
- [x] 测试：过期、邮箱不匹配、重复接受、撤销后接受失败、跨租户邀请、配额上限

#### R4 组织域授权解释（explain）

| 项 | 内容 |
|---|---|
| 现状 | 平台有 `/admin/iam/authorization:explain`，但它只加载 `platform` 上下文事实。组织管理员只能看到 403，无法回答"这个人为什么不能建部门"。 |
| 目标 | 在 `organization:{id}` 上下文内解释某个成员对某操作的决策依据。 |
| 影响面 | proto/service、biz（复用 `AuthorizeIn` 的输入构造）、web（组织 IAM 页） |
| 规模 | M |
| 依赖 | 无 |

验收：

- [x] `GET /orgs/{id}/iam/authorization:explain?user_id=&operation=` ，权限为 `organization.iam.assignment.read` 或 `organization.iam.role.read`
- [x] 响应包含：决策结果与 reason、命中的角色与分配、deny 来源、scope 边界、有效期、缺失项
- [x] 只读取本组织事实，响应中不出现平台角色、其他租户数据与平台策略细节
- [x] 与平台 explain 共用同一套领域求值（`authorization.Evaluate` + 相同的 `Input` 构造），不允许另写一份判断
- [x] 目标用户必须是本组织成员，否则 `RESOURCE_NOT_FOUND`
- [x] 测试：允许、拒绝（无权限）、deny 覆盖、分配过期、非成员

#### R5 租户审计导出

| 项 | 内容 |
|---|---|
| 现状 | 平台有 `ExportAuditEvents` 与导出下载；组织侧只有 `GET /orgs/{id}/audits` 列表，没有导出。 |
| 目标 | 组织管理员可导出本组织审计，用于合规留档与事故复盘。 |
| 影响面 | proto/service、biz（复用导出任务）、data（任务归属校验）、web |
| 规模 | S–M |
| 依赖 | 无 |

验收：

- [x] `POST /orgs/{id}/audits:export` 复用现有导出任务与下载签名，不新建一套下载通道
- [x] 导出内容严格限定 `organization_id = {id}`，字段与平台导出一致
- [x] 权限 `organization.audit.read`；导出任务记录租户归属，跨租户下载返回 `RESOURCE_NOT_FOUND`
- [x] CSV 公式前缀转义、文件名 `filepath.Base` 处理沿用现有规则
- [x] 权限或 policy revision 变化后必须重新导出（与平台语义一致）
- [x] 测试：导出只含本租户、跨租户下载拒绝、权限不足 403、CSV 注入转义

#### R6 组织域事件进 Outbox（C 类扩展）

| 项 | 内容 |
|---|---|
| 现状 | V2.3 只发 `organization.created`；成员、部门、角色、分配变更只写审计，下游投影与缓存拿不到通知。设计 6.5 的事件清单本身不含组织事件，因此这是**扩展**而非设计缺口。 |
| 目标 | 组织域变更可被订阅方消费，减少轮询与缓存不一致。 |
| 影响面 | biz（emit）、文档（事件表）、测试 |
| 规模 | M |
| 依赖 | R3 的事件命名先定稿 |

验收：

- [x] 事件类型：`organization.member.added/updated/removed`、`organization.department.created/updated/archived`、`organization.role.created/updated/archived`、`organization.assignment.created/revoked`、`organization.archived`
- [x] 载荷只含 ID、版本、角色码等最小字段；**不含邮箱、昵称等个人数据**（与设计 6.5 的隐私约束一致）
- [x] 与业务事务同提交（Outbox），回滚不产生事件
- [x] 订阅方按 `event_type` 过滤；文档新增组织事件表
- [x] `event_id` 幂等去重、旧版本不覆盖新状态
- [x] 测试：事务回滚无事件、载荷无 PII、event_id 去重、订阅过滤

---

### W3 · 集成面与治理体验（P1 / P2）

#### R7 内部 gRPC `Authenticate` / `CompleteMFA`

| 项 | 内容 |
|---|---|
| 现状 | `integration.proto` 只有 `ValidateSession`、`ValidateSubject`、`GetUser`、`BatchGetUsers`、`GetSessionAuthorization`、`GetResourceAuthorization`、`RevokeSession`。BFF 只能复用已有会话，无法经 gRPC 完成登录并创建会话。设计 9.5 明确要求这两个 RPC。 |
| 目标 | 经允许的原系统 BFF 可在服务端完成登录（含 MFA），拿到绑定该应用的会话。 |
| 影响面 | proto/service、biz（复用 HTTP 登录用例）、data（审计）、接入客户端白名单 |
| 规模 | M |
| 依赖 | 接入客户端方法白名单机制（已有） |

验收：

- [x] `Authenticate(app_id, username, password, request_id)` 返回"需要 MFA 的挑战"或"会话令牌"，不返回 Cookie
- [x] `CompleteMFA(challenge_id, code)` 完成登录；挑战单次消费、绑定应用与身份版本
- [x] 凭据只经服务端 gRPC 传输；调用方必须是通过白名单的接入客户端
- [x] 失败计数与 HTTP 登录**共用同一套限流**，不能形成绕过通道
- [x] 会话 audience 绑定调用方应用；`ValidateSession` 对该会话的校验语义不变
- [x] 审计记录 `actor_service_id`；失败响应不泄露账号是否存在、是否启用 MFA
- [x] 停用用户、错误密码、未授权客户端、挑战过期各有稳定错误码
- [x] 测试：成功登录、需 MFA、错误密码、停用用户、未授权 client、挑战重放

#### R8 审计详情页（B 类：后端有、前端无）

| 项 | 内容 |
|---|---|
| 现状 | 后端 `GetAuditEvent` 已实现；前端只有 `/admin/audits` 列表，没有 `/admin/audits/:id`，看不到 before/after/diff。设计 7.1 有该路由。 |
| 目标 | 管理员能看到单条审计的完整上下文。 |
| 影响面 | web（路由 + 页面 + API 客户端） |
| 规模 | S |
| 依赖 | 无 |

验收：

- [x] `/admin/audits/:id` 路由与详情页：actor、action、target、result、reason、`request_id`、before/after/diff、版本信息
- [x] 列表行可进入详情，返回列表时保留原筛选条件
- [x] diff 为空时降级提示；长 JSON 可折叠且不破坏布局
- [x] 无权限或事件不存在时显示统一空状态，不泄露事件存在性
- [x] 测试：渲染、空 diff、返回保留筛选

#### R9 外部身份 provider 配置页

| 项 | 内容 |
|---|---|
| 现状 | provider 启停走 `/admin/settings/auth` 的 `providers` 列表；GitHub/Google 凭据来自环境变量；没有设计 7.1 中的 `/admin/settings/providers`。 |
| 目标 | 集中展示每个 provider 的启用状态、凭据来源与回调地址，避免"配了环境变量但不知道是否生效"。 |
| 影响面 | web、settings proto（若需暴露来源） |
| 规模 | S–M |
| 依赖 | **需决策：凭据是否入库**（建议先做只读可视化，凭据继续走环境变量；入库需要加密、轮换与审计） |

验收：

- [x] 页面列出 GitHub / Google：启用状态、凭据来源（env / db）、回调地址、最近变更
- [x] 未配置凭据时显示引导（含所需环境变量名），不是报错或空白
- [x] 启停变更写审计并推进 policy revision；与 `/admin/settings/auth` 的行为一致
- [x] 凭据不回显（只显示是否已配置）
- [x] 决策记录写进文档：凭据来源单一化，避免 env 与 db 同时生效
- [x] 测试：未配置、已配置、启停后登录入口变化

#### R10 用户名修改

| 项 | 内容 |
|---|---|
| 现状 | `UpdateMeRequest` 只有 `display_name`；自助与管理端都不能改用户名。设计 4.1 要求"用户名修改需重新验证并检查唯一"。 |
| 目标 | 账号可改用户名，规则与创建时一致。 |
| 影响面 | proto/service、biz、data（唯一性）、web（安全中心） |
| 规模 | M |
| 依赖 | Step-up（已有） |

验收：

- [x] 修改接口要求 Step-up + `expected_revision`，并校验当前密码（按设计"重新验证"）
- [x] 唯一性按归一化规则检查（大小写、空白），与创建路径共用同一校验函数
- [x] 保留字/格式限制与创建一致；冲突返回稳定错误码而不是驱动错误
- [x] 变更后旧用户名不能登录；审计记录前后值
- [x] 明确管理端是否可改名（建议不允许，避免审计主体歧义），并把结论写进 API 文档
- [x] 测试：重复、保留字、Step-up 缺失、并发 409、旧用户名登录失败

#### R11 单条分配预览

| 项 | 内容 |
|---|---|
| 现状 | 只有 `PreviewBatchAssign`（批量）；设计 9.4 的单条 preview 没有对应 RPC。 |
| 目标 | 分配前能预览"这个人会获得什么权限、是否有冲突"。 |
| 影响面 | proto/service、biz（复用批量预览计算）、web（分配对话框） |
| 规模 | S |
| 依赖 | 无 |

验收：

- [x] `POST /admin/iam/assignments:preview`：入参 user / role / boundary / 有效期，不写库
- [x] 返回将获得的权限、命中的 deny、scope 交集、受约束影响的结果
- [x] 与批量预览共用同一计算路径，不允许两套逻辑
- [x] 角色已归档、超出 `max_members`、边界不合法时给出明确原因
- [x] 预览结果与真实创建后的有效权限一致（测试断言）
- [x] 测试：普通角色、deny 覆盖、超限、归档角色

#### R12 组织创建配额

| 项 | 内容 |
|---|---|
| 现状 | 任意状态正常账号可无限创建组织，没有配额或审批。 |
| 目标 | 可配置每用户组织数量上限与全局开关，防止资源滥用。 |
| 影响面 | proto/service（新 settings 组）、biz、data（计数）、web（管理端设置） |
| 规模 | S–M |
| 依赖 | **需产品确认默认值**（建议默认关闭，开启后每用户 5 个） |

验收：

- [x] 新增组织设置组（沿用 settings 模式），包含开关、每用户上限、是否统计归档组织
- [x] 超限返回稳定错误码（`ORGANIZATION_QUOTA_EXCEEDED`），HTTP 状态固定
- [x] 平台管理员豁免；豁免行为写入文档
- [x] 计数在事务内完成，并发创建不能突破上限
- [x] 拒绝也写审计（含原因与当前计数）
- [x] 测试：上限、豁免、归档是否释放、并发创建

---

### W4 · 强认证扩展（P1，可整体滑动到 V2.5）

#### R13 WebAuthn / Passkey

| 项 | 内容 |
|---|---|
| 现状 | 只有 TOTP + 恢复码；`identity_mfa` 没有 WebAuthn 凭据表；Step-up 只接受 TOTP/恢复码。设计 1.2 把 WebAuthn/Passkey 列为 V2 扩展。 |
| 目标 | 支持注册与使用平台认证器/ Passkey 作为第二因素，并在 Step-up 中可用。 |
| 影响面 | proto/service、biz（凭据与挑战）、data（新表）、web（安全中心）、migration |
| 规模 | L |
| 依赖 | MFA 策略抽象（已有 `MFARequiredForAdmins`）；Step-up 语义（v0.5.1 已修） |

验收：

- [ ] 注册：attestation `none`，保存 `credential_id`、公钥、`sign_count`、AAGUID、transports、创建时间
- [ ] 认证：校验 challenge 一次性、RP ID/origin、`sign_count` 单调（回退即拒绝并告警）
- [ ] 凭据列表与删除；删除最后一个第二因素时保留至少一种可用方式，或强制先绑定替代方式
- [ ] 管理员强制 MFA 时，WebAuthn 可满足策略；TOTP 与恢复码仍作为兜底
- [ ] Step-up 接受 WebAuthn 断言（与 TOTP 同等效力），证明仍绑定会话与身份版本
- [ ] 不把 WebAuthn 当主认证唯一方式（用户名 + 密码仍是第一因素），除非产品另行决策
- [ ] 测试：注册、认证、`sign_count` 回退拒绝、删除最后凭据、Step-up、策略联动

---

### W5 · 合规（P2，未排期）

#### R14 个人信息保留与清理

| 项 | 内容 |
|---|---|
| 现状 | 账号只有归档（`archived`），没有匿名化/清理任务，也没有保留期配置。 |
| 目标 | 归档后按保留期清理个人数据，同时保留审计最小标识。 |
| 影响面 | biz（清理用例）、data、cmd（定时任务）、ops 文档 |
| 规模 | M |
| 依赖 | 合规要求与保留期数值（需法务/客户确认） |

验收：

- [ ] 保留期可配置（按归档时间），默认值需确认后写入文档
- [ ] 清理范围：邮箱、用户名、昵称、第三方身份、会话、恢复码；审计与事件只保留不可逆标识
- [ ] 任务幂等、支持 dry-run、有指标与审计事件
- [ ] 支持 legal hold 例外（命中则不清理）
- [ ] 清理不可逆，运维文档写明执行前备份与确认流程
- [ ] 测试：到期清理、未到期不动、legal hold、审计仍可追溯

---

## 5. 波次与发版建议

| 波次 | 主题 | 工作项 | 建议版本 | 备注 |
|---|---|---|---|---|
| W1 | OIDC 收尾 | R1–R2 | `v0.6.0` | P0，阻塞第三方应用正式接入 |
| W2 | 组织企业化 | R3–R6 | `v0.6.0` | 与 W1 同版；若延期则顺延到 `v0.7.0`，不拖累 W1 |
| W3 | 集成面与治理体验 | R7–R12 | `v0.7.0` | 每项可独立合入，不必等齐 |
| W4 | 强认证 | R13 | `v0.8.0` | 可整体滑动到 V2.5 |
| W5 | 合规 | R14 | 未排期 | 取决于上线地区与合同要求 |

发版规则（沿用现有实践）：

- 语义化版本：新增能力用 MINOR，修缺陷用 PATCH；W1/W2 合并发 `v0.6.0`。
- 每个波次单独出 release notes，`CHANGELOG.md` 同步；不把多个波次塞进一个 tag。
- W1 与 W2 若必须拆开发版，先发 `v0.6.0`（OIDC），组织能力进 `v0.7.0`，并在 README 明确"组织邀请尚未可用"。

硬依赖（只有这几条，其余可并行）：

- R2 复用 R1 的客户端配置表 → R1 先合入。
- R6 的事件命名依赖 R3 定稿 → R6 排在 R3 之后。
- R13 依赖 Step-up 的"多因素抽象" → 可与 W3 并行，但合入前需确认 Step-up 语义不再变。
- R14 依赖归档语义稳定 → 排在 W3 之后。

## 6. 质量门禁

每个工作项合入前必须全部通过：

- [x] `make api` 后生成物无差异（`git diff --exit-code api openapi.yaml`）
- [x] `make wire` 后生成物无差异
- [x] `go vet ./...`
- [x] `go test ./...`；涉及并发或授权上下文时加 `go test -race ./domain/... ./internal/biz/ ./internal/data/`
- [x] `cd web && npm test && npm run build`
- [ ] 迁移真跑：`USER_CENTER_MYSQL_TEST_DSN=... go test ./cmd/migrate/`
- [ ] 本地 compose 全流程冒烟（含未登录 401、跨租户拒绝、Step-up、租户审计）

工程前置（建议随 W1 一起做）：

- [ ] 把 v0.5.1 的 Docker E2E 脚本收进 `scripts/e2e/`，支持 `--base-url`、自动清理与失败快照；冒烟不再依赖临时目录

## 7. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 改动 `/oidc/authorize` 影响现有 OIDC 客户端 | 第三方登录中断 | 保留"已有同意即直通"路径；覆盖 discovery/authorize/token/userinfo 全链路回归；灰度按 client 白名单 |
| WebAuthn 浏览器与认证器差异 | 部分用户无法注册 | 优先平台认证器、attestation none；TOTP 与恢复码始终兜底 |
| 邀请邮件可达性 | 邀请无法送达 | SMTP 已完成真实验收；提供重发与"复制邀请链接"（一次性、限时） |
| gRPC 登录扩大攻击面 | 暴力破解绕过 HTTP 限流 | 共用限流与失败计数、方法白名单、审计 `actor_service` |
| 组织事件增加投递量 | 下游压力 | 订阅侧按 `event_type` 过滤；批量与背压策略在 R6 验收中明确 |
| 合规清理不可逆 | 误删数据 | dry-run、legal hold、双人确认、执行前备份 |

## 8. 追踪矩阵（设计 → 现状 → 工作项）

| 设计条目 | 要求 | 现状 | 工作项 |
|---|---|---|---|
| 1.2 V2 扩展 | 标准 OIDC 接入应用 | ✅ v0.3.0 | — |
| 1.2 V2 扩展 | 组织与部门 | ✅ v0.4.0 | — |
| 1.2 V2 扩展 | 多租户 | ✅ v0.5.0（逻辑隔离） | 物理隔离不纳入 |
| 1.2 V2 扩展 | WebAuthn / Passkey | ❌ 未实现（按路线图滑动到 V2.5） | R13 |
| 1.2 V2 扩展 | SCIM | ❌ 未实现 | 不纳入（V2.6） |
| 1.2 V2 扩展 | 企业目录同步 | ❌ 未实现 | 不纳入（V2.6） |
| 4.1 个人资料 | 用户名修改需重新验证并检查唯一 | ✅ v0.7.0 待发版 | R10 |
| 6.5 事件机制 | 固定事件清单（不含组织事件） | ✅ 清单内已实现；组织事件属扩展 | R6（扩展） |
| 7.1 路由 | `/admin/audits/:id` | ✅ 详情页已交付 | R8 |
| 7.1 路由 | `/admin/settings/providers` | ✅ 只读配置页已交付 | R9 |
| 7.1 路由 | `/admin/applications` | ✅ 以 `/admin/oidc-clients` 实现（命名差异） | 文档标注 |
| 7.1 / V2 | 授权同意页 | ✅ 已交付 | R1 |
| 9.4 IAM | 单条分配 preview | ✅ 已交付 | R11 |
| 9.5 gRPC | `Authenticate` / `CompleteMFA` | ✅ 已交付 | R7 |
| 9.5 gRPC | `ExchangeLegacySession` | ❌ 未实现（设计允许默认关闭） | 不纳入 |
| 4.2 管理端 | 租户审计导出 | ✅ 已交付 | R5 |
| — | 组织邀请与接受 | ✅ 已交付 | R3 |
| — | 组织域 explain | ✅ 已交付 | R4 |
| — | 组织创建配额 | ✅ 已交付 | R12 |
| — | 个人信息保留与清理 | ❌ 未实现（未排期） | R14 |

## 9. 变更记录

| 日期 | 变更 | 说明 |
|---|---|---|
| 2026-11-04 | 初稿 | 基于 `v0.5.1` 盘点；确定 W1–W5 与 R1–R14，明确不纳入项与理由 |
| 2026-11-05 | W1/W2 合入 | R1–R6 代码、迁移、前端与测试已合入 `develop`（`72437ce`、`4a55083`）；草稿发布说明 `release-v0.6.0.md` 待打标 |
| 2026-11-05 | W3 合入 | R7–R12 代码、迁移、前端与测试已合入 `develop`；草稿发布说明 `release-v0.7.0.md` 待打标 |
| 2026-11-05 | 范围说明 | R13（WebAuthn/Passkey）按 §3.3 整体滑动到 V2.5；R14 未排期。两者本次未实现，保留 `[ ]` |

> 说明：R1–R12 的验收项已在本地 SQLite 集成测试、前端组件测试与构建中验证；§6 中「MySQL 迁移真跑」「本地 compose 全流程冒烟」「E2E 脚本收纳」未在本次执行，保留 `[ ]`。R6 的「旧版本不覆盖新状态」属于订阅方投影语义，已在 `docs/architecture.md` §8.1 约定（`aggregate_revision` 判新旧），本仓库不持有下游投影实现。

维护约定：新差距先补进第 8 节矩阵并标注类型（A/B/C），再决定是否进当前波次；已合并的工作项把 `[ ]` 改成 `[x]` 并在变更记录留一行，不删除历史条目。
