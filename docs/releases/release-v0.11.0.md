# v0.11.0 · 2026-11-09

上一版：[v0.10.1](./release-v0.10.1.md) · 范围：认证与组织权限加固、运维修复、用户手册与操作视频。

**版本判定：MINOR（v0.10.1 → v0.11.0）。** 本次包含上一发布标签之后积累的组织委派能力边界、存量组织 IAM 增量回填及完整文档媒体交付，不能按纯文档 PATCH 发布。包含 **1 个数据库迁移**：`014_password_history_backfill.sql`。没有新增 protobuf RPC；既有授权与凭据检查会更严格。

## 根因与修复

| 问题 | 修复 | 影响面 |
|---|---|---|
| 并发登录分别计数、回收和插入会话；MFA 可能先固定旧快照再取得锁 | 签发入口统一复用事务，首先锁定用户行，随后计算上限并签发；回收事件与返回值统一 | 密码、MFA / Passkey、第三方回调与内部 gRPC 登录 |
| 首次改密与密码过期只在部分协议入口被检查 | 统一凭据限制判定，OIDC 授权与刷新、第三方身份及内部登录共用 | 受限账号必须先完成改密 |
| 旧账号的当前密码不在历史窗口，轮换后可以立刻改回 | `014` 回填历史，轮换事务按需补录旧摘要并维持窗口上限 | MySQL 存量账号、SQLite 升级、策略关闭后重启用 |
| 组织授权只检查操作权限；并发授予不同角色绕过集合约束 | 策略行先加锁，按事务内事实授权，并检查能力、委派、范围、有效期与上限 | 组织角色分配与撤销、职责分离 |
| 过期分配仍被计入冲突；平台账号能跨租户读取约束 | 共用有效分配判定，组织约束使用独立租户治理守卫 | 过期分配不再阻挡新授权，平台身份不能代替组织 owner |
| 成员移除按 JSON 模糊匹配委派目标，并覆盖创建者 | 按 ID 精确比较；仅在管理角色没有有效持有者时失效相应管理委派，保留 `created_by` | 避免用户 ID 前缀混淆与委派残留 |
| 原始协议路由重复限流，指标标签随资源 ID 增长 | 移除重复过滤器，指标与慢日志共用已注册的路由模板 | 单次请求只消耗一次预算，标签基数有界 |
| 数据库仍响应 Ping 时就绪探针误报正常，镜像健康检查仍查存活 | 查询实际业务表，镜像健康检查改用 `/readyz` | schema 或业务表缺失时退出就绪，SQLite 开发库仍可用 |
| E2E 项目名可能继承真实部署；恢复指纹只核对行数 | 每次生成独立项目名，指纹同时核对行数与 `max_id` | 测试清理限定为本次栈，恢复核对覆盖高水位 |

## 手册与操作素材

- [用户手册](../user-guide.md)：账号登录、安全中心、会话、应用授权与组织协作。
- [管理员操作手册](../admin-guide.md)：用户生命周期、角色与授权、职责分离、审计导出、应用和系统设置。
- [视频清单](../videos/README.md)：10 段真实界面字幕录屏、19 张截图、覆盖范围与重新录制步骤。视频与截图随仓库提交；克隆后可在浏览器打开 `docs/videos/index.html`。
- 所有演示使用隔离数据库；二维码、密钥、恢复码均遮挡，并在截图导出前断言遮挡有效。
- 委派、职责分离与认证配置视频仅展示表单，不提交规则或策略；不把它们列作写入验收。

## 兼容性与升级影响

| 项目 | 说明 |
|---|---|
| 数据库 | 必须执行迁移 `014`；仅为没有历史行的凭据补录当前摘要，不改写未知密码年龄，不明文读取密码 |
| 存量组织 | 迁移命令增量补齐内置组织角色所需的约束权限，保留已有额外授权，不重置租户策略 |
| 组织授权 | 只有 `organization.iam.assignment.manage` 不再代表能授予任意角色；能力或有效委派不足时返回 `DELEGATION_REQUIRED` |
| 组织约束 | 平台身份不提供跨租户读取或修改入口；需要组织成员身份，修改规则要求 owner |
| 凭据限制 | 旧接入如果依赖初始密码或过期密码继续刷新令牌、内部登录，升级后会被拒绝，应先改密 |
| 指标与日志 | `route` 按注册模板归一化，未知路径为 `unknown`；依赖旧路径标签的面板和日志检索需核对 |
| 容器健康 | 内置检查从存活改为就绪；数据库未迁移或表缺失时不再显示 healthy |
| HTTP 契约 | 无新增 protobuf RPC；ID、revision 与既有 Cookie / CSRF 协议保持现有约定 |

组织委派的**求值能力已实现，但组织委派 CRUD API 与界面尚未交付**（该缺口在 [v0.12.0](./release-v0.12.0.md) 已补齐）。不要把平台委派界面当作组织委派入口；当前无有效委派时，实际只能授予自己已持有的能力。详见 [安全边界](../security.md)。

## 升级步骤

1. 备份数据库、当前制品与部署清单，确认备份可恢复；保留上一版本镜像标签。
2. 从 `v0.11.0` 源码构建服务与 SPA，或构建对应镜像。`migrate` 与主服务必须使用同一版本；本仓库当前没有镜像自动发布 workflow，GitHub Release 不代表已向镜像仓库推送制品。
3. **先执行迁移，再启动服务**：使用现有部署配置运行 `migrate`，确认迁移 `014` 与组织 IAM 回填成功。SQLite 开发库继续通过现有迁移命令走 AutoMigrate，密码轮换路径提供历史补录。
4. 重启用户中心，先确认 `/readyz` 与 `/healthz`；核对登录、MFA、改密限制、用户列表与组织授权。
5. 在测试账号上核对并发会话上限、过期分配、职责分离、委派不足拒绝及审计记录；核对前端的会话回收与拒绝原因提示。
6. 若更新了容器，确认其内置健康检查使用 `/readyz`；核对指标和慢日志的路由模板标签。

**回滚**：项目不提供 down 迁移。需要完整恢复旧语义时，按 [运维手册](../operations.md) 恢复升级前的数据库、镜像与部署清单；只回退镜像会撤掉本版新增的凭据与授权保护，不能等同于完整回滚。

## 验证与发布门禁

- 本次文档交付已验证：前端构建与 66 个测试、10 段视频完整解码、19 张截图、桌面 / 移动端目录页、链接与锚点、录制脚本自检和敏感字段遮挡断言。
- 录制脚本机器评审覆盖完成，建议已处理；未更改既有业务实现来制作演示。
- 发版前使用候选提交的 `ci` 作为门禁：`backend`、`mysql`、`generated`、`frontend`、`container` 必须全部成功；MySQL job 运行迁移幂等、仓储及 HTTP 并发回归。
- 合入 `main` 后等待该提交的 `ci` 与 `e2e-compose` 成功，再推送发布标签并创建 GitHub Release。最终运行证据以该候选提交的 GitHub Actions 记录为准，不以旧版本绿灯替代。
- 捷径台账：未发现 `shortcut:` 或旧 `ponytail:` 注释。

**验收边界**：本次发布不部署生产环境；真实邮件链路、上游供应商登录、硬件 Passkey 与全站移动端验收不因文档录制而视为完成。手册记录的自助找回密码入口和导出计数显示问题仍未在本批次修复。

## 完整变更日志

以下为 `v0.10.1` 之后本次纳入的非合并提交；发布文档与分支同步提交由 Git 历史补充。

- `3ecf9c9` fix(e2e): generate a fresh compose project name per run
- `7f245d7` feat(obs): classify requests by registered route template
- `621e402` fix(server): raw OIDC and OAuth routes spend the rate budget once
- `77f52ec` fix(dr): fingerprint comparison covers the high-water mark
- `bf95124` fix(auth): every session issuance is one transaction locked on the user row
- `d261627` fix(auth): lock the user row before the MFA transaction reads anything
- `aae8217` fix(security): one credential-restriction gate for every protocol surface
- `224c14e` feat(security): close the password-history gaps a one-shot migration cannot reach
- `4d7e656` fix(iam): an assignment that has ended confers nothing
- `980a506` fix(iam): platform accounts lose the cross-tenant constraint entry point
- `c8d52d5` feat(iam): backfill the V2.5 constraint operations into existing tenants
- `9295b0e` fix(iam): serialize organization grants on the policy row
- `6e7d7d2` fix(authz): organization writes decide on the snapshot they write against
- `5c0a409` feat(org): delegation boundary on assignment writes and exact delegation revocation
- `03913f3` fix(ops): readiness fails when the schema is gone, and the image proves it
- `207372f` test(mysql): run the concurrency-sensitive HTTP paths against real MySQL
- `87c3506` fix(web): surface evicted sessions and the delegation reason on the client
- `56b47cd` docs: add user manuals and operation video guides
