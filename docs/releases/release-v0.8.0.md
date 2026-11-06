# v0.8.0 · 2026-11-06

上一版：[v0.7.1](./release-v0.7.1.md) · 范围：[V2.5 路线图](../roadmap-v2.5.md) W3（S6–S8）+ W5 设计（S12）

**版本判定：MINOR（v0.7.1 → v0.8.0）。** 新增密码策略、会话上限与写接口限流，均为新增能力并带默认值；API 只做增量（settings 四个字段、登录响应一个字段），无破坏性契约变更。有 **1 个数据库迁移**（`012`）和 **3 处默认行为变化**，升级前请读 §升级注意。

主题是**认证与访问加固**。v0.7.x 解决了"看得见、说得清、守得住"，留下的是这个仓库最弱的一环：密码只有长度下限、会话可以无限堆积、`/admin/*` 与 `/orgs/*` 的写接口完全没有限流。这一版补上这三块，并把 V2.4 欠下的组织治理设计债交出来评审。

## Added

### 密码策略（S6）

- 策略项进 `settings.auth`：`password_min_classes`（0-4，默认 3）、`password_history_count`（0-20，默认 5）、`password_expiry_days`（0-3650，默认 0 即不过期）。
- 迁移 `012`：新增 `password_history`（**只存 bcrypt 摘要**，每次写入折叠到策略窗口，行数上界为 `用户数 × 历史条数`）与 `user_credentials.password_changed_at`。
- 四处入口共用同一 `ValidatePassword(pw, PasswordPolicy)`：注册、自助改密、验证码重置、管理员设初始密码。
- 违反策略返回稳定错误码 `PASSWORD_POLICY_VIOLATION` 并带可读原因（例如"需至少包含 3 类字符…当前只有 2 类"）。
- `GET /api/v1/auth/context` 新增 `password_min_classes`，注册/重置/改密/建号四张表单在提交前就能提示规则；管理端「认证配置」页新增四项设置。

### 会话与设备治理（S7）

- `max_sessions_per_user`（默认 10，0 表示不限制）。超限时按**最久未活跃**回收，撤销是服务端写 `revoked_at`，被回收设备下一次请求得到 401。
- 登录响应新增 `recycled_sessions`，前端以 toast 提示「已退出 N 个最久未使用的会话」，避免用户在其他设备上莫名被登出。
- `POST /api/v1/me/sessions:revoke-others` 补写安全事件 `session_revoke_others`（即使没有其他会话也记录）。

### 写接口限流（S8）

- 统一中间件：按「主体（user id / 接入 client id / 匿名才退回 IP）+ 路由类」计数，**只对非安全方法生效**，读接口永不被限。
- 默认额度：普通写 120 次/分钟；导出（`/admin/users:export`、`/admin/audits:export`、`/orgs/{id}/audits:export`）、批量分配（`:batch-assign` / `:batch-preview`）、邀请（`/invitations`）10 次/分钟。
- 超限返回 `429` + `Retry-After`（窗口剩余秒数，1–60）+ 稳定错误码 `RATE_LIMITED`。
- 新指标 `usercenter_rate_limit_hits_total{scope}`（`write` / `export` / `batch` / `invite`）。
- 配置：`RATE_LIMIT_ENABLED`（默认开启）、`RATE_LIMIT_WRITE_PER_MINUTE`、`RATE_LIMIT_HEAVY_PER_MINUTE`。

### 组织治理设计（S12，设计阶段）

- `docs/design/org-sod-delegation.md`：作用域模型（约束/委派复用 `(context_type, context_id)`）、与平台约束的**交集合并**规则、6 步冲突判定顺序、跨租户 404 边界、迁移 `013` 方案、3×9 决策矩阵。
- **本版不含实现代码**。按路线图「设计先行」约定，评审通过后才展开。

## Changed

- **密码复杂度默认开启**：新设密码需满足 4 类字符中的 3 类。这是 [路线图 W3](../roadmap-v2.5.md) 与决策 D2 的差异点，已在路线图注明。存量账号不受影响——策略只在"设置密码"时执行，登录不校验强度。
- 会话上限默认 10；此前无上限。
- 写接口默认限流。此前只有登录/注册/MFA/重置四条路径有独立计数器。

## Fixed

- **root 首次改密可以改回引导密码**：`password_history` 在引导时为空，而"不能与当前密码相同"只覆盖上一个值。现在 bootstrap 与 admin-rescue 都会把初始密码播种进历史。
- 组织 `AssignRole` 既不校验 `CheckConstraints` 也不校验 `checkDelegation`，平台 SoD 在组织域可被绕过。**本版只记录为已知限制**（`docs/security.md` §4 第 10 条），修复随 S12 实现。

## 升级注意

1. **必须执行迁移**：`012_password_policy.sql` 增加 `password_history` 表与 `user_credentials.password_changed_at` 列。compose 部署走 `migrate` 一次性服务，正常 `up -d` 即已应用；手工部署需先跑 `migrate`。
2. **回滚代价**：删掉两列即可回到旧 schema，但组织/用户的历史密码记录会一并丢失（平台策略不受影响）。迁移本身不可逆，回滚前先备份。
3. **有效期保持关闭**，不要在不了解后果时开启：存量账号 `password_changed_at` 为 `NULL`，语义是"年龄未知"，永不判定过期；开启后只对发版之后改过密码的账号生效。
4. **会话上限会立即生效**：发版后第一个超过 10 个会话的登录会回收最久未活跃的那些。对使用多个设备的用户是可见变化（前端会提示）。
5. **限流默认开启**：如果前面已有网关级限流，或客户端有高频写脚本，先把 `RATE_LIMIT_WRITE_PER_MINUTE` 调高或 `RATE_LIMIT_ENABLED=false`，再逐步收紧。多实例且未配 Redis 时，实际额度是「配置值 × 实例数」。

## 验证

| 项 | 结果 |
|---|---|
| `go test ./...` | 8 个包全绿（新增 20 个用例，覆盖密码策略、会话回收顺序、越权撤销、限流并发与窗口） |
| `gofmt` / `go vet` / `scripts/gen-check.sh` | 干净，无生成物漂移 |
| 前端 | `npm test` 17 文件 / 62 用例通过；`npm run build` 通过 |
| 本地 compose 全栈 E2E | `E2E OK`（health、401 门禁、登录、自助、V2.4 发现、Step-up、租户边界、审计、登出）；落库证据 organizations=1 / audit_events=2 / outbox_events=2 / sessions=1；`schema_migrations_applied 61`（含 `012`）；容器日志 0 条 5xx |
| 指标端点 | 从宿主机抓取到 `db_pool_connections{state="max"} 20`、`dependency_up{mysql}=1` |

## 已知限制

- 组织域仍无 SoD 与委派（见上）；设计文档待评审。
- 密码强度无法在登录时校验（不持有明文），存量弱密码只能靠有效期推动轮换。
- 限流后端故障时 fail-open；无 Redis 时额度按实例计算。
- 字符类规则对纯中文口令只贡献长度，不贡献"类"——这是有意为之，不是遗漏。

## 下一版

W6 运维就绪（S13 备份恢复/升级回滚演练、S14 真实 OAuth 沙箱验收）与 S12 实现（评审通过后）。S14 依赖真实凭据与 HTTPS 回调域名，无凭据时按约定如实标 N/A。
