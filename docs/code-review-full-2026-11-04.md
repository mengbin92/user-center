# 用户中心全项目代码审查（2026-11-04）

审查基线：`develop` / `af0ed5a`（v0.5.1 之后）· 审查人：吴八哥（高级开发工程师）
审查范围：全仓库，重点为 V1 平台 IAM、V2 OIDC、V2.3 组织域 IAM 与多租户隔离。

## 0. 结论摘要

| 级别 | 数量 | 说明 |
|---|---|---|
| **P1** | 2 | 一个有探针实证的策略绕过；一个主列表页的查询放大 |
| **P2** | 12 | 一致性、并发、信息泄露、可运维性 |
| **P3** | 8 | 卫生问题与边界优化 |

代码整体质量高于同类项目：分层干净（service 不碰 GORM、biz 不碰 proto）、错误映射统一、CAS 覆盖到位、上下文隔离在 SQL 层强制、OIDC 与导出安全检查扎实。本轮**未发现** SQL 注入、XSS、越权直达（除下述门禁绕过）、密钥泄露或空实现桩。

基线验证（全部通过）：

- `go vet ./...`
- `go test ./...`（domain / biz / data / server 全绿）
- `cd web && npm test`（57 项）与 `npm run build`
- 未发现 `TODO` / `FIXME` / `NotImplemented` 桩

## 1. P1 · 必修

### P1-1 首次改密门禁未覆盖组织路由（已用探针复现）

**证据**：`internal/server/middleware.go:173-178`

```go
func requiresAuth(path string) bool {
	if strings.HasPrefix(path, "/api/v1/me") || strings.HasPrefix(path, "/api/v1/admin") {
		return true
	}
	return false
}
```

同一文件 `:156` 却写了 `/api/v1/orgs`：

```go
if actor.PasswordChangeRequired && (strings.HasPrefix(r.URL.Path, "/api/v1/admin") ||
    strings.HasPrefix(r.URL.Path, "/api/v1/orgs")) {
```

这段判断在 `if requiresAuth(...)` 块内，而 `requiresAuth("/api/v1/orgs")` 恒为 `false`，所以组织路径上的改密门禁**永远不执行**。

**复现**（临时探针，已删除）：管理员创建带初始密码的用户，该用户登录后 `password_change_required=true`，随后

- `GET /api/v1/orgs` → `200 {"items":[]}`
- `POST /api/v1/orgs` → `200`，成功创建组织并成为 owner

**影响**：强制首次改密策略可被绕过；被邀请/新建的账号在改密前即可建立组织、读取组织目录。虽不构成越权到他人数据，但属于策略失效，且组织侧后续会挂邀请、审计导出等更敏感能力。

**修复建议**：把路径判定收敛成一个显式策略，而不是前缀散落判断。

```go
func requiresAuth(path string) bool {
	for _, prefix := range []string{"/api/v1/me", "/api/v1/admin", "/api/v1/orgs"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
```

并把 `:156` 的路径列表改为复用同一份定义，避免再次漂移；补一条「初始密码用户访问 `/orgs` 返回 403 `PASSWORD_CHANGE_REQUIRED`」的回归测试。

### P1-2 用户列表的授权查询放大（N+1）

**证据**：`internal/biz/user.go:505-524`

```go
for _, u := range users {
	d, derr := uc.Decide(ctx, actor, "identity.user.list", u.ID, false)          // 每次全量加载
	...
	roles, _ := uc.Users.RolesForUser(ctx, nil, u.ID)                            // +1
	if state, merr := uc.MFA.Get(ctx, nil, u.ID); merr == nil { ... }            // +1
	if d, derr := uc.Decide(ctx, actor, "identity.user.contact.read", u.ID, false) { ... } // 再来一次
}
```

每次 `Decide` → `LoadAuthzFacts`（`internal/biz/authorizer.go:35-110`）会执行：策略版本、用户版本、**全量角色 + 全部 Grant + 继承边**（`iam_repo.go:205-223`，3 条）、该用户全部授权、全部约束，共 7 条查询。单行约 **16 条查询**，默认 20 行即 **约 320 条**；`page_size=100` 时约 1600 条。用户列表是管理端首屏，这是可观测的性能缺陷。

**影响**：数据库压力随页大小线性放大；角色/约束越多越慢（`loadRoles` 是全表加载，见 P2-11）。

**修复建议**（改动很小，收益最大）：

```go
facts, err := uc.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
if err != nil { return nil, 0, ErrAuthorizationDown }
for _, u := range users {
	d, derr := uc.decideWithFacts(ctx, facts, actor, "identity.user.list", u.ID, false)
	...
	d2, derr := uc.decideWithFacts(ctx, facts, actor, "identity.user.contact.read", u.ID, false)
	...
}
```

再把 `RolesForUser` 与 `MFA.Get` 改成批量查询（`WHERE user_id IN (...)`）即可把 20 行从 ~320 条降到 **约 10 条**（列表 2 + 授权事实 7 + 两个批量 2）。同一模式在导出路径也应复查。

## 2. P2 · 应修

| 编号 | 位置 | 问题 | 建议 |
|---|---|---|---|
| P2-1 | `internal/biz/org_iam.go:383-400` | `PutRoleGrants` 只校验 `Builtin`，未校验 `Status == archived`，归档角色仍可被改权限（`UpdateRole` 已修过同类问题，两处不一致） | 与 `UpdateRole` 对齐：归档角色拒绝写，返回 `VALIDATION_FAILED` |
| P2-2 | `internal/biz/organization.go:398-407`、`:369-378`、`:429-442` | 最后 owner 保护在事务外 `COUNT`，随后才开事务。两个 owner 并发降级/移除时都读到 2，最终可能 0 个 owner | 把计数放进事务并对 owner 行 `SELECT ... FOR UPDATE`；或更新后在同事务内复核计数（需加锁读） |
| P2-3 | `internal/biz/org_iam.go:484-505` | `AssignRole` 的重复授权与 `max_members` 检查在 `Tx.InTx` 之前，并发下可超限或重复 | 检查移入事务，配合 `FOR UPDATE` 锁角色行；或在 `iam_user_roles` 上加「活跃分配」唯一约束（需处理撤销历史） |
| P2-4 | `internal/biz/organization.go:282-293` | 加成员时「账号不存在」返回 `USER_NOT_FOUND`、「账号被禁用」返回 `VALIDATION_FAILED`，租户管理员可借此枚举全平台账号 | 两种失败统一为不可区分的响应（如一律 `VALIDATION_FAILED`「无法添加该账号」）；R3 邀请流程改为按邮箱发送、不回报存在性 |
| P2-5 | `internal/biz/iam.go:1474` + `web/src/features/admin/explain-page.tsx:51,71` | `_ = resourceID`：`resource_id` 被接口接收、前端也在填，但后端完全忽略，解释结果可能误导管理员 | 三选一：实现 owner 服务查询；非空时返回 400「资源级解释需在资源 owner 执行」；或从前端/契约移除该字段。**不要静默忽略** |
| P2-6 | `internal/service/helpers.go:215-220` + 33 处调用 | `reasonOr` 在 `reason` 为空时自动填默认理由，与 `docs/api.md:15`「必须携带非空 reason，不自动填充默认理由」直接冲突；审计里会出现大量模板化理由 | 改为 `requireReason`：空值返回 `VALIDATION_FAILED`。若产品决定允许省略，则反向修订文档与 AGENTS.md，二者只能有一个事实 |
| P2-7 | `internal/data/infra.go:404-448` | `memoryKV` 只在 `get` 时删除过期项；限流键含时间桶（`:203`），旧桶永不再读，因此在未配置 Redis 的单机部署中**持续泄漏内存**（每个 IP/用户每窗口一个键） | 增加后台清扫（如每分钟删除过期项），或写入时顺带清理；限流键可改为固定键 + 滑动窗口计数 |
| P2-8 | `internal/biz/integration_admin.go:47-52`、`:375` | Webhook 回调允许 `http` 且不限制主机，`169.254.169.254`、`127.0.0.1`、内网地址均可作为回调目标（管理员面 SSRF） | 生产强制 `https`；解析后拒绝 loopback/link-local/私网网段；保留 `CheckRedirect` 现状 |
| P2-9 | `internal/biz/integration_admin.go:396-400` | `_ = uc.Dispatch(ctx)` 吞掉错误，Webhook 连续失败无日志、无指标 | 记录 `zap` 错误与连续失败计数，暴露到概览或 metrics；失败超阈值自动降级/告警 |
| P2-10 | `internal/server/grpc.go:45-47` | 拦截器对非 `IntegrationService` 方法直接 `handler(ctx, req)` 放行。当前只注册一个服务所以无影响，但新增服务即静默绕过鉴权 | 改为默认拒绝：只对白名单方法放行，其余返回 `Unauthenticated` |
| P2-11 | `cmd/migrate/main.go:104-120` | 把 SQL 迁移包在 `db.Transaction` 里，但 MySQL DDL 隐式提交，事务对 DDL 无效。006 若在第 2 条语句失败，第 1 条已生效而版本未记录，重跑必失败（需手工修复） | 迁移文件改为「单语句幂等」或按语句记录进度；至少在 006 中先判断列/索引是否存在。当前 001–006 已在 Docker 验证通过，属潜在运维风险 |
| P2-12 | `internal/biz/authorizer.go:84`、`internal/data/iam_repo.go:257-277` | 每次授权决策都全量加载角色与 Grant；`GetRole(id)` 也先加载全表再线性查找。角色数增长后，每个管理请求都付出 O(角色数) 代价 | 以 `policy_revision` 为键做短 TTL 缓存（版本已存在，天然可失效）；`GetRole` 改为按 id 查角色 + 按 role_id 查 Grant/继承 |

## 3. P3 · 建议修

| 编号 | 位置 | 问题 |
|---|---|---|
| P3-1 | `internal/server/http.go:66`、`middleware.go:217`、`wiring.go:216`、`iam_repo.go:191`、`service/helpers.go:224` | `var _ = time.Now` / `_ = publicBase` 等 5 处「保 import」死代码，是重构残留；`publicBase` 实际在 `:89` 已使用 |
| P3-2 | `internal/data/infra.go:197-224` | 固定窗口限流（`Truncate(window)`）在窗口边界允许 2× 突发；登录暴破场景可接受，但需在安全文档注明 |
| P3-3 | `internal/biz/org_iam.go:228-230`、`organization.go:90-92` | 平台管理员提前返回，跳过 `ensureOrganizationIAM`；若回填未执行，平台管理员看到的旧组织角色列表为空，与「首次访问懒回填」的文档描述不符 |
| P3-4 | `internal/server/http.go:228-233` | SPA 回退用 `filepath.Join(dir, clean)` 做存在性探测，未用 `filepath.IsLocal`；`http.FileServer` 自身防穿越，故不可利用，但属卫生问题 |
| P3-5 | `internal/biz/org_iam.go:274-294` | `validateGrants` 不拒绝重复 operation，重复 Grant 会写多行（求值无影响，但审计与展示噪音） |
| P3-6 | `internal/biz/org_iam.go:494-501` | `CountActiveAssignments` 只按 `status='active'` 计数，已过期未撤销的分配仍占用 `max_members` 名额 |
| P3-7 | `web` 构建 | 单 chunk > 500 kB 警告，无代码分割；管理端首屏可考虑路由级 `lazy()` |
| P3-8 | `web/src/lib/http.ts:72-76` | CSRF bootstrap 用 `credentials: 'same-origin'`；若以 `VITE_API_BASE` 指向跨域后端，引导请求不带 Cookie，后续写操作会 403（当前同源部署无影响） |

## 4. 已验证良好的部分

- **分层与依赖方向**：`service` 不触碰 GORM，`biz` 不引用 proto HTTP stub，`data` 只返回 biz 类型；Wire 是唯一装配点。
- **错误映射**：`internal/server/errors.go:13-25` 把未知错误统一收敛为 `DEPENDENCY_UNAVAILABLE`，不泄露 SQL/驱动信息；`CODEC` 错误转校验错误。
- **多租户隔离**：组织仓储的读、写、撤销全部在 SQL 层带 `context_type/context_id`；跨租户 ID 返回 `RESOURCE_NOT_FOUND`；平台查询固定过滤 `platform`（`iam_repo.go:253-260`、`user_repo.go:261-268`）。
- **凭据比较**：OIDC client secret（`biz/oidc.go:602`）与接入客户端凭据（`integration_admin.go:238`）均使用 `subtle.ConstantTimeCompare`。
- **OIDC 授权端点**：先校验 `redirect_uri` 精确匹配再决定是否回跳错误；PKCE 强制 S256；`prompt=none`/`max_age` 处理符合规范；表单 1 MiB 上限、重复参数拒绝、`token` 端点禁止 query 传参（`server/oidc.go:157-191`）。
- **导出安全**：下载前复核 policy/session revision 与有效期（`biz/export_security.go:44-81`）；CSV 公式前缀转义在 `TrimLeft` 后判断，绕过写法也被覆盖（`:83-93`）；下载路径用 `filepath.Base`。
- **密码与会话**：bcrypt 默认成本、72 字节上限；改密同时提升 `identity_version`、撤销其他会话、更新当前会话版本（`biz/user.go:151-173`）；会话校验比对身份版本，失效即撤销。
- **事务与审计**：组织/角色/分配的写操作均把业务写与 `auditOrg` 放在同一事务；`auditOrg` 记录 `organization_id` 与 request id。
- **前端请求层**：CSRF 双提交 + 自动引导、请求代际（`sessionGeneration`）防止登录切换后的陈旧 401、统一错误归一化，没有 `dangerouslySetInnerHTML`。

## 5. 建议修复顺序

1. **P1-1**（一行改动 + 回归测试）立即修，属策略失效。
2. **P1-2**（约 30 行改动）随下一补丁修，管理端体感明显。
3. P2-1 / P2-2 / P2-3 / P2-4 一起做，都是组织域一致性，可共用一组并发与隔离测试。
4. P2-6 / P2-5 属契约事实问题，先定产品口径再动代码。
5. P2-7 / P2-8 / P2-9 / P2-10 / P2-11 归入运维加固批次。
6. P2-12 单独做性能优化，用基准对比（角色 10/100/500）验证，避免凭感觉改。

## 6. 审查方法

- 机器检查：`go vet ./...`、`go test ./...`、`go test -race ./domain/... ./internal/biz/ ./internal/data/ ./internal/server/`、前端 `npm test` + `npm run build`。
- 模式扫描：SQL 拼接、`Updates` 缺 revision、被忽略错误、`panic`、goroutine/ticker 泄漏、`dangerouslySetInnerHTML`、常量时间比较、超时与请求体上限。
- 人工通读：`domain/authorization`、`biz/authorizer.go`、`biz/org_iam.go`、`biz/organization.go`、`data/org_iam_repo.go`、`data/iam_repo.go`、`server/middleware.go`、`server/oidc.go`、`server/grpc.go`、`biz/export_security.go`、`web/src/lib/http.ts`。
- 动态验证：用临时 HTTP 探针复现 P1-1（已删除，未入库）。
