# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.12.0] - 2026-11-09

**版本判定：MINOR（v0.11.0 → v0.12.0）。** V2.6 四项能力按阶段独立提交并统一发版；新增 14 个 RPC、9 条 SCIM 原始路由、2 个迁移（`015`、`016`）与相应界面。租户物理隔离默认关闭，阶段④的存量 cutover 未完成，未完成项以 `[ ]` 列在 `docs/tenancy.md` §4。详见 [发布说明](docs/releases/release-v0.12.0.md)。

### 阶段① — 组织级 SoD 补齐（组织委派 CRUD 与界面）

- 新增 4 个组织委派端点：`GET/POST /api/v1/orgs/{id}/iam/delegations`、`PATCH .../delegations/{delegation_id}`、`POST .../delegations/{delegation_id}:revoke`。此前求值侧 `checkOrgDelegation` 的委派分支在生产不可达（没有写入口），现在可由 owner 通过 HTTP 创建并撤销。
- 写入侧强制治理权限（读 owner+admin、写仅 owner）、Step-up、`reason`、`expected_revision` 与 `expected_policy_revision` 两道 CAS、组织审计、Outbox 事件与 policy revision bump；管理/目标角色必须同属本组织且 active，授权上限不得超过创建者在本组织持有的能力。
- 仓储写入增加 `context_type/context_id` 谓词作为纵深防御；跨租户 id 一律 404，平台委派不进入组织列表。
- 前端「职责分离」页新增委派列表、创建/编辑/撤销对话框；授权上限由目标角色的 grants 自动快照，避免手写出永不可用的委派；目标用户范围可选「全部成员」或「指定成员」，失败原因在对话框内展示。组件测试覆盖列表、创建（含 ceiling 与 user_ids 断言）与撤销。
- HTTP 级测试：创建后解锁分配、撤销后重新拒绝；并覆盖缺少 `reason`、平台角色/跨租户角色引用、越权 ceiling、策略版本冲突、非 owner 写入、非成员读取、跨租户更新/撤销、revision CAS 等拒绝用例。
- 文档状态回填：`README.md`、`docs/api.md`、`docs/security.md` §4.10、`docs/roadmap-v2.5.md`、设计文档 §12/§14（含实现期修正 F10）。

### 阶段② — SCIM 2.0 用户与组供给

- 新增 `/scim/v2/{ServiceProviderConfig,ResourceTypes,Schemas,Users,Groups}` 协议面：SCIM schema、ListResponse 分页、闭合 filter 语法、PATCH、ETag/`If-Match`、标准 Error 消息与 `scimType`。原始路由位于 `/api/v1/` 之外，不受浏览器 CSRF 约束，但每个请求都由处理器自行做 Bearer 鉴权。
- 新增 4 个平台管理端点签发/列出/轮换/停用 SCIM 凭据；凭据**绑定唯一组织**，只存 SHA-256 摘要、明文只返回一次，停用立即生效。管理写入要求平台管理员 + Step-up + `reason` + `expected_revision` + 平台审计。
- 迁移 `015`：`scim_tokens`、`scim_identities`、`scim_groups`、`scim_group_members`（SQLite 同步纳入 `AutoMigrate`）。**升级须先执行迁移 015 再启动服务。**
- 供给写路径：`externalId` 权威匹配、跨租户邮箱拒绝（409）、`active=false` 只停用本组织成员资格并撤销其角色/委派、`DELETE` 保留全局账号与审计、组成员只允许本组织已供给用户；全部写组织审计。
- 前端组织设置页新增平台管理员可见的凭据管理（签发/轮换/停用 + 一次性展示）。
- HTTP 级测试 4 组：发现与鉴权、供给生命周期、租户边界与组成员、凭据治理拒绝；覆盖无/错/停用 token、缺 schemas、非法 filter/path、跨租户 id、跨租户邮箱绑定、组成员越权、`If-Match` 412、唯一性冲突、非平台管理员签发、凭据不回显。
- 新增 `docs/scim.md`（含明确不支持的子集与已知限制），回填 `README.md`、`docs/api.md`、`docs/security.md`、`docs/data-model.md`、两份路线图的追踪状态。

### 阶段③ — 企业目录同步

- 新增两类连接器：`ldap`（go-ldap，Simple Bind、分页搜索、`whenChanged>=cursor` 增量、`userAccountControl` 判定停用、属性映射可配）与 `jsonfeed`（HTTP JSON 网关，`since` 游标、显式 `deleted` 与 `full` 标记）。连接器实现统一 `Fetch` 接口，新增源不改引擎。
- 外部凭据按 `docs/api.md` 原有前置落地加密入库（`SecretBox`/AES-GCM）、只写不读、轮换（`expected_revision` + `reason` + Step-up）与平台审计；明文协议仅允许回环地址并禁用重定向（SSRF 防护）。
- 同步引擎：独立 30s worker 按 `interval_seconds` 调度、`full` / `delta` / `dry_run` 三种模式、增量游标、`directory_objects` 映射、tombstone 对账（`disable` / `delete` / `keep`）、`source_wins` / `local_wins` 冲突策略、逐对象报告与 `partial` 状态；`dry_run` 不写入也不推进游标。供给复用 SCIM 路径，不存在第二套账号创建逻辑。
- 迁移 `016`：`directory_sources`、`directory_sync_runs`、`directory_objects`（SQLite 同步纳入 `AutoMigrate`）。**升级须先执行迁移 016 再启动服务。**
- 新增 6 个平台管理端点与组织设置页（仅平台管理员可见）；全部写操作要求平台管理员 + Step-up + `reason`。
- HTTP 级测试 2 组：供给/对账生命周期（dry-run、全量、增量停用、全量 tombstone、运行记录留存）与治理拒绝（缺 reason、明文非回环 URL、未知连接器、非法 config、非平台账号读写、凭据不回显、过期 revision）。
- 新增 `docs/directory-sync.md`（含未实现项：组/部门层级同步、非 AD LDAP 增量、原生 Entra/飞书连接器、多实例分布式租约、写回），回填 README、API/安全/数据模型文档与两份路线图。

### 阶段④ — 租户物理隔离（独立 schema 基础设施）

**状态：基础设施与租户数据域已交付，存量数据 cutover 未完成**（未完成项以 `[ ]` 列在 `docs/tenancy.md` §4）。

- 配置：`conf.Data.Tenancy`（`schema_isolation` / `schema_prefix` / 连接池上限）与 `TENANT_SCHEMA_ISOLATION` / `TENANT_SCHEMA_PREFIX` 环境变量。**默认关闭**，关闭时所有请求仍走平台连接池，存量行为与既有测试不变。
- 路由：`platform/tenant` 从组织 URL 与 SCIM bearer token 解析组织 id 注入 context；`Data.TenantDB(ctx)` 懒加载并缓存每组织独立 `*gorm.DB` + `*sql.DB`；租户库不可用时 fail-closed，**不回退平台库**。
- 编排：`cmd/tenant-schema -org / -all / -list` 幂等建库并建表（静态 SQL 迁移无法表达每组织一套 schema）。启用顺序：先迁移 → 再建租户 schema → 最后开开关。
- 分域：`scim_identities` / `scim_groups` / `scim_group_members` / `directory_objects` / `directory_sync_runs` 落到各自组织 schema；治理元数据 `scim_tokens` / `directory_sources` 留在平台 schema。隔离关闭时 `tenantOr` 沿用事务连接，避免单连接池下第二个连接互锁（本次全量门禁发现并修复）。
- 测试：`internal/data/tenancy_test.go`（不同连接池、跨 schema 不可见、同 externalId 跨租户可共存、平台库无租户行、默认关闭、非法 id）与 `internal/server/tenancy_test.go`（HTTP 级：A 的 token 读 B 的用户 404、列表只含本租户、平台库无租户映射）。
- 新增 `docs/tenancy.md`；回填 `README.md`、`docs/api.md`、`docs/security.md` §4.5、`docs/data-model.md`、`docs/operations.md` 与两份路线图的追踪状态。
- **未完成 `[ ]`**：存量组织/角色/委派/约束/审计表 cutover、全局账号与登录链路物理隔离、平台跨租户治理聚合、新建组织自动建库、多实例建库租约、跨库事务补偿、DR/备份脚本多 schema 改造、MySQL 运行账号权限模型重定。

## [0.11.0] - 2026-11-09

**版本判定：MINOR**（v0.10.1 → v0.11.0）。新增组织授权的委派能力边界、存量组织权限回填，以及用户手册、管理员手册和操作视频；统一凭据限制并加固并发会话与组织授权。包含 **1 个数据库迁移**（`014_password_history_backfill.sql`），升级须先迁移再启动服务。详见 [发布说明](docs/releases/release-v0.11.0.md)。

### Added

- 组织角色分配与撤销执行目标角色、用户范围、动作、有效期及授权上限的委派边界；存量组织内置角色增量补齐职责分离权限。组织委派 CRUD API 与界面仍未交付，不将求值能力表述为完整委派产品入口。（该缺口已在 v0.12.0 补齐，见上方。）
- 迁移 `014` 回填旧账号当前密码摘要；密码轮换事务补录未进入历史窗口的旧摘要，覆盖 SQLite 升级和关闭后重新开启历史策略的账号。
- 用户手册、管理员操作手册、10 段脱敏字幕录屏、19 张截图、本地视频目录与可复现录制脚本；README 提供视频直链，媒体随仓库提交。
- MySQL HTTP 并发回归纳入 CI，覆盖并发会话、组织授权、约束与租户边界。

### Changed

- 密码登录、MFA / Passkey、第三方身份回调及内部 gRPC 的会话签发统一为按用户行锁串行化的事务；并发回收与事件记录不再因入口不同而漂移。
- OIDC、第三方登录与内部 gRPC 统一检查初始密码和密码过期限制；受限凭据须先完成改密。
- 指标与慢请求日志共用已注册路由模板，限制方法与路由标签基数；未注册路径归为 `unknown`。
- 容器内置健康检查改用 `/readyz`；就绪检查查询实际业务表，MySQL schema 或哨兵表缺失时失败，兼容已迁移 SQLite。

### Fixed

- 并发签发会话时超出账号上限，以及 MFA 在取得行锁前已固定旧快照的问题。
- 过期角色分配仍参与职责分离、组织授权判断的问题；组织写入现在按策略锁后的事务内事实重新授权，串行化授权与约束变更。
- 平台账号跨租户读取组织职责分离规则的入口；组织约束端点执行独立的租户成员与 owner 权限检查。
- 成员移除时用 JSON `LIKE` 混淆用户 ID、误撤销其他成员委派、覆盖 `created_by` 的问题；按用户 ID 精确匹配并保留创建者。
- 原始 OIDC / OAuth 路由重复经过写限流，单次请求消耗两次预算的问题。
- 恢复指纹只比较行数遗漏 `max_id` 高水位，以及 E2E 继承部署项目名后可能清理其他栈数据卷的问题。
- 登录页补齐其他设备会话被回收的提示；组织职责分离页面展示具体委派拒绝原因。

## [0.10.1] - 2026-11-07

**版本判定：PATCH**（v0.10.0 → v0.10.1）。修复限流命中计数器冷启动无时间序列的可观测性缺陷，并修正运维文档表述。无新增端点、无行为变更、无迁移。详见 [发布说明](docs/releases/release-v0.10.1.md)。

### Fixed

- `usercenter_rate_limit_hits_total` 在从未拒绝过请求的进程里**完全没有时间序列**（Prometheus `CounterVec` 只在 `WithLabelValues` 后物化），导致 `rate()`/`increase()` 拿到空向量、`absent()` 对健康实例误报。现由 `NewMetrics` 对 4 个 scope 以 `Add(0)` 预置。
- scope 名称提取为 `internal/obs` 导出常量，`internal/server/ratelimit.go` 改为引用，消除预初始化列表与写入方漂移的可能。
- `docs/operations.md` §5.1.1 原文「看到指标突然为 0 要怀疑限流器」描述的是不可能发生的观察；改为准确表述，给出基于 `increase()` 的告警表达式，并明确不要用 `absent()`。指标表补注零值预置。
- `scripts/e2e/README.md` 补充「`compose-e2e.sh` 与 `--keep` 栈共用默认项目名导致 migrate 密码不匹配」的排障说明。

### 未新增

- `alerts.yml` 未加限流告警规则：拒绝率阈值缺生产基线，凭空加 page 告警只会制造噪音。

## [0.10.0] - 2026-11-07

**版本判定：MINOR**（v0.9.0 → v0.10.0）。运维就绪：新增对外端点 `/readyz`、变更容器 healthcheck 与数据库探针语义、新增两个可复现的灾难恢复演练脚本。修复"数据库不可用时容器仍报 healthy"的真实缺陷。**无数据库迁移**。详见 [发布说明](docs/releases/release-v0.10.0.md)。

### Added

- `GET /readyz`：MySQL 必需（不可达返回 503 并附错误），Redis 仅报告；`GET /healthz` 保持纯存活探针。
- compose healthcheck 改指 `/readyz` 并加 `start_period`；镜像名参数化为 `${USER_CENTER_IMAGE:-user-center:latest}`，回退无需改清单。
- `scripts/dr/`：`restore-drill.sh`（备份→清库→恢复→冒烟）、`upgrade-rollback-drill.sh`（v0.6.1→当前→回滚）、`compare_fingerprint.py`、`lib.sh`。
- `scripts/e2e/smoke.sh` 默认断言 `/readyz`；新增 `--skip-readyz` 供旧版本演练使用。
- `docs/operations.md` §5/§7/§10 与 [S13 演练记录](docs/releases/drill-2026-11-07-s13.md)；`configs/config.docker.yaml` 补 OAuth 环境变量与 HTTPS 回调说明。
- 新增测试 6 条：`internal/obs/ready_test.go`、`internal/server/probe_test.go`。

### Changed

- `Data.PingDatabase` 从 `PingContext`（`COM_PING`，空库也返回成功）改为真实查询 `schema_migrations`；`usercenter_dependency_up` 指标随之变准。
- 演练就绪轮询改为校验响应体；S13 之前的版本改用 `wait_legacy_ready`（healthz + 真实 SQL）。
- 路线图 W6 波次行、D3/D4 决策状态、W5 版本行回填，删除过时的"W3 可降 v0.7.1"假设。

### Fixed

- `DROP DATABASE` 后容器仍报 healthy：`/healthz` 是静态 200 却被当作健康判断。
- 初版 `/readyz` 假绿（依赖 `COM_PING`）、旧版 SPA fallback 假绿（未知路径返回 200 + HTML）。
- 演练脚本自身两处口径错误：升级后误用"完全相等"比对、fingerprint 漏表。

### 演练结论（详见运维手册）

- 恢复会带回会话（session 在 MySQL，含之后被撤销的），Redis 不备份且自然重建；安全事件回滚后必须显式撤销会话。
- 只回退镜像不恢复库会静默丢数据：改密码返回 200 却不写 `password_history`、不更新 `password_changed_at`。唯一安全路径是旧镜像 + 恢复备份库 + 清单一并回退。
- 项目不提供 down 迁移；不可逆 DDL 由演练脚本从迁移文件自动扫描（当前 1 处）。

### 未执行

- **S14 真实 OAuth 沙箱验收：N/A**。决策 D4 未提供凭据与 HTTPS 回调域名，四项验收保留未勾选，未创建虚构的验收记录。

## [0.9.0] - 2026-11-07

**版本判定：MINOR**（v0.8.0 → v0.9.0）。组织域职责分离与委派：新增 4 个 API、2 个权限码、1 个前端 tab、迁移 `013`。修复"组织分配绕过平台 SoD"的安全缺口。详见 [发布说明](docs/releases/release-v0.9.0.md)。

### Added

- 组织约束 CRUD（`mutual_exclusion` / `max_roles`）：`/api/v1/orgs/{id}/iam/constraints`。
- 迁移 `013`：`iam_role_constraints` 与 `iam_delegations` 增加 `(context_type, context_id)`，`DEFAULT` 即回填存量行。
- 权限码 `organization.iam.constraint.read`（owner+admin）与 `.manage`（仅 owner）。
- 收紧约束需显式确认：返回 `violating_assignments`，未确认时返回 `ORGANIZATION_POLICY_VIOLATIONS_PENDING`。
- 委派上下文隔离：`DelegationFilter.Context`；平台委派不能批准组织分配，反之亦然。
- 前端组织详情页「职责分离」tab。

### Changed

- 组织分配现在执行约束校验（此前完全没有），行为只会变严。
- 组织成员不能给自己授权（`ORGANIZATION_SELF_GRANT`）。

### Fixed

- 组织 `AssignRole` 既不校验 `CheckConstraints` 也不校验 `checkDelegation`，平台 SoD 在租户内被绕过。
- 移除组织成员时未失效其委派，被移除者仍可能通过残留委派获得角色；现双向软失效。

## [0.8.0] - 2026-11-06

**版本判定：MINOR**（v0.7.1 → v0.8.0）。认证与访问加固：密码策略、会话上限、写接口限流。新增 1 个迁移（`012`）与 3 处默认行为变化。详见 [发布说明](docs/releases/release-v0.8.0.md)。

### Added

- 密码策略可配：`password_min_classes`（默认 3）、`password_history_count`（默认 5）、`password_expiry_days`（默认 0 即不过期）；四处入口共用同一校验函数。
- 迁移 `012`：`password_history`（只存 bcrypt 摘要，写入时折叠到策略窗口）与 `user_credentials.password_changed_at`。
- 稳定错误码 `PASSWORD_POLICY_VIOLATION`；`/api/v1/auth/context` 返回 `password_min_classes`，前端四张表单在提交前提示规则。
- 每用户并发会话上限 `max_sessions_per_user`（默认 10），超限按最久未活跃回收；登录响应返回 `recycled_sessions` 并前端提示。
- 统一写接口限流：按「主体 + 路由类」计数，普通写 120 次/分钟，导出/批量/邀请 10 次/分钟；429 + `Retry-After` + `RATE_LIMITED`；新指标 `usercenter_rate_limit_hits_total{scope}`；`RATE_LIMIT_*` 可配。
- `docs/design/org-sod-delegation.md`：组织 SoD 与委派设计（**仅设计，未实现**，待评审）。

### Changed

- 密码复杂度默认开启（新设密码需 3 类字符）；存量账号不受影响，登录不校验强度。
- 会话默认上限 10（此前无上限）。
- 写接口默认限流（此前仅认证路径有独立计数器）。
- `POST /me/sessions:revoke-others` 现写安全事件 `session_revoke_others`。

### Fixed

- root 首次改密无法被历史拦截（`password_history` 在引导时为空）：bootstrap 与 admin-rescue 现在会播种初始密码。
- 记录已知限制：组织 `AssignRole` 不校验约束与委派，平台 SoD 在组织域可绕过（修复随 S12 实现）。

## [0.7.1] - 2026-11-06

**版本判定：PATCH**（v0.7.0 → v0.7.1）。仅修复 CI 与 E2E 脚本；无代码、API、迁移变更。详见 [发布说明](docs/releases/release-v0.7.1.md)。

### Fixed

- compose E2E 在 Linux 上启动失败：OIDC 私钥以 `0600` 生成，容器以非 root 用户运行导致 `permission denied`；改为 `0700` 目录内 `0444` 文件（macOS Docker Desktop 放宽挂载权限，故本地无法复现）。
- 镜像陈旧判定误报：Docker 缓存完全命中时 `Created` 时间不变，正确的构造被判为陈旧；该判断还依赖 GNU `date -d`，在 macOS 上静默失效。现在只保留 `PIPESTATUS` 真实退出码这道门，并记录镜像 ID。
- 失败产物上传整个快照目录（含会话 Cookie）；改为只上传诊断文件。
- `buf-setup-action` 未传 token 触发匿名限流警告。
- 健康门禁失败时不打印服务日志，只显示 `Restarting (1)`。

## [0.7.0] - 2026-11-06

**版本判定：MINOR**（v0.6.1 → v0.7.0）。生产化基座：可观测性、负载基线与工程门禁。无迁移、无破坏性契约变更。详见 [发布说明](docs/releases/release-v0.7.0.md)。

### Added

- Prometheus 指标端点（独立监听，默认 `127.0.0.1:9091`，`METRICS_ADDR=off` 关闭）：HTTP 请求数与延迟直方图（`route` 为模板）、Outbox 投递按状态、迁移步数、依赖连通性、DB 连接池占用与排队。
- `deployments/prometheus/alerts.yml`：7 条告警规则（5xx 比例、P95 延迟、登录失败激增、Outbox 积压、依赖不可用、连接池耗尽、迁移未应用），`promtool check rules` 通过；运维手册新增 §5.2 SLO 与告警。
- 慢请求日志（`SLOW_REQUEST_THRESHOLD_MS`，默认 500ms），字段为 `request_id` / 路由模板 / 方法 / 状态 / 耗时，不含 body、header、query 与 Cookie；字段集由测试白名单锁定。
- gRPC unary interceptor 注入 `request_id` 并通过响应头回写；此前内部 API 写入的审计行该字段为空。
- `scripts/bench/`：可复现的 MySQL 8.4 负载基线（5 个 k6 场景 + 会话池 + 结果表）与 `explain.sql` 索引审计夹具；`docs/performance.md` 记录环境、基线、梯度与偏差。
- CI `mysql` job（MySQL 8.4 service 上验迁移幂等与 MySQL 仓储测试）、`generated` job（生成物漂移即失败）、`e2e-compose` workflow（main 分支与手动触发的全栈冒烟）。

### Changed

- 邮件日志把收件人掩码为 `a***@example.com`，含 CR/LF 的地址直接拒绝。
- compose 默认 `METRICS_ADDR=0.0.0.0:9091` 并把端口发布在宿主机回环。

### Performance

- 修复权限决策的重复查询：单次 `GET /api/v1/admin/users?page_size=20` 的 prepared statement 从 92 条降到 20 条 SELECT；`admin` 场景 16 VUs 从 176 QPS / P95 111 ms 提升到 622 QPS / P95 31 ms。
- 授权快照增加每请求的操作定义缓存，列表过滤器复用同一份快照；快照仍为每请求，policy revision 语义不变。

### Notes

- 依赖：`github.com/prometheus/client_golang v1.25.0`，它要求 `golang.org/x/oauth2 v0.37.0`（MVS 无法保留 v0.36.0）。
- v0.6.0 的 W3 波次附记从 `releases/release-v0.7.0.md` 更名为 `releases/release-v0.6.0-w3.md`，避免与真实版本号冲突。
- 索引审计结论：无缺失索引，故无 `012` 迁移；关键字搜索全表扫、受限 scope 分页 filesort、组织成员列表无分页作为已知限制记录。
- 大表（会话/审计/Outbox/投递）仍无定期清理，保留期与删除流程待合规确认。

## [0.6.1] - 2026-11-05

**版本判定：PATCH**（v0.6.0 → v0.6.1）。第二轮完整 code review 修复，无新增能力、无迁移、无破坏性契约变更。共修复 1 个 P1、6 个 P2、9 个 P3，详见 [发布说明](docs/releases/release-v0.6.1.md)。

### Fixed

- **P1 组织提权**：持有 `organization.member.manage` 的非管理员自定义角色不能再授予/修改 `admin`，也不能邀请 `admin`；只有 platform/owner/admin 可授予 admin，只有 platform/owner 可修改现有 admin。
- **P2 邀请竞态**：重新邀请撤销旧 pending 时递增 `revision`，接受/撤销 CAS 增加 `status='pending'`，在途令牌无法覆盖已撤销记录。
- **P2 登出会话残留**：RP-initiated logout 的回跳被拒绝时仍先撤销本地会话、Step-up 并清 Cookie；`client_id` 与 hint `aud` 不一致返回 400。
- **P2 邀请列表 PII**：列表要求 `organization.member.manage`，不再向普通成员暴露被邀请人邮箱；前端邀请 Tab 仅对 owner/admin/platform 展示。
- **P2 OIDC 应用白名单**：编辑应用时提交 `post_logout_redirect_uris`，避免未携带字段导致已登记白名单被清空。
- **P2 并发改用户名**：唯一索引冲突映射为 `USERNAME_EXISTS`（409）。
- **P2 consent revision**：`UpsertConsent` 正确递增 `revision` 并更新 scopes。
- **P3**：会话校验依赖故障时全路径 503 fail-closed；组织事件补齐 `role_code`/`user_id`/`role_id`；租户审计导出写入租户审计流；归档部门不可用于成员/邀请/部门树；部门环检测覆盖完整祖先链；重发邀请先撤销旧记录再查配额；重复撤销返回 `INVITATION_REVOKED`。

### Tests

- 新增 HTTP 级拒绝测试：自定义 `member.manage` 角色自升/降级/添加/邀请 admin 均 403；普通成员读取邀请列表 403；非法登出回跳后会话失效且 Cookie 清除。
- 新增仓库测试：撤销邀请递增 revision 且旧快照 CAS 失败；consent upsert revision 递增；事务回滚不留下 Outbox 事件。

## [0.6.0] - 2026-11-05

**版本判定：MINOR**（v0.5.2 → v0.6.0）。V2.4 R1–R14、code review 修复与工程前置一次性连续交付；分波次 tag 会让 v0.6.0/v0.7.0 缺少后续 P1 安全修复，故统一发版，决策已同步至 [路线图 §5](docs/roadmap-v2.4.md) 与 [发布说明](docs/releases/release-v0.6.0.md)。

### Added (W1/W2)

- OIDC 交互式授权同意页：一次性服务端 handle、按 client+user 持久化已授予 scope、scope 扩张与 `prompt=consent` 重新征询、`prompt=none` 返回 `interaction_required`、`/me/oidc-consents` 列出与撤销。
- RP-initiated logout：discovery `end_session_endpoint`、`/oidc/logout`、客户端 `post_logout_redirect_uris` 精确白名单、会话撤销与 Cookie 清理、幂等重复调用。
- 组织邀请与接受：令牌哈希存储、邮件投递、邮箱匹配、过期/撤销/重复接受/上限/跨租户拒绝、接受后同步内置角色授权、审计事件。
- 组织域授权解释 `GET /orgs/{id}/iam/authorization:explain`，复用同一 `authorization.Evaluate` 路径。
- 租户审计导出 `POST /orgs/{id}/audits:export` + 租户下载通道，复用平台 CSV/签名与版本校验。
- 组织域事件进 Outbox（成员/部门/角色/分配/归档，最小无 PII 载荷），文档新增事件表。

### Added (W3)

- 内部 gRPC `Authenticate` / `CompleteMFA`，复用 HTTP 登录限流与失败计数、会话绑定应用、审计 `actor_service_id`。
- 审计详情页 `/admin/audits/:id`（before/after/diff 折叠、返回保留筛选）、身份提供方配置页 `/admin/settings/providers`、组织策略页 `/admin/settings/organization`。
- 用户名自助修改（Step-up + 当前密码 + revision CAS，管理端不可改）、单条分配预览、组织创建配额。

### Added (W4/W5)

- WebAuthn/Passkey 第二因素（R13）：attestation none、真实 COSE/ES256 验签、RP ID/origin 校验、sign_count 回退拒绝、Step-up 与登录 MFA、管理员策略联动、最后第二因素保护。
- 个人信息保留与清理（R14）：`cmd/retention`、365 天可配保留期、dry-run/双人确认、legal hold、幂等匿名化、最小审计标识。
- E2E 冒烟脚本正式收纳到 `scripts/e2e/smoke.sh`（`--base-url`、自动清理、失败快照）。
- 迁移 `010_webauthn.sql`、`011_retention.sql`；新增 `github.com/fxamacker/cbor/v2` 依赖。

### Changed

- 认证配置变更（`settings.auth.update`）现在推进 policy revision。
- 迁移新增 `007_oidc_consent.sql`、`008_org_invitations.sql`、`009_org_quota.sql`；权限目录新增 `settings.organization.read/update`，菜单新增应用授权、身份提供方、组织策略。

### Notes

- 本地 compose 全栈冒烟通过（MySQL 8.4 + Redis 7 + migrate 001–011 + user-center，连续两次全绿、日志 0 error/5xx）；MySQL 8.4 容器迁移真跑与本地 dev 实例 E2E 冒烟同样通过。首轮失败根因是 `docker compose build | tail` 掩盖构建失败导致复用旧镜像，已改为校验真实退出码与镜像创建时间。
- `scripts/e2e/smoke.sh` 新增 `--compose-env`，用于带 `:?` 强制校验的 compose 文件抓取失败日志。
- 范围决策：R13/R14 原分别标注「可滑动到 V2.5」与「未排期」，本次按用户要求一并交付（统一发 `v0.6.0`）。

## [0.5.2] - 2026-11-04

Full-project review follow-up. No schema change.

### Fixed

- The password-change gate skipped `/api/v1/orgs*`: `requiresAuth` only knew
  `/me` and `/admin`, so the `/orgs` branch was unreachable. An account with an
  initial password could create and read organizations before changing it.
  Tenant routes now share one path table with the gate.
- The user list reloaded all roles, grants, inheritance, assignments and
  constraints twice per row (about 16 queries per row). It now loads the policy
  snapshot once and resolves roles and MFA state in two batch queries.
- Archived organization roles accepted grant edits; the status check was only
  present in `UpdateRole`.
- Last-owner and `max_members`/duplicate-assignment checks ran outside the
  transaction, so concurrent requests could leave an organization without an
  owner or overfill a role. Both now run inside the transaction under a row
  lock (`FOR UPDATE`; SQLite skips it).
- Adding a member distinguished "unknown account" (404) from "disabled account"
  (400), letting a tenant administrator enumerate the platform directory.
- `authorization:explain` accepted `resource_id` and silently ignored it,
  returning an authoritative-looking but incomplete decision. It is now
  rejected with a validation error and the SPA no longer offers the field.
- `reason` was optional and silently defaulted at 33 call sites, contradicting
  the documented audit contract. Management writes now require a non-empty
  reason (max 512 characters).
- `memoryKV` never swept expired entries; rate-limit keys embed a time bucket,
  so a Redis-less deployment grew without bound.
- Webhook callbacks accepted plaintext `http` for any host and any link-local
  address (including the metadata endpoint). Public receivers now require
  `https`; link-local and unspecified hosts are always rejected.
- Outbox dispatch failures were discarded; they are now logged.
- The gRPC interceptor forwarded non-integration methods without authentication;
  it now denies by default.
- MySQL migrations were wrapped in a transaction even though DDL commits
  implicitly, so a partial migration could not be resumed. Progress is now
  recorded per statement.
- `GetRole` loaded every role and scanned linearly; it now reads one role plus
  its grants and inheritance.

### Changed

- SPA routes are code-split: account, organization and admin screens load on
  demand. The initial JS bundle drops from 779 kB to 303 kB (gzip 214 to 92 kB)
  and the build no longer emits the 500 kB chunk warning.
- `authorization:explain` returns `VALIDATION_FAILED` for resource-scoped
  requests instead of a partial explanation.
- Swagger/HTTP clients that omitted `reason` on management writes now receive
  400 `VALIDATION_FAILED`.

## [0.5.1] - 2026-11-04

### Fixed

- Unauthenticated requests to `/api/v1/orgs*` dereferenced a zero actor and
  panicked (the connection was dropped instead of returning 401). Every
  organization RPC now requires an authenticated actor and keeps the request
  metadata used by tenant audit.
- Accounts without MFA could never obtain a step-up proof: `Verify` always
  required a second factor, so every step-up-protected organization write was
  permanently blocked for them. Step-up now requires the enrolled factor when
  present and falls back to primary-password re-entry otherwise.

## [0.5.0] - 2026-11-04

V2.3 delivers organization-scoped IAM and tenant isolation.

### Added

- Authorization contexts: `platform` and `organization:{id}`. A grant only
  applies inside the context it was issued for, and a permission whose
  `context_types` lacks the request context is refused.
- Organization-scoped IAM API: list roles/permissions, create/update/archive
  custom roles, replace role grants, list/assign/revoke member assignments and
  read tenant audit at `/api/v1/orgs/{id}/iam/*` and
  `/api/v1/orgs/{id}/audits`.
- Built-in organization roles `org_owner/org_admin/org_member` materialized per
  organization; membership roles are projected onto them and stay in sync.
- Tenant-scoped audit: `iam_audit_events.organization_id`, filtered on read.
- Backfill for organizations created before V2.3 (`cmd/migrate` plus lazy
  provisioning on first access).
- SPA: organization "角色与授权" and "审计" tabs (custom roles, grants,
  assignments, tenant audit with action filter).

### Changed

- Organization endpoints are now permission-driven (`organization.member.*`,
  `organization.department.*`, `organization.iam.*`, `organization.audit.read`,
  `organization.settings.update`, `organization.archive`) instead of only
  comparing the membership role.
- Platform role/assignment queries exclude organization-context rows, and vice
  versa, at the SQL layer.

### Fixed

- Organization member list returned zero-valued ids, roles and status: the query
  scanned into an embedded unexported PO, which GORM could not populate. The
  scan now uses explicit fields, so member lists and member-based UIs are
  correct again.
- Organization roles leaked into platform views: `/me`, user details and the
  platform role directory no longer list organization-scoped assignments
  (`context_type='platform'` filter on role lookups).
- Concurrent creation of the same organization role returned a raw driver error;
  it now answers 409 `ORGANIZATION_ROLE_EXISTS`, and first-access backfill
  tolerates concurrent or interrupted provisioning.

### Security

- Cross-tenant role/assignment identifiers in URL or body resolve to
  `RESOURCE_NOT_FOUND`; tenant queries always carry the context in the WHERE
  clause.
- Custom organization roles may only grant organization-context permissions
  with allow semantics; `org_` codes and built-in roles are immutable.

## [0.4.0] - 2026-11-04

V2.2 delivers organization, department and membership management.

### Added

- Organization lifecycle: create/list/get/rename/archive; creator becomes owner.
- Organization members with owner/admin/member roles, username/email lookup,
  department assignment, role changes, removal and self-service leave.
- Last-owner protection: the final owner cannot be demoted, removed or leave.
- Departments with parent/child hierarchy, cycle detection, archive and member
  assignment.
- Platform admin organization directory and archive endpoints.
- Org member email masking for plain members; owner/admin/platform see contact.
- Audit events for organization/member/department changes.
- SPA organization switcher, `/orgs` list/create, `/orgs/:id` overview/members/
  departments/settings, and `/admin/organizations` platform directory.
- MySQL migration `005_organizations.sql`, permissions/menu seed and tests.

### Notes

- Organization roles are separate from platform IAM roles. Organization-scoped
  IAM contexts (`organization:{id}`), role assignments and tenant data isolation
  remain V2.3.
- No invitation acceptance flow yet: managers add existing enabled accounts
  directly.

## [0.3.0] - 2026-11-03

V2 starts with a standards-based OIDC Provider.

### Added

- OIDC discovery (`/.well-known/openid-configuration`), JWKS (`/oidc/jwks`),
  authorization endpoint (`/oidc/authorize`), token endpoint (`/oidc/token`) and
  userinfo endpoint (`/oidc/userinfo`).
- Authorization code flow with S256 PKCE, exact redirect URI matching,
  RS256 ID/access tokens, refresh tokens for `offline_access`, nonce and
  auth_time claims.
- OIDC client administration (`/admin/oidc-clients*`): one-time client secret,
  redirect URI/scope management, secret rotation, disable and audit.
- OIDC RSA signing key loading from `OIDC_SIGNING_KEY_PATH`/PEM with an
  ephemeral development fallback.
- Admin SPA page for OIDC applications and discovery/JWKS endpoint display.
- Real QQ SMTP acceptance: implicit TLS/STARTTLS support, end-to-end send and
  IMAP delivery verification (see `docs/acceptance-smtp-2026-11-03.md`).

### Notes

- V2.1 auto-consents clients pre-registered by an administrator; interactive
  consent and RP-initiated logout are V2.2.
- Organization/multi-tenancy, WebAuthn, SCIM and directory sync remain open V2
  milestones.

## [0.2.1] - 2026-11-03

Security-review and verification follow-up to 0.2.0.

### Security

- Enforce actor-aware scopes, root protection, delegation ceilings, atomic
  batch authorization, current policy/target revisions and non-empty reasons.
- Prevent challenge, TOTP, recovery-code and stale step-up replay; fail closed
  on authentication dependencies and keep sensitive writes with their audit.
- Recheck export authority, restrict integration callers and session revocation,
  remove the static integration-token bypass, and harden mail and startup secrets.
- Isolate frontend sessions and cached authorization; keep legacy governance
  roles pending until explicitly reassigned with a verified boundary.
- Refuse unsigned Outbox webhook delivery when `OUTBOX_SIGNING_SECRET` is absent.

### Changed

- Use strict ProtoJSON and decimal-string 64-bit values; update generated API
  types and management preconditions together.
- Add OAuth-only identity re-verification and explicit offline root MFA rescue.
- Recover Outbox leases and historical backlog; fix Docker command overrides.
- Save the first email settings row with a deterministic revision instead of a
  false `REVISION_CONFLICT`.
- Record findings, compatibility changes and validation in the review report
  (archived outside the repository).

### Added

- Adapter tests against local fake GitHub/Google OAuth servers and a local fake
  SMTP server.
- Docker image build plus container smoke test for native and linux/amd64
  targets; CI container job.
- Release notes for v0.2.1.

## [0.2.0] - 2026-11-02

Completes the remaining V1 governance, integration and migration capabilities
on top of the 0.1.0 extraction.

### Added

- Enforced admin MFA policy at the authorization seam; root/admin can still
  authenticate and enroll a second factor but management calls return
  `MFA_ENROLLMENT_REQUIRED` until TOTP is active.
- Forced first password change: initial-password accounts receive
  `password_change_required` at login and are blocked from `/admin/*` until
  the password is changed.
- GitHub/Google OAuth login and account binding with single-use state,
  HttpOnly state cookie, server-side code exchange and no email auto-merge.
- Administrator email change with a verification code sent to the new mailbox,
  step-up, identity version bump and session revocation.
- Assignment listing endpoint with user/role/status filters and pagination.
- IAM delegation CRUD and assignment enforcement for bounded manager roles;
  seeded permissions, menu and step-up protection.
- Integration client management (allowed gRPC methods, event subscriptions,
  callback URL), credential rotation with one-time display, and persisted
  client authentication replacing the static-token-only path.
- Transactional outbox webhook worker with HMAC-SHA256 signatures, retry
  backoff, delivery listing and manual retry.
- `cmd/import-legacy` offline importer with dry-run, conflict reporting,
  stable user IDs, password hashes, role assignments and import batch records.
- User export filters (`role_id`, `mfa_enabled`) and audit export `target`
  filter; delegation revocation fields in the API.
- Domain `Scope.Covers` for delegation boundary containment.
- Frontend: forced password/MFA prompts, OAuth buttons and callback handling,
  admin email change, assignment list filters, delegation and integrations
  pages.
- Tests for registration/password reset, admin email change, OAuth bind/login,
  OAuth+MFA, MFA enforcement, forced password change, integration clients +
  webhook delivery, legacy import, assignments and delegations.
- Adapter tests against a local fake GitHub/Google OAuth server and a local
  fake SMTP server; Docker image build plus container smoke test for both
  native and linux/amd64 targets; CI container job.

### Fixed

- Verification-code hashes now derive from the challenge purpose consistently;
  registration, password reset and email-change flows no longer fail with
  `CHALLENGE_INVALID`.
- Outbox delivery rows are scanned explicitly, so event/subscriber IDs and
  statuses are persisted and listed correctly.

## [0.1.0] - 2026-11-02

First runnable extraction of the user center from `micro-one-api` (baseline
`4116899a`).

### Added

- Standalone Kratos service with HTTP `/api/v1` and internal gRPC `:9090`,
  Wire assembly, MySQL migrations, Redis-backed challenges/rate limiting,
  SMTP/console mail adapter and SPA hosting.
- Account lifecycle: registration with email challenge, password login,
  password reset, profile update, enable/disable/archive, CSV export with
  permission rechecks.
- Security: bcrypt credentials, TOTP + recovery codes, step-up proofs,
  one-time email challenges, security events, admin MFA reset.
- Sessions: opaque HttpOnly cookie sessions, identity version validation,
  idle/absolute expiry, self-service and admin revocation, active session
  roles with constraint checks.
- IAM: resource/permission catalog, roles, inheritance, scoped assignments,
  explicit deny, validity windows, separation-of-duty constraints, menus,
  batch assignment, explain/simulate, policy revisions and immutable audit.
- React 19 SPA with user portal and admin console, generated OpenAPI types,
  CSRF-aware API client and permission-gated navigation.
- Tests: domain authorization, data repositories on SQLite, end-to-end HTTP
  flows including CSRF, scoped admin access, revision conflicts, export
  download and full MFA login.
- Dockerfile, docker-compose (MySQL/Redis/migrate/app), Makefile, dev scripts
  and architecture/API/data/migration/operations/security documentation.

### Known limitations

See `docs/security.md` §4 and `README.md` §实现范围与已知差异:
admin MFA enforcement, forced first password change, OAuth provider login,
legacy import tooling, outbox webhook delivery and delegation management are
not delivered in 0.1.0.
