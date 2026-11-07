# V2.5 路线图：生产化基座与组织治理深化

> 基线：`v0.6.1`（`6d1898c`）· 盘点日期：2026-11-06 · 当前进度：**W1/W2/W4 已随 `v0.7.0` 发布**
> 状态：正式路线图。W1/W2/W4 随 `v0.7.0` 发布，W3（认证加固）随 `v0.8.0` 发布，W5（组织治理）随 `v0.9.0` 发布。W6：S13（备份恢复与升级回滚演练）已完成并提交（`develop` 上 2 个 commit），**未发版**；S14（真实 OAuth 沙箱验收）因缺少凭据与回调域名按约定标 N/A，待 D4 落实后补做。W6 引入运行时变更，版本号待判定，见 §5。
> 上游：[V2.4 路线图](./roadmap-v2.4.md)（R1–R14 全部交付，§6 门禁 8/8 勾选）

## 0. 这份文档怎么用

- 回答三个问题：**V2.4 之后真实缺什么、V2.5 做什么、怎么算做完**。
- 状态只在真实合并后勾选，未开工保留 `[ ]`；不做"文档先行打勾"。
- 只有 §4 的工作项可被排期，§3 不纳入项需先改决策再谈实现。

## 1. 基线：v0.6.1 的客观状态

| 维度 | 事实 | 判定 |
|---|---|---|
| 功能面 | V2.4 R1–R14 全部交付（OIDC 同意/登出、邀请、explain、租户导出、组织事件、gRPC 登录、WebAuthn、保留清理） | ✅ 无已知功能空洞 |
| 代码卫生 | `internal` + `domain` + `platform` + `pkg` + `cmd` 共 ≈33.6k 行 Go；`TODO`/`FIXME`/`NotImplemented` 全仓库 0 命中 | ✅ |
| 迁移 | `migrations/mysql/001–011`，v0.6.1 无新增 | ✅ |
| 前端 | `web/src` 107 个 TS/TSX 文件，v0.6.1 后 17 文件 / 60 用例全绿 | ✅ |
| 分支 | `develop` = `6d1898c`，`main` = `f9ce01c`（merge），tag `v0.6.1` | ✅ 已同步 |
| **可观测性** | 全仓库无 `prometheus` / `/metrics` / tracing 依赖；只有 `/healthz` | ❌ 空白 |
| **性能** | 无压测脚本、无基线数值、无慢查询清单；一次性 SQL 优化只有 v0.5.2 的用户列表 N+1 | ❌ 空白 |
| **限流覆盖面** | 仅 auth 路径：`login:<ip>` 30/5min、`login-user`、`mfa` 20/5min、`register` 10/h、`reset` 10/h；**admin/IAM/组织写接口无任何限流** | ⚠️ 局部 |
| **密码策略** | 仅最小长度（默认 10）+ 72 字节上限；无复杂度、无历史复用、无有效期 | ⚠️ 弱 |
| **会话治理** | 有列表/撤销/空闲超时/身份版本；无并发会话上限、无设备标签 | ⚠️ 局部 |
| **CI 门禁** | 3 个 job：backend（sqlite `go vet/test/build`）、frontend、container（sqlite 冒烟）；**无 MySQL 集成 job、无生成物漂移校验、无 compose E2E** | ⚠️ 缺口 |
| `scripts/check.sh` | 只有 `gofmt` / `vet` / `test` / `web test` / `web build`，**未含 `make api` / `make wire` 生成物校验** | ⚠️ 缺口 |
| 运维闭环 | `docs/operations.md` 有备份命令与保留清理流程；**无恢复演练记录、无升级回滚演练记录** | ⚠️ 未验证 |
| 外部集成验收 | GitHub/Google 仅有本地 fake provider 测试；**真实提供方沙箱验收未执行**（缺凭据） | ⚠️ 未闭环 |

盘点结论：**功能维度已经没有"未开工"的承诺项**。剩余差距全部在"能不能放心上生产"这一层：看不见（无可观测性）、说不清（无容量基线）、守不住（门禁不全）、没演练过（备份/回滚）。

## 2. 差距分类

沿用 V2.4 §2 口径：

| 类型 | 本阶段内容 |
|---|---|
| A · 设计明确要求、未实现 | 组织级 SoD / 组织内委派（V2.4 §3.2 明确留到 V2.5 且要求"先出设计"）；密码策略强度（设计 4.1 要求"重新验证"，未要求复杂度，属 C 类补强） |
| B · 设计与实现不一致 | 无新增。v0.6.1 已收敛 |
| C · 工程扩展 | 可观测性、容量基线、全局限流、会话设备治理、CI 门禁、运维演练、真实 OAuth 验收 |

不算完成的判定（沿用）：返回空实现/501；只改文档不改代码；用"暂时不支持"代替权限判定；压测不写环境与数值只写"已优化"。

## 3. V2.5 范围

### 3.1 纳入

- **可观测性**（P0）：指标、日志相关性、SLO 与告警基线。
- **容量基线与查询治理**（P0）：可复现压测脚本 + 数值基线 + 缺失索引补齐。
- **工程门禁**（P0）：CI 加 MySQL 集成、生成物漂移、compose E2E；本地脚本对齐。
- **认证与访问加固**（P1）：密码策略、并发会话上限与设备标签、管理面限流。
- **组织治理深化**（P1）：组织上下文内的互斥角色对与角色数量上限、组织内委派 —— **设计先行**。
- **运维就绪**（P2）：备份恢复演练、升级回滚演练、真实 OAuth 沙箱验收。

### 3.2 不纳入（附理由）

| 项 | 不纳入的理由 | 去向 |
|---|---|---|
| SCIM 2.0 / 目录同步 | 需完整 schema、过滤语法、PATCH 语义与 IdP 兼容矩阵，等于独立里程碑；V2.4 已定 V2.6 | V2.6 单独立项 |
| SAML 2.0 SP/IdP | 设计文档未要求；企业客户若提需求需先做产品决策，不与 SCIM 混做 | 待产品输入 |
| 租户物理隔离（独立库 / RLS / 分区） | 当前逻辑隔离满足单库多租户；取决于部署规模与合规合同 | 按需评估 |
| `ExchangeLegacySession` | 设计标注"可选、默认关闭" | 明确不做 |
| 组织成员批量导入（CSV） | 与 SCIM 能力重叠，做一次会白做 | 并入 SCIM 评估 |
| 管理端可视化审计大屏 | 收益低于可观测性，无合规驱动 | 不排期 |

### 3.3 为什么这样切

- 功能已满，**风险全部转移到运行期**。没有指标和基线的 MINOR 版本发得越多，线上问题定位成本越高。
- 门禁缺口是**已经踩过的坑**：v0.6.0 的 compose 首轮失败源于 `build | tail` 吞掉退出码，本质就是"门禁不校验真实退出码"；把它写进 CI 比写进文档可靠。
- 组织治理（SoD/委派）是 V2.4 明确欠下的设计债，但改动横跨 domain/biz/data/web，**必须先出设计再动代码**，否则会重演 v0.6.0 的返工。
- 认证加固有行为变更（存量弱密码账号、会话被上限裁剪），**单独成版**发，避免和生产化增量混在一次发布里难以回滚。

## 4. 工作项

优先级：**P0** 阻塞上生产；**P1** 影响安全或企业落地；**P2** 运维完备性。
规模：**S** 单点（≤1 天）、**M** 跨层（proto + biz + data + web）、**L** 新子系统。

---

### W1 · 生产可观测性（P0）

#### S1 指标端点与核心指标

| 项 | 内容 |
|---|---|
| 现状 | 无 `/metrics`，无 Prometheus 依赖；只有 `/healthz` 返回 200 |
| 目标 | 暴露 RED 指标与业务关键计数，运维可采集可告警 |
| 影响面 | `internal/server`（中间件 + 独立监听端口）、`internal/config`、`docs/operations.md` |
| 规模 | M |
| 依赖 | 无 |

验收：

- [x] `GET /metrics` 独立监听（默认 `127.0.0.1:9091`，`METRICS_ADDR=off` 关闭）；不挂 `/api/v1`、不需要会话
- [x] HTTP 维度：`route` 模板（数字段归一 `{id}`，非 API 路径归 `spa`）+ `method` + `status` 计数与延迟直方图
- [x] 认证维度以路由+状态码派生（`/api/v1/auth/login` 的 200/401/429 即成功/失败/限流），**未做 biz 埋点**；按 key 前缀的限流细分留给 S8 统一限流中间件
- [x] 数据维度：Outbox 投递按状态计数、迁移步数、MySQL/Redis 连通性 gauge
- [ ] 审计写入数 —— **未做**，同样需要 biz 埋点，排到 S8 或 S2 一并处理
- [x] 标签基数受控：路由模板化 + 未知状态归 `other` + 超长路径截断 `/**`；有单测断言同一资源不同 ID 落同一标签
- [x] 不泄露用户标识（端到端验证 scrape body 无 `orgs/7`、无数字 ID）；探测失败保留上次值、不影响抓取
- [x] `docs/operations.md` §5.1 给出采集地址、指标清单、Prometheus 配置与两个易误读点；GRAFANA 面板字段随 S3 一起出

#### S2 请求链路标识与日志脱敏

| 项 | 内容 |
|---|---|
| 现状 | 有 `request_id` 中间件与 zap 日志；无 trace/span，脱敏依赖人工审查 |
| 目标 | 一条请求的 HTTP → service → biz → data 日志可用同一标识串起来；敏感字段有测试兜底 |
| 影响面 | `internal/server`（context）、`internal/biz`、`internal/data`、日志封装 |
| 规模 | M |
| 依赖 | S1（同一次改造引入 metrics/log 封装） |

验收：

- [x] `request_id` 贯通：HTTP 中间件已有，新增 gRPC unary interceptor（取 `x-request-id` metadata，缺省生成、超长替换而非截断、并通过 header 回写）；邮件日志开始携带
- [x] 日志结构化字段写入 `docs/operations.md` §5.1 表格（慢请求 5 个字段、邮件 3 个字段），字段名由测试白名单锁定
- [x] 脱敏测试：慢请求日志断言不含请求体内容；字段白名单 `{request_id, route, method, status, duration_ms}`，新增字段会让测试失败强制审查；邮件 `to` 掩码为 `a***@example.com`（含换行注入拒绝，表驱动 8 个用例）
- [x] 慢请求日志含 `route`（模板非原始路径）、`duration_ms`、`status`，不含 body/header/query/Cookie；阈值 `SLOW_REQUEST_THRESHOLD_MS`（默认 500ms）
- [x] 未引入 OpenTelemetry（D5），只做 request_id 贯通
- [x] **顺带补齐**：新增 `usercenter_db_pool_connections{state=open|in_use|max}` 与 `usercenter_db_pool_wait_total`，否则「连接池耗尽」这条告警写不出来（S4 已证明池配置能吞掉 3.5 倍容量）

#### S3 SLO 与告警基线

| 项 | 内容 |
|---|---|
| 现状 | 无 SLO、无告警规则 |
| 目标 | 把"什么算不健康"写成可执行规则 |
| 影响面 | 文档 + 告警规则文件（`deployments/`） |
| 规模 | S |
| 依赖 | S1 |

验收：

- [x] `docs/operations.md` §5.2 定义可用性 99.9%、P95 < 300ms、5xx < 1%、Outbox < 1000、连接池 < 90% 且无排队，每项标注依据
- [x] 7 条告警规则（`deployments/prometheus/alerts.yml`）：5xx 率、P95 越界、登录失败激增、Outbox 积压、依赖不可用、连接池耗尽、迁移未应用；`promtool check rules` 通过（7 rules found）
- [x] 每条规则带 `first_step` 注解 + 运维手册表格写清触发条件/影响面/首步排查动作（含 429 vs 401 vs 5xx 的拆分判断）
- [x] 两个容易写错的细节已处理：连接池除法必须 `ignoring(state)`（否则默认一对一匹配返回空向量，告警永不触发）；迁移规则只对 MySQL 启用（SQLite 走 AutoMigrate 恒为 0）

---

### W2 · 容量基线与查询治理（P0）

#### S4 压测脚本与基线数值

| 项 | 内容 |
|---|---|
| 现状 | 无压测脚本，无任何 QPS/延迟数据 |
| 目标 | 任何人可在干净机器上复现同一组基线 |
| 影响面 | `scripts/bench/`（新）、`docs/performance.md`（新） |
| 规模 | M |
| 依赖 | S1（压测时同时观察指标） |

验收：

- [x] 脚本覆盖 5 个场景：`auth/context` 未认证基线、`/me/authorization`、`/admin/users`、`/orgs/{id}/members`、`login`（受硬限流的拒绝路径）。OIDC 授权码交换未纳入：需要浏览器交互式同意，脚本化成本远高于收益，见 §8
- [x] 脚本参数化（`--vu`、`--duration`、`--scenarios`、`--accounts`、`--http-port`、`--out`），一条命令跑完并打印 markdown 表（`scripts/bench/run.sh`）
- [x] `docs/performance.md` 记录：Apple M5 / 16 GB / Docker 10 CPU、MySQL 8.4.11、Go 1.27.3、k6 v2.3.0；5 场景 QPS 与 P50/P95/P99、失败率
- [x] 明确"单实例安全水位"与扩容判据：`me` ≈780 QPS、`org` ≈878 QPS（未探底）、`admin` ≈150 QPS；先优化 `admin` 列表再谈横向扩容
- [x] 基线以 MySQL 8.4 跑（SQLite 未纳入：dev 配置 `max_open_conns=1` 不代表生产形态，且 SQLite 无并发写能力）
- [x] **附带发现**：`configs/config.dev.yaml` 的 `max_open_conns: 1` 被 MySQL 部署继承时吞掉 3.5–4 倍容量；基准改用 `scripts/bench/config.mysql.yaml`（20/10 连接），不影响 dev 配置

#### S5 索引审计与慢查询治理

| 项 | 内容 |
|---|---|
| 现状 | 索引随功能增量添加，无系统性审查；v0.5.2 只修过用户列表 N+1 |
| 目标 | 热点查询全部走索引，缺索引有迁移有依据 |
| 影响面 | `migrations/mysql/012_*.sql`、`internal/data` 查询、`docs/data-model.md` |
| 规模 | M |
| 依赖 | S4（压测暴露热点） |

验收：

- [x] 用 `EXPLAIN` 核对场景涉及的每条查询：新增 `scripts/bench/explain.sql` 灌 2 万行夹具后对 12 条真实查询出计划，结果表见 `docs/performance.md` §7
- [x] 审计结论：**没有缺失索引，本阶段不新增 `012` 迁移**（为有产出而加索引只会增加写放大）；`users` 分页命中 `idx_users_created_id` 且无 filesort，会话按哈希 `const`，批量查询走 range
- [x] 三个遗留限制写入文档而非糊过去：关键字搜索 `LIKE '%kw%'` 全表扫（需产品定前缀/全文语义）、受限 scope 分页有 filesort（scope 小，可接受）、组织成员列表无分页（前端契约变更，不在本阶段）
- [x] 审计/会话/Outbox 大表清理策略写入 `docs/performance.md` §8，含增长估算、建议保留期与**为什么现在不做**（删除不可逆 + 保留期需合规输入 + 缺少删除前行数水位告警）
- [x] 列表接口抽查：用户/审计/投递/导出均 SQL 侧过滤 + `Offset/Limit` + `Count`；组织成员为全量返回（已知限制，已记录）
- [x] **附带修复（超出原验收范围，但它是本阶段最大收益）**：`admin` 列表单请求 92 条 prepared statement（权限字典逐行重查 70 次 + 政策快照加载 4 次）→ 20 条 SELECT；`admin` 16 VUs 从 176 QPS/111 ms 提升到 622 QPS/31 ms（3.5×）

---

### W3 · 认证与访问加固（P1）

#### S6 密码策略

| 项 | 内容 |
|---|---|
| 现状 | 只有最小长度（默认 10）与 72 字节上限；无复杂度、无历史、无有效期 |
| 目标 | 策略可配置，且对存量弱密码账号有明确的迁移路径而非静默放行 |
| 影响面 | `internal/biz`（校验）、settings proto、注册/改密/重置三处入口、web 提示、migration |
| 规模 | M |
| 依赖 | **决策 D2**（已拍板：复杂度 + 历史 5 条，有效期默认关闭） |

验收：

- [x] 策略项进 settings：`password_min_classes`（0-4）、`password_history_count`（0-20）、`password_expiry_days`（0-3650）、`max_sessions_per_user`（0-1000），带 `update_mask` 与范围校验
- [x] **与本节原意的偏差（按 D2 执行）**：原写"默认不提高门槛"，但 D2 已拍板复杂度与历史默认开启，故默认值为 3 类字符 + 历史 5 条。存量账号不受影响——策略只在"设置密码"时生效，登录不校验强度
- [x] 历史校验用不可逆摘要存储（`password_history` 只存 bcrypt 输出，每次写入折叠到策略窗口），迁移 `012`
- [x] 四处入口共用同一 `ValidatePassword(pw, PasswordPolicy)`：注册、自助改密、验证码重置、管理员设初始密码（比原验收多一处）
- [x] 违反策略返回稳定错误码 `PASSWORD_POLICY_VIOLATION` 并带可读原因；字符类错误会说明"需要几类 / 当前几类"。前端 `web/src/lib/password.ts` 同步该规则，注册/重置/改密/建号四处表单在提交前就提示
- [x] 存量账号策略：有效期默认关闭（0）；开启后只触发"登录响应置位 + 中间件强制改密"，不锁定账号。`password_changed_at` 为 `NULL` 的存量账号视为"年龄未知"，永不过期。结论写入 `docs/security.md` §3.2 与 §4 第 11 条
- [x] 测试：长度（Rune 计数 vs bcrypt 字节上限）、字符类（8 个表驱动用例，含中文口令不计类）、历史复用（回退到初始密码被拒）、有效期到期、默认配置行为（放宽后同一弱密码可通过）
- [x] **附带修复**：bootstrap 与 admin-rescue 也播种历史，否则 root 的首次轮换可以改回引导密码（`password_history` 为空导致规则静默跳过）

#### S7 会话与设备治理

| 项 | 内容 |
|---|---|
| 现状 | 有会话列表/撤销/空闲超时；无并发上限、无设备标识 |
| 目标 | 账号被盗时可判断"哪台设备"，并限制会话数量膨胀 |
| 影响面 | `internal/biz`、`internal/data`（会话表列）、web 安全中心、migration |
| 规模 | M |
| 依赖 | S6（同一批 settings 扩展） |

验收：

- [x] 会话记录 `user_agent` 摘要（120 字符）+ 掩码 IP（IPv4 保留前三段、IPv6 保留前两组，末段/后组替换为 `x`），**不存完整 IP 明文**；粒度结论写入 `docs/security.md` §3.2
- [x] 每用户并发会话上限可配（`max_sessions_per_user`，默认 10），超限按"最久未活跃"回收；登录响应新增 `recycled_sessions`，前端以 toast 告知"已退出 N 个最久未使用的会话"
- [x] 回收为服务端强制失效（写 `revoked_at` + 清 step-up），被回收会话下一次请求 401
- [x] `POST /me/sessions:revoke-others` 已存在，本次补写安全事件 `session_revoke_others`（即使没有其他会话也记录：这是事件复盘要找的信号）
- [x] 测试：上限触发（第 3 次登录回收 1 个）、回收顺序（回拨 `last_seen_at` 后断言被回收的是旧会话）、按用户隔离（root 的回收不动他人会话）、撤销其他会话、不可越权撤销他人会话（404 而非 403）

#### S8 管理面与写接口限流

| 项 | 内容 |
|---|---|
| 现状 | 限流只在 auth 路径手写调用；`/admin/*`、`/orgs/*` 写接口无限流 |
| 目标 | 统一中间件限流，堵住"高权限账号被脚本刷"和"批量导出拖库" |
| 影响面 | `internal/server`（中间件）、`internal/config`、设置项、测试 |
| 规模 | M |
| 依赖 | S1（限流命中要能观测） |

验收：

- [x] 统一限流中间件（`internal/server/ratelimit.go`）：按「主体（user id / 接入 client id / 匿名才退回 IP）+ 路由类」计数，默认仅对非安全方法生效。**偏差**：路由模板在 Filter 层不可得（S1 已确认），因此按稳定的 API 形状（`:export` / `:batch-*` / `/invitations` / 其余）分类，而不是精确模板
- [x] 认证类限流保持独立并**显式排除**在该中间件之外（`/api/v1/auth/*`），因此不存在一次请求消耗两份预算或挑松一侧绕过的情况；两个计数器共用同一个 `RateLimiter` 后端
- [x] 导出（`/admin/users:export`、`/admin/audits:export`、`/orgs/{id}/audits:export`）、批量分配（`:batch-assign`/`:batch-preview`）、邀请默认 10 次/分钟，普通写 120 次/分钟
- [x] 超限返回 429 + `Retry-After`（窗口剩余秒数，1–60）+ 稳定错误码 `RATE_LIMITED`，并记 `usercenter_rate_limit_hits_total{scope}`
- [x] 测试：并发触发上限（40 并发 / 上限 5，恰好 5 个通过）、窗口滑过后恢复（200ms 窗口跨边界恢复）、限流不影响只读接口、命中计数进指标（按 scope 分行）、后端故障 fail-open
- [x] 配置化：`RATE_LIMIT_ENABLED` / `RATE_LIMIT_WRITE_PER_MINUTE` / `RATE_LIMIT_HEAVY_PER_MINUTE`，默认开启；`docs/operations.md` §5.1.1 写清多实例下无 Redis 时额度是「配置值 × 实例数」

---

### W4 · 工程门禁（P0）

#### S9 CI 增加 MySQL 集成 job

| 项 | 内容 |
|---|---|
| 现状 | CI 只在 SQLite 上跑 `go test`；MySQL 迁移真跑与 `oidc_mysql_review_test.go` 依赖人工在本地起容器 |
| 目标 | MySQL 相关行为在 CI 上每次合并都被验证 |
| 影响面 | `.github/workflows/ci.yml` |
| 规模 | S |
| 依赖 | 无 |

验收：

- [x] job 使用 `mysql:8.4` service，设置 `USER_CENTER_MYSQL_TEST_DSN` 后运行 `go test -run MySQL ./cmd/migrate/` 与 `./internal/data/`（v0.7.0 W4 已实现，`.github/workflows/ci.yml` 的 `mysql` job）
- [x] 迁移连续应用两次（幂等）在 CI 中被断言（`TestOIDCMySQLMigrations` 内 `for range 2` 应用 001–011）
- [x] job 失败时保留日志，不因 DB 未就绪假失败（service `--health-cmd` 30 次重试 + `if: failure()` 输出容器日志）
- [ ] 总 CI 时长增加不超过 5 分钟 —— **待首次真实 CI 运行观测**；本地两条命令耗时 1.57s + 0.59s（不含编译），编译时间取决于 module 缓存

#### S10 生成物漂移校验

| 项 | 内容 |
|---|---|
| 现状 | V2.4 §6 要求 `make api` / `make wire` 后 `git diff --exit-code`，但只靠人记得做；`scripts/check.sh` 未包含 |
| 目标 | 手改生成物或忘记重新生成时 CI 直接红 |
| 影响面 | `.github/workflows/ci.yml`、`scripts/check.sh`、`Makefile` |
| 规模 | S |
| 依赖 | 无 |

验收：

- [x] CI 增加生成物校验（`scripts/gen-check.sh`，`generated` job）。实现比验收标准更严：用 `git status --porcelain` 而非 `git diff --exit-code`，因为新增 proto 产生的**未跟踪**生成文件 `git diff` 看不见
- [x] `scripts/check.sh` 默认包含该校验；`buf`/`wire` 缺失或工作区脏时跳过并打印原因，不静默通过
- [x] 失败信息明确指出"生成物已过期，请运行 make api / make config / make wire 并提交"，并列出变更文件与 `diff --stat`
- [ ] 真实 CI 首跑确认（本地已双向验证：干净树 exit 0；注入过期生成物 exit 1）

#### S11 compose E2E 进 CI（nightly 或 merge 到 main）

| 项 | 内容 |
|---|---|
| 现状 | `scripts/e2e/smoke.sh --compose` 只在本地跑过；CI 只有 sqlite 容器冒烟 |
| 目标 | 真实 MySQL + Redis + migrate + 服务的全栈冒烟不再依赖"人记得跑" |
| 影响面 | `.github/workflows/`、`scripts/e2e/` |
| 规模 | M |
| 依赖 | S9 |

验收：

- [x] 工作流 `.github/workflows/e2e-compose.yml`：`workflow_dispatch` + `push: main`，不进 PR 门禁
- [x] 构建步骤校验真实退出码并比对镜像创建时间：`set +e` + `PIPESTATUS[0]`，禁止 `| tail` 吞码；镜像 `Created` 早于构建开始时间直接失败
- [x] 失败时上传容器日志与冒烟快照为 artifact（`if: failure()`，`if-no-files-found: warn`）；teardown 在失败时先补收 `compose logs`，避免 artifact 为空
- [x] 通过后输出关键落库证据：`organizations` / `iam_audit_events` / `event_outbox` / `iam_sessions` 行数
- [x] **额外门禁**：容器日志出现 `"status":5xx` 或 `panic:` 直接判失败（冒烟绿但日志有 5xx 比红更危险）
- [x] 步骤抽到 `scripts/e2e/compose-e2e.sh`，本地与 CI 执行同一份逻辑（本地实跑通过：`E2E OK`、organizations=1、audit=2、outbox=2、sessions=1、日志 0 条 5xx）
- [ ] 真实 CI 首跑观测（工作流首次触发后回填验证结果）

---

### W5 · 组织治理深化（P1，设计先行）

#### S12 组织上下文内的职责分离与委派

| 项 | 内容 |
|---|---|
| 现状 | 约束（互斥角色对、`max_roles`）与委派都是**平台上下文**语义；组织域有角色与分配，但没有约束与委派 |
| 目标 | 组织管理员能在不触碰平台策略的前提下，为本组织定义互斥角色对与组织内委派 |
| 影响面 | `domain/authorization`（约束作用域）、proto、biz、data、web（组织设置页） |
| 规模 | L |
| 依赖 | **决策 D3**（是否做）；先出设计文档再动代码 |

验收（设计阶段）：

- [x] `docs/design/org-sod-delegation.md`：作用域模型（约束/委派沿用角色的 `context_type/context_id`）、与平台约束的关系、冲突判定顺序（6 步）、越权边界、迁移 `013` 与"默认值即回填"方案
- [x] 明确"组织约束不能放宽平台约束"的合并规则：逐集合独立求值 + AND 合并（交集），组织侧无任何"禁用平台约束"字段
- [x] 决策矩阵覆盖 platform admin / 组织 owner / 组织自定义 `iam.role.write` 三类角色的 9 类操作
- [x] 设计评审完成：8 条发现（F1–F8），推翻 §4 论证与 §7 后果描述，砍掉平台管理员跨租户只读，D6–D10 定案，结论"通过，可进入实现"。评审记录见 `docs/design/org-sod-delegation.md` §0
- [x] **设计期发现并已修复**：组织 `AssignRole` 原本既不校验 `CheckConstraints` 也不校验委派边界，平台 SoD 在组织域可被绕过。现已在事务内接入约束校验，并补上"不能给自己授权"（`ORGANIZATION_SELF_GRANT`）

验收（实现阶段，评审通过后展开）：

- [x] 组织内 `mutual_exclusion` 与 `max_roles` 生效。**与设计原稿的偏差**：不是"与平台约束求交"，而是结构性隔离 —— 角色在单表里全局自增，平台约束的 role id 永不匹配组织角色；隔离由 `ListConstraints(ctx, tx, authCtx)` 的显式 context 过滤保证，不依赖 ID 分配。`max_roles` 按 `role_ids` 范围计数（实现期发现原设计对语义理解有误，见设计文档 F9）
- [x] 组织内委派：`DelegationFilter.Context` 强制过滤；`CreateDelegation` 写 `(context_type, context_id)`；平台委派无法批准组织分配，反向亦然
- [x] 分配路径执行约束校验（`checkOrgConstraints`）。激活路径不适用：组织分配无需会话激活，`LoadAuthzFactsIn` 每次都按当前分配重算
- [x] HTTP 级拒绝测试 6 条：平台约束不影响组织决策、组织互斥生效且不跨租户、跨上下文引用被拒（400）、跨租户读写 404、自授权被拒、收紧需确认
- [x] 变更写组织审计 + Outbox 事件（`organization.constraint.created/updated/deleted`）+ policy revision bump
- [x] **评审补充**：组织成员移除时双向软失效其委派（原实现只撤销分配，被移除者仍可能被授权或代授）

---

### W6 · 运维就绪（P2）

#### S13 备份恢复与升级回滚演练

| 项 | 内容 |
|---|---|
| 现状 | `docs/operations.md` 写了备份命令，无任何演练记录；升级流程只有 `docker compose up -d --build` |
| 目标 | 出事时照文档能救回来，且时间可预期 |
| 影响面 | `docs/operations.md`、`docs/releases/`（演练记录） |
| 规模 | S–M |
| 依赖 | S11（需要可重复的环境） |

验收：

- [x] 演练：备份 → 清库 → 恢复 → 冒烟，记录总耗时与数据一致性断言（用户数/审计数/Outbox 数）。脚本 `scripts/dr/restore-drill.sh`，实测 dump 150–200ms / 清库 341–371ms / 恢复 366–637ms / 服务自愈 831–1,392ms，10 张表行数+`MAX(id)` 逐表一致，恢复后 smoke 通过
- [x] 演练：`v0.6.1 → 新版本` 升级，中途失败回滚到旧镜像 + 旧 schema 的可行性与限制（迁移不可逆部分必须写明）。脚本 `scripts/dr/upgrade-rollback-drill.sh`，实测 58→64 步 / 341–352ms 迁移 / 回滚 1,081–1,243ms（其中恢复 766–803ms），回滚后 8 张表一致且 smoke 通过；不可逆 DDL 由脚本自动扫描（当前 1 处：`006` 的 `DROP INDEX`）
- [x] 结论写入 `docs/operations.md` §7.1–§7.3 与 [演练记录](releases/drill-2026-11-07-s13.md)，含"能回滚到哪一步、不能回滚的原因"。**额外实测**："只回退镜像不恢复库"能跑通但静默丢数据（回退窗口内改密码不进 `password_history`），已写入 §7.3
- [x] 恢复后必须跑 `scripts/e2e/smoke.sh` 通过才算演练成功（smoke 本身也新增了 `/readyz` 断言）
- [x] **演练中发现的真实缺陷（已修）**：`/healthz` 是静态 200，却被 compose healthcheck 当作健康判断，`DROP DATABASE` 后容器仍报 healthy；`PingDatabase` 用 `PingContext`（`COM_PING`）对空库也返回成功。新增 `/readyz`（真实查询 `schema_migrations`），healthcheck 切过去，`/healthz` 保持为纯存活探针；演练脚本同时修了旧版 SPA fallback 造成的假绿灯（F4/F5，见演练记录）

#### S14 真实 OAuth 提供方沙箱验收

| 项 | 内容 |
|---|---|
| 现状 | GitHub/Google 只有本地 fake provider 测试；真实凭据下的登录/绑定/回调解密未验收 |
| 目标 | 关闭 V2.4 遗留的"代码就绪、未真实验收"状态 |
| 影响面 | 验收记录文档、`configs/` 样例注释 |
| 规模 | S |
| 依赖 | **决策 D4**（是否提供凭据与回调域名） |

验收：

- [ ] GitHub：真实 OAuth App 完成登录、绑定、解绑、`state` 校验、邮箱已验证判定 —— **N/A，未执行**
- [ ] Google：同上（含 `email_verified=false` 的拒绝路径）—— **N/A，未执行**
- [ ] 回调地址为 HTTPS 且与生产域名一致（不是 localhost）—— **N/A，无可用域名与凭据**
- [ ] 验收记录写入 `docs/acceptance-oauth-2026-XX-XX.md` —— 未创建（无内容可记）
- [x] 无凭据时如实标 N/A，不勾选。**本阶段按此约定归档**：决策 D4 未提供 GitHub/Google 凭据与 HTTPS 回调域名，真实验收无法进行。fake provider 覆盖的路径见 `docs/security.md` §3（关键实现细节）与 §2 控制清单；未被真实凭据覆盖的部分已写入 §4 已知限制第 1 条

---

## 5. 波次与发版建议

| 波次 | 主题 | 工作项 | 建议版本 | 备注 |
|---|---|---|---|---|
| W1 | 可观测性 | S1–S3 | `v0.7.0` | 纯增量，无破坏性契约 |
| W2 | 容量与查询 | S4–S5 | `v0.7.0` | 与 W1 同版；索引迁移随版本发 |
| W4 | 工程门禁 | S9–S11 | `v0.7.0` | 不改变运行时行为，可提前独立合入 |
| W3 | 认证加固 | S6–S8 | `v0.8.0` | 有行为变更（策略门槛、会话上限），单版发布便于回滚 |
| W5 | 组织治理 | S12 | **`v0.9.0`（已发）** | 设计先行；实现含 4 个新 API，故单独 MINOR 发版 |
| W6 | 运维就绪 | S13–S14 | **待判定，见下方偏差说明** | 原计划"纯文档更新、不单独占版本号"，实际因演练发现缺陷引入运行时代码变更（`19d6e55`），不能按原计划处理 |

语义化版本判定：

- `v0.7.0`（MINOR）：新增 `/metrics`、新增索引迁移、CI 变更 —— 新增能力，向后兼容。
- `v0.8.0`（MINOR）：新增密码策略/会话上限/写接口限流 —— 新增能力 + 默认值有变更，故非 MAJOR。
- `v0.9.0`（MINOR）：新增组织约束 CRUD 等 4 个 API —— 新增对外能力，故非 PATCH（曾误打 `v0.8.1`，推送前撤销）。
- **W6 待判定**：新增对外端点 `/readyz`、变更 `docker healthcheck` 目标、变更 `PingDatabase` 语义（从 `COM_PING` 改为真实查询）。按"新增对外能力即 MINOR"应为 **`v0.10.0`（MINOR）**，与路线图原计划"跟随上一版文档更新、不单独占版本号"**有偏差**：原计划假设 W6 只有文档，实际演练揪出了必须修的运行时缺陷。此处不擅自改版本号，等拍板；若选择不单独发版，则这些运行时变更随下一次发版一起走，路线图备注需同步改写。

硬依赖：

- S2/S3 依赖 S1 的封装。
- S5 依赖 S4 暴露的热点。
- S8 依赖 S1（限流命中要进指标）。
- S11 依赖 S9（同一 MySQL service 复用）。
- S12 依赖设计评审通过，**评审未过不进实现**。
- S13 依赖 S11（可重复环境）。

## 6. 质量门禁

沿用 V2.4 §6，并新增三条（本阶段就是在补门禁，不补等于没做）：

- [ ] `go vet ./...`、`gofmt -l .` 无输出
- [ ] `go test ./...`；涉及并发/授权时 `go test -race ./domain/... ./internal/biz/ ./internal/data/`
- [ ] `cd web && npm test && npm run build`
- [ ] `make api` / `make wire` 生成物无差异（S10 进 CI 后由 CI 强制）
- [ ] MySQL 8.4 迁移与仓储测试在 CI 通过（S9）
- [ ] compose 全栈冒烟在 CI 或 nightly 通过（S11）
- [ ] **新增**：每个新指标有对应测试（断言指标存在且标签基数受控）
- [ ] **新增**：每条告警规则至少在本地用构造数据触发一次，记录触发证据
- [ ] **新增**：性能基线写入 `docs/performance.md`，含环境与日期，不含"大约""感觉更快"

## 7. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 指标标签基数爆炸 | Prometheus 内存暴涨 | 路由模板化 + 有限枚举；禁止 IP/邮箱/用户 ID 做标签 |
| 日志脱敏靠人肉 | 凭据泄露进日志 | 表驱动脱敏测试进 CI；日志封装层统一出口 |
| 密码策略上线导致存量账号被锁 | 用户体验与支持成本 | 默认值不变；开启有效期只做"提示 + 强制改密"，不做登录拒绝 |
| 会话上限误杀 | 移动端频繁掉线 | 默认 10 且按最久未活跃回收；响应中告知；可在设置中放宽 |
| 全局限流误伤正常运营 | 批量操作失败 | 区分读写；重操作单独阈值；429 带 `Retry-After`；灰度观察指标 |
| 迁移加索引锁表 | 大表 DDL 阻塞 | MySQL 8.4 `ALGORITHM=INPLACE` 评估；必要时用 `pt-osc`/在线 DDL，写入文档 |
| 组织 SoD 设计与平台语义冲突 | 决策不一致、返工 | 先出设计 + 决策矩阵；合并规则定为"求交不放宽" |
| 压测数据误导容量 | 高估单机能力 | 基线必须带环境规格与后端类型；区分 SQLite/MySQL |

## 8. 需拍板的决策点

| ID | 决策 | 结论 | 状态 |
|---|---|---|---|
| D1 | V2.5 主题取舍：先生产化，还是先组织治理 | **先生产化**：W1/W2/W4 为 `v0.7.0` 全部内容；W5 组织治理不进本版 | ✅ 2026-11-06 拍板 |
| D2 | 密码策略是否引入复杂度/历史/有效期 | 引入字符类复杂度 + 历史 5 条（不可逆摘要存储），**有效期默认关闭** | ✅ 2026-11-06 拍板 |
| D3 | 组织级 SoD 与组织内委派是否做 | 做设计，实现视评审结论 | ✅ 2026-11-06 评审通过并实现，随 `v0.9.0` 发布 |
| D4 | 是否提供真实 OAuth 凭据与 HTTPS 回调域名 | 提供则可闭环 S14，否则标 N/A | ⚠️ **未提供**：2026-11-07 W6 执行时仍无凭据与 HTTPS 域名，S14 已按约定如实标 N/A；凭据到位后需另开一轮补做 |
| D5 | 是否引入 OpenTelemetry tracing | **本阶段不引入**，只做 request_id 贯通 | ✅ 默认按此执行 |

D1 的连带结论：`v0.7.0` 范围锁定为 **S1–S5 + S9–S11**，不含 S6–S8（认证加固）与 S12（组织治理）。

## 9. 变更记录

| 日期 | 变更 | 说明 |
|---|---|---|
| 2026-11-06 | 初稿 | 基于 `v0.6.1`（`6d1898c`）盘点；确定 S1–S14 与 W1–W6，明确不纳入项与理由；D1–D5 待拍板 |
| 2026-11-06 | 决策 D1/D2 | D1 定为「先生产化」：`v0.7.0` 锁定 S1–S5 + S9–S11，W3/W5 顺延 `v0.8.0`；D2 定为「复杂度 + 历史 5 条，有效期默认关闭」 |
| 2026-11-06 | S9/S10 合入 | `37f3591`（CI MySQL job + check.sh MySQL 分支）、`27efa70`（`scripts/gen-check.sh` + CI `generated` job）；本地 MySQL 8.4 两条命令真跑通过、gen-check 正反双路径验证通过 |
| 2026-11-06 | S1 合入 | `5e7d140`：`internal/obs` 指标端点（独立回环监听）、`internal/data` 探测实现、`docs/operations.md` §5.1；端到端验证 401 计数与 `{id}` 归一 |
| 2026-11-06 | S4 合入 | `bdcbbd4`：`scripts/bench/` 与 `docs/performance.md`；发现 `max_open_conns: 1` 在 MySQL 下吞掉 3.5–4 倍容量，基准改用独立配置 |
| 2026-11-06 | S5 合入 | `32c7bb6`（权限决策 92 → 20 条 SELECT，`admin` 3.5× 吞吐）、`7c60bde`（修压测脚本会话池与失败断言）、`0922dc1`（`explain.sql` + 索引审计结论：无缺失索引，不加 `012`） |
| 2026-11-06 | S11 合入 | `eaaa6ab`：`e2e-compose` workflow + `scripts/e2e/compose-e2e.sh`；本地实跑 `E2E OK` 并落库证据 |
| 2026-11-06 | S2/S3 合入 | `9a85879`（gRPC `request_id`、慢请求日志、邮件掩码、7 条告警规则）、`f176bdf`（连接池探测测试）；compose 暴露 metrics 端口并纳入 E2E 断言 |
| 2026-11-06 | **v0.7.0 发布** | W1/W2/W4 全部交付，MINOR 发版；发布说明 `docs/releases/release-v0.7.0.md`；W3/W5/W6 留待下一版 |
| 2026-11-06 | **v0.7.1 补丁** | v0.7.0 打标后 `e2e-compose` 首次在真实 Linux runner 运行失败（OIDC 私钥 `0600` + 非 root 用户）；同时移除会误报的镜像时间守卫。发布说明 `docs/releases/release-v0.7.1.md` |
| 2026-11-06 | S6/S7/S8 合入（W3 完成） | 密码策略（`012` 迁移、四处入口共用 `ValidatePassword`、`PASSWORD_POLICY_VIOLATION`）、会话上限与设备治理（`recycled_sessions`）、统一写接口限流（429 + `Retry-After` + `rate_limit_hits_total`）；前端同步规则与设置项 |
| 2026-11-06 | S12 设计交付（W5 待评审） | `docs/design/org-sod-delegation.md`：作用域模型、交集合并规则、6 步判定顺序、越权边界、迁移 `013`、决策矩阵；**未写实现代码**。评审后回到本节展开实现项 |
| 2026-11-06 | **v0.8.0 发布** | W3 全部交付（S6/S7/S8），MINOR 发版，含迁移 `012` 与 3 处默认行为变化；发布说明 `docs/releases/release-v0.8.0.md` |
| 2026-11-06 | S12 评审 + 实现 | 评审 8 条发现（F1/F2 推翻原设计论证与后果描述，F6 砍范围）；实现组织约束 CRUD（迁移 `013`）、约束校验接入组织分配、自授权拦截、委派 context 隔离、成员移除双向级联委派失效 |
| 2026-11-07 | **v0.9.0 发布** | W5 交付（S12）：组织约束 CRUD + 上下文隔离 + 自授权拦截 + 成员移除双向级联，含迁移 `013`；发布说明 `docs/releases/release-v0.9.0.md` |
| 2026-11-07 | S13 演练完成 | 两个可复现演练脚本（`scripts/dr/`）；实测数字与"能回滚到哪一步"写入 `docs/operations.md` §7；演练中发现 `/healthz` 被当健康判断的缺陷，新增 `/readyz` 并切换 healthcheck |
| 2026-11-07 | S14 按约定归档 N/A | 决策 D4 未提供真实 OAuth 凭据与 HTTPS 回调域名，四项验收保留未勾选并标注 N/A，不虚构验收记录 |
