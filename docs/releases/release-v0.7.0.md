# v0.7.0 · 2026-11-06

上一版：[v0.6.1](./release-v0.6.1.md) · 范围：[V2.5 路线图](../roadmap-v2.5.md) W1 / W2 / W4

**版本判定：MINOR（v0.6.1 → v0.7.0）。** 新增可观测性能力、负载基线与工程门禁；无数据库迁移、无破坏性契约变更。默认行为保持兼容：指标只绑回环、日志只在慢请求时新增字段、认证加固留给 `v0.8.0`。

主题是**生产化基座**。v0.6.1 之后功能面已无未开工项，缺的是"能不能放心上生产"这一层：看不见（无可观测性）、说不清（无容量数据）、守不住（门禁不全）。

## 新增

### 指标端点

- 独立监听，默认 `127.0.0.1:9091`，`METRICS_ADDR=off` 关闭；不挂 `/api/v1`、不需要会话。
- `usercenter_http_requests_total{route,method,status}`、`usercenter_http_request_duration_seconds{route,method}`：路由标签是**模板**（`/api/v1/orgs/{id}/members`），非 API 路径统一记为 `spa`，标签基数由路由表决定而不是由用户输入决定。
- `usercenter_event_deliveries{status}`、`usercenter_schema_migrations_applied`、`usercenter_dependency_up{dependency}`、`usercenter_db_pool_connections{state}`、`usercenter_db_pool_wait_total`。
- 指标中间件放在认证过滤器**外层**：放在 router 层会漏掉全部 401/403 短路，错误率面板会系统性少报。
- compose 把 `METRICS_ADDR` 设为 `0.0.0.0:9091` 并把端口发布在宿主机回环；`compose-e2e` 会断言该端点从宿主机可抓取。

### SLO 与告警

- [`deployments/prometheus/alerts.yml`](../../deployments/prometheus/alerts.yml) 7 条规则，`promtool check rules` 通过：5xx 比例、P95 延迟、登录失败激增、Outbox 积压、依赖不可用、连接池耗尽、迁移未应用。
- 每条规则带 `first_step` 注解；运维手册 §5.2 给出 SLO 目标、触发条件、影响面与首步排查动作。
- 两处会静默失效的写法已规避：连接池比值需要 `ignoring(state)`（否则默认一对一匹配返回空向量，告警永不触发）；迁移规则只对 MySQL 启用（SQLite 走 AutoMigrate，该值恒为 0）。

### 日志与链路

- 慢请求日志（`SLOW_REQUEST_THRESHOLD_MS`，默认 500ms）记录 `request_id`、路由模板、方法、状态、耗时；**不记录** 请求体、请求头、查询串与 Cookie。
- gRPC 补上 `request_id` 注入（此前内部 API 写入的审计行该字段为空），并通过响应头回写；HTTP 与 gRPC 规则一致（缺省生成、超长替换而非截断）。
- 邮件日志把收件人掩码为 `a***@example.com`；含 CR/LF 的地址直接拒绝，不以防脱敏形式回显。

### 负载基线与索引审计

- `scripts/bench/`：一条命令起 MySQL 8.4、迁移、建 24 个账号、起服务、跑 5 个 k6 场景并输出 markdown 表。会话池缓存 30 分钟（登录限流 30 次/5 分钟/IP 是硬上限）。
- `scripts/bench/explain.sql`：灌 2 万行后对真实查询跑 `EXPLAIN`，用来回答"是否缺索引"。
- [`docs/performance.md`](../performance.md)：环境、主基线、并发梯度、安全水位、偏差声明。

### 工程门禁

- CI 新增 `mysql` job：在 `mysql:8.4` service 上应用 001–011 两次（验幂等）并跑 MySQL 仓储测试。
- CI 新增 `generated` job：`make api` / `make config` / `make wire` 后生成物有差异即失败；插件版本与产出这些文件的版本一致。
- 新增 `e2e-compose` workflow（`workflow_dispatch` + `push: main`）：构建镜像、起全栈、跑冒烟、断言落库证据与指标端点，失败上传容器日志与快照。构建步骤校验真实退出码并比对镜像创建时间（v0.6.0 的 `build | tail` 事故）。

## 性能

**权限决策的重复查询**：单次 `GET /api/v1/admin/users?page_size=20` 原先执行 92 条 prepared statement —— `iam_permissions` 被逐行逐操作重查约 70 次，政策快照被完整加载 4 次。

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 单请求 SELECT | ≈92 | 20.03 |
| `admin` 16 VUs QPS | 176 | 622 |
| `admin` 16 VUs P95 | 111 ms | 31 ms |
| `admin` 8 VUs QPS | 150 | 472 |

实现：授权快照增加每请求的操作定义缓存，列表过滤器把快照传给调用方复用。快照仍是每请求的，policy revision 语义不变。

## 数据库与兼容性

- **无迁移**，`migrations/mysql/001–011` 不变。
- 无破坏性 API 变更；`AuthzFacts` 字段调整属内部实现。
- 新增环境变量：`METRICS_ADDR`、`SLOW_REQUEST_THRESHOLD_MS`。
- 依赖：`github.com/prometheus/client_golang v1.25.0`，它要求 `golang.org/x/oauth2 v0.37.0`（MVS，无法保留 v0.36.0）。

## 验证

- `go vet ./...`、`go test ./...`（8 包）、`gofmt -l` 全部通过；`gen-check` 干净。
- 新增测试：指标标签归一化与基数、探测失败保留旧值、慢请求字段白名单与不含请求体、邮件掩码（含 CR/LF）、gRPC request_id 复用与生成、连接池与 Outbox 探测。
- 本地 compose 全栈（MySQL 8.4 + Redis 7 + migrate + 服务）：冒烟 `E2E OK: health, 401 gate, login, self-service, V2.4 discovery, Step-up, tenant boundary, audit, logout`；落库 `organizations=1 / audit_events=2 / outbox_events=2 / sessions=1`；指标端点从宿主机可抓取（`db_pool{state="max"}=20`、`dependency_up{mysql}=1`、`schema_migrations_applied=58`）；容器日志 0 条 5xx。
- 负载基线（MySQL 8.4，16 VUs）：`context` 4,772 QPS、`me` 598 QPS / P95 33.5 ms、`admin` 504 QPS / P95 39.6 ms、`org` 773 QPS / P95 25.6 ms，失败率均为 0。
- `promtool check rules`：`SUCCESS: 7 rules found`。

## 已知限制

- 关键字搜索 `LIKE '%kw%'` 全表扫；需要先定"前缀匹配还是全文检索"，本版不猜。
- 受限 scope 分页有 `filesort`（id 集合通常很小，可接受）。
- 组织成员列表无分页；改它属于 API 契约变更。
- `iam_sessions` / `iam_audit_events` / `event_outbox` / `event_deliveries` 仍无定期清理；保留期需合规输入且删除不可逆，故只记录策略不实现。
- 基准账号是 root（`admin-rescue bootstrap` 只能造 root），`me` / `admin` 数字代表权限计算的**最坏情况**。
- CI 的 `mysql` / `generated` / `e2e-compose` 三个 job 尚未在远端观测到首次运行，本地已等价验证。

## 升级注意

1. compose 部署的 `METRICS_ADDR` 已默认 `0.0.0.0:9091` 并发布在 `127.0.0.1:9091`；不需要采集就设为 `off` 并删除端口映射。
2. 接入告警前先确认 Prometheus 已抓取到 `usercenter_*`，否则规则一直是 `nodata`。
3. 生产 MySQL **不要**沿用 dev 配置的 `max_open_conns: 1`（那是 SQLite 需要的）；实测这一项吞掉约 3.5 倍容量，`UserCenterDBPoolExhausted` 会一直响。
4. v0.6.0 的 W3 波次附记已从 `release-v0.7.0.md` 更名为 [`release-v0.6.0-w3.md`](./release-v0.6.0-w3.md)，旧链接请更新。
