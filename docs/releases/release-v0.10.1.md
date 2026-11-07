# v0.10.1 · 2026-11-07

上一版：[v0.10.0](./release-v0.10.0.md) · 触发：本地 Docker 全栈服务验证

**版本判定：PATCH（v0.10.0 → v0.10.1）。** 修复一个指标可观测性缺陷：限流命中计数器在冷启动时没有任何时间序列。无新增端点、无行为变更、无数据库迁移、无配置变更。

## Fixed

### `usercenter_rate_limit_hits_total` 冷启动无序列

Prometheus 的 `CounterVec` 只有在对该 label 调用过 `WithLabelValues` 之后才会物化时间序列。此前 `RateLimited(scope)` 是唯一的写入点，所以一个从未拒绝过请求的进程在 `/metrics` 里**完全没有** `usercenter_rate_limit_hits_total`——不是 0，是「不存在」。由此产生两个具体问题：

- `rate()` / `increase()` 得到空向量而非 0，任何基于增长率的规则都拿不到数据；
- `absent(usercenter_rate_limit_hits_total)` 会对一台完全健康的实例触发告警。

而 `docs/operations.md` §5.1.1 原文写「看到 `rate_limit_hits_total` 突然为 0 且流量正常，要怀疑限流器是否在工作」——这个观察在修复前根本不可能发生。

修复：`NewMetrics` 在注册时对四个 scope（`write` / `export` / `batch` / `invite`）以 `Add(0)` 预置，与既有 `usercenter_dependency_up` 的 seeding 方式一致。scope 名称提取为 `internal/obs` 的导出常量，`internal/server/ratelimit.go` 改为引用，使「预初始化列表」和「实际写入方」不可能各自漂移。

### 文档修正

- `docs/operations.md` §5.1.1 改为准确表述，并给出可用的告警表达式：

  ```promql
  sum by (scope) (increase(usercenter_rate_limit_hits_total[5m])) > 100
  ```

  明确警告**不要用 `absent()`** 判断限流器是否工作（序列现在恒存在，该检查永不触发）；要确认限流器生效，用演练记录里的超预算请求法观察 429 与计数是否同步增长。
- 指标表补注零值预置；「三条运维要点」修正为四条。
- `scripts/e2e/README.md` 补充一个实测踩到的坑：`compose-e2e.sh` 与 `--keep` 保留的栈共用默认项目名 `docker-compose`，第二次执行会复用旧容器却换上新 `.env`，MySQL 密码不匹配导致 `migrate` 以 exit 1 失败。先 `down -v` 清理，或用 `COMPOSE_PROJECT_NAME` 区分。

**未新增 `alerts.yml` 规则**：拒绝率阈值缺生产基线，凭空加一条 page 告警只会制造噪音。表达式已给在文档里，有基线后再落地。

## 升级注意

无需停机、无需执行迁移。升级后 `/metrics` 会多出最多 4 条值为 0 的时间序列，属预期变化：

```text
usercenter_rate_limit_hits_total{scope="batch"} 0
usercenter_rate_limit_hits_total{scope="export"} 0
usercenter_rate_limit_hits_total{scope="invite"} 0
usercenter_rate_limit_hits_total{scope="write"} 0
```

如果现有面板或告警用了 `absent()`，升级后需改为基于 `increase()` 的表达式。已有的 `rate()` 面板则从「空」变成「0」，这是修复目标。

## 验证

| 项 | 结果 |
|---|---|
| 本地 Docker 全栈（4 服务） | ✅ mysql/redis/user-center healthy，migrate Exited(0)；39 表 / 64 迁移；非 root 运行；日志 0 panic/error |
| 修复前复现 | 冷启动 `/metrics` 无任何 `rate_limit_hits_total` 行 |
| 修复后冷启动实测 | ✅ 0 次 429 时四个 scope 全为 `0` |
| 触发后实测 | ✅ 强制 5 次 429 → `write=5`，其余三个仍为 `0` |
| 全栈端点 | ✅ 探针、SPA 静态资源、11 个业务 API、7 个指标族、gRPC 鉴权拒绝、限流第 121 次起 429、故障注入 `DROP DATABASE` 后 `/readyz` 503 与自愈 |
| `go test ./...` | ✅ 8 包全绿（新增 2 条指标测试） |
| `gofmt` / `go vet` / `scripts/gen-check.sh` / 文档链接 | ✅ 干净 |
| compose 全栈 E2E | ✅ `== pass`，`schema_migrations_applied 64`，0 条 5xx |

## 已知限制

- 本版仍未新增限流告警规则（缺生产基线）。
- S14 真实 OAuth 沙箱验收仍为 **N/A**（决策 D4 未提供凭据与 HTTPS 回调域名），见 `docs/security.md` §4 第 1 条。
