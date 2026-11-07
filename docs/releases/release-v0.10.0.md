# v0.10.0 · 2026-11-07

上一版：[v0.9.0](./release-v0.9.0.md) · 范围：[V2.5 路线图](../roadmap-v2.5.md) W6（S13、S14）

**版本判定：MINOR（v0.9.0 → v0.10.0）。** 新增对外端点 `/readyz`，变更容器 healthcheck 目标与数据库探针语义，新增两个可复现的灾难恢复演练脚本。**无数据库迁移**，无破坏性契约变更。

> ⚠️ **与 V2.5 路线图原计划的偏差**：§5 原写 W6「跟随 `v0.8.0` 文档更新，不单独占版本号」，前提是 W6 只有文档。实际执行 S13 演练时揪出了一个必须修的运行时缺陷（数据库不可用时容器仍报 healthy），因此本版包含运行时代码与一个新增的对外端点。按"新增对外能力即 MINOR"判定，单独发版。路线图 §5 已同步回填这一偏差。

主题不是"加功能"，而是**把"照文档能救回来"从一句假设变成可执行、可复验的资产**。演练过程中有 5 处"看起来在检查、其实空转"，逐一修掉。

## Added

### 就绪探针 `/readyz`

- `GET /readyz`：必需检查 MySQL，不可达时返回 **503** 并附具体错误；Redis 状态仅在响应里报告，不影响就绪判定。返回 `{"status":"ok","checks":{"mysql":"ok","redis":"ok"}}`。
- `GET /healthz` 保持为**纯存活探针**（静态 200，不查任何依赖）。两者职责分离：`healthz` 回答"要不要重启"，`readyz` 回答"要不要给流量"。
- `deployments/docker-compose/docker-compose.yml` 的 healthcheck 改指 `/readyz`，并加 `start_period: 30s`（冷启动或恢复期间不应被判为不健康）。
- 镜像名参数化为 `${USER_CENTER_IMAGE:-user-center:latest}`。回退版本不再需要改清单文件——改文件会让部署清单偏离实际运行的东西，且下次 `git pull` 会被覆盖。
- `scripts/e2e/smoke.sh` 默认断言 `/readyz`；新增显式 `--skip-readyz`，仅用于演练中运行 S13 之前发布的旧版本。

### 灾难恢复演练脚本（`scripts/dr/`）

- `restore-drill.sh`：起完整 compose 栈 → 写入真实业务数据 → `mysqldump` → `DROP DATABASE` → 恢复 → 断言 10 张表的行数与 `MAX(id)` → 恢复后跑 `smoke.sh`。同时断言故障期间 `/readyz` 失败而 `/healthz` 仍为 200。
- `upgrade-rollback-drill.sh`：构建 v0.6.1 旧栈 → 备份 → 升级到当前版本 → 校验 → 恢复备份库并起旧镜像 → 校验。不可逆 DDL 由脚本从迁移文件自动扫描，不写死清单。
- `compare_fingerprint.py` 提供 `strict`（恢复，逐表相等）与 `no-loss`（升级，允许演练自身写入使计数增长）两种口径；`lib.sh` 统一环境、指纹与等待逻辑。

### 文档与测试

- `docs/operations.md` §5 区分存活/就绪探针；§7 补齐备份恢复、演练记录与「能回滚到哪一步」；§10 明确"迁移先于代码"的顺序。
- [S13 演练记录](./drill-2026-11-07-s13.md) 保存实测数字与 5 条发现。
- `configs/config.docker.yaml` 补 OAuth 环境变量与 HTTPS 回调地址说明（与 `internal/biz/oauth.go` 的实际路径一致）。
- 新增测试：`internal/obs/ready_test.go` 3 条（数据库故障 / 仅缓存故障 / 无探针）、`internal/server/probe_test.go` 3 条（职责分离、无需鉴权）。

## Changed

- **`Data.PingDatabase` 从 `PingContext` 改为真实查询 `SELECT COUNT(*) FROM schema_migrations`**。`COM_PING` 只证明 TCP 连接活着，库被删了照样应答；这同时让 `usercenter_dependency_up{dependency="mysql"}` 指标变得可信。
- `wait_ready` 校验响应体含 `"status":"ok"`，而非只看状态码；对 S13 之前的版本改用 `wait_legacy_ready`（`/healthz` + 真实 SQL 查询）。
- 路线图 W6 波次行、D3/D4 决策状态、W5 版本行回填；删掉过时的「W3 可降 v0.7.1」假设。

## Fixed

- **`DROP DATABASE` 后容器仍报 healthy**：`/healthz` 是静态 200，却被用作容器 healthcheck。数据库不可用时编排器会把流量继续打给一个连不上的实例。
- **初版 `/readyz` 仍是假绿**：依赖探针走 `COM_PING`，空库也返回成功。
- **旧版本 SPA fallback 假绿**：S13 之前的版本对未知路径返回 200 + `index.html`，按状态码判断的就绪轮询会被蒙混过去。
- 演练脚本自身两处口径错误：升级后按"完全相等"比对数据（冒烟会写入数据，应为"无丢失"）；fingerprint 漏掉一张表（写成了不存在的 `iam_oauth_identities`）。

## 演练实测结论（写入运维手册）

**备份恢复**（空库 + 1 组织 / 1 用户 / 2 审计 / 2 Outbox，用于验证流程而非容量）：

| 步骤 | 实测 |
|---|---|
| `mysqldump` | 67 KB / 150–200 ms |
| `DROP DATABASE` + 重建（39 张表） | 341–371 ms |
| 导入恢复 | 366–637 ms |
| 服务自愈（**未重启容器**） | 831–1,392 ms |
| 恢复后 smoke | 通过 / 775–1,144 ms |
| 数据一致性 | 10 张表行数 + 自增高水位逐表一致 |

**升级回滚**（v0.6.1 → 当前 → 回滚）：58 → 64 迁移步 / 341–352 ms；回滚 1,081–1,243 ms（其中数据库恢复 766–803 ms）；8 张表逐表一致且两次 smoke 通过。当前仅 1 处不可逆 DDL（`006_org_iam.sql` 的 `DROP INDEX`）。

数值是本机 3 次执行的区间，几乎全是固定开销，**不能外推到生产数据量**。要估真实 RTO 请用 `scripts/bench` 的规模数据重跑脚本。

三条此前没有写进任何文档的运维事实：

1. **恢复会带回会话**。会话存在 MySQL，备份时刻有效的会话（包括之后被撤销的）会复活；Redis 里的挑战、step-up、限流计数不备份且自然重建。因安全事件回滚后必须显式撤销会话，不能假设"恢复 = 踢下线"。
2. **只回退镜像、不恢复数据库是静默丢数据**。旧二进制能启动、能登录、能过 smoke（012/013 新增列都是 `NULL` 或带 `DEFAULT`），但实测改密码返回 200 却不写 `password_history`、不更新 `password_changed_at` —— 密码复用检测在回退窗口内失效，组织 SoD 新表在旧版视角下也全部暂停。**唯一无条件安全的路径是：旧镜像 + 恢复升级前备份库 + 清单一并回退**。项目不提供 down 迁移。
3. **回退到没有 `/readyz` 的旧版本时**，当前 compose 的 healthcheck 会被旧版 SPA fallback 的 200 蒙混成 healthy。这是"旧镜像 + 新清单"的固有代价，不单独给旧版打补丁。

## 升级注意

1. **无迁移**，无需停机执行 DDL。
2. **容器 healthcheck 已改指 `/readyz`**。若外部编排器（Kubernetes、Nginx、云负载均衡）仍把探针指向 `/healthz`，请一并改为 `/readyz`；否则数据库故障时本版的修复不会生效。**存活探针仍应指向 `/healthz`** —— 存活探针查依赖会造成重启循环，且会把诊断日志冲掉。
3. **`/readyz` 不需要鉴权与 CSRF**，是公开端点；不要把它挂到公网反代之外暴露内部错误信息（当前仅返回驱动错误文本，不含凭据或 SQL 细节）。
4. **回退**：把 `USER_CENTER_IMAGE` 指回上一版镜像，并恢复升级前备份；不要只换镜像。详见 `docs/operations.md` §7.3。
5. Redis 故障不会导致 `/readyz` 返回 503：限流与 step-up 按既定 fail-open 语义降级，认证仍可用。若希望缓存故障也摘流量，需要在编排层另加判断。

## 验证

| 项 | 结果 |
|---|---|
| `go test ./...` | 8 个包全绿 |
| `gofmt` / `go vet` / `scripts/gen-check.sh` / 文档链接 | 干净 |
| compose 全栈 E2E | `== pass`，`schema_migrations_applied 64`，0 条 5xx |
| 两个演练脚本 | 各自 `DRILL OK`，各执行 3 次 |
| 前端 | 本版未改动前端代码；沿用 v0.9.0 的 `tsc -b` + 17 文件 / 62 用例 |

## S14 状态：N/A，未勾选

真实 GitHub / Google 沙箱验收**未执行**。决策 D4 未提供凭据与 HTTPS 回调域名，四项验收在路线图中保留未勾选并标注 N/A，**未创建** `docs/acceptance-oauth-*.md`（没有内容可记，不虚构）。`docs/security.md` §4 第 1 条仍保留该已知限制。凭据到位后需另开一轮补做；`configs/config.docker.yaml` 已写明所需环境变量与回调地址。

## 已知限制

- 演练数据规模很小，耗时不能作为生产 RTO 基线。
- 回退到 S13 之前的版本时，新清单的 healthcheck 会假绿（见上）。
- S14 真实 OAuth 验收仍待 D4。

## 下一版

V2.5 路线图的 W1–W6 已全部交付（S14 按约定归档 N/A）。后续方向由下一轮规划确定：SCIM / 目录同步、跨租户 SoD 模型、审计归档与分区、以及 S14 在凭据到位后的补做。
