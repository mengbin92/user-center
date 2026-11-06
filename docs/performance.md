# 性能基线

> 最近采集：2026-11-06（v0.7.0 W2，含 S5 权限决策修复）· 脚本：[`scripts/bench/`](../scripts/bench/)
>
> 这份文档只描述**这台机器上的**单实例表现。它不是容量承诺，也不能直接外推到生产；
> 它的用途是给后续改动一个可复现的对照点。

## 1. 环境

| 项 | 值 |
|---|---|
| 主机 | Apple M5，16 GB RAM，macOS 27.0.1 |
| Docker VM | 10 CPU / 8 GB（MySQL 容器运行于此） |
| MySQL | 8.4.11（`mysql:8.4`） |
| Go | go1.27.3 darwin/arm64 |
| 压测器 | k6 v2.3.0，**与服务同机** |
| 服务配置 | `scripts/bench/config.mysql.yaml`：`max_open_conns=20`、`max_idle_conns=10`、Redis 未启用（内存回退）、metrics 关闭 |

## 2. 复现

```bash
scripts/bench/run.sh                          # 16 VUs，5 个场景，30s/场景
scripts/bench/run.sh --vu 32 --scenarios me,admin,org
```

索引审计用独立的一次性库，灌 2 万行后再看执行计划：

```bash
docker exec -e MYSQL_PWD=... <container> mysql -uroot -e \
  "DROP DATABASE IF EXISTS usercenter_explain; CREATE DATABASE usercenter_explain;"
DB_DSN='root:...@tcp(127.0.0.1:3307)/usercenter_explain?...' go run ./cmd/migrate -config scripts/bench/config.mysql.yaml
docker exec -i -e MYSQL_PWD=... <container> mysql -uroot --force usercenter_explain < scripts/bench/explain.sql
```

## 3. 主基线（16 VUs）

| 场景 | VUs | 时长 | 请求数 | QPS | P50 (ms) | P95 (ms) | P99 (ms) | 失败率 |
|---|---|---|---|---|---|---|---|---|
| `context`（未认证） | 8 | 20s | 115,639 | 5,782 | 1.23 | 1.87 | 3.18 | 0% |
| `me`（授权投影） | 16 | 30s | 22,411 | 747 | 20.82 | 25.81 | 29.86 | 0% |
| `admin`（用户列表） | 16 | 30s | 18,657 | 622 | 25.03 | 31.09 | 35.83 | 0% |
| `org`（成员列表） | 16 | 30s | 27,427 | 914 | 17.04 | 21.19 | 25.20 | 0% |
| `login`（限流中） | 8 | 20s | 195,168 | 9,758 | 0.88 | 1.82 | 2.28 | 50%（429） |

`login` 的 50% 失败率是预期：该场景每轮发一次登录，几秒内就打满 `30 次/5 分钟/IP`
的硬限流，之后的请求全部 429。这个数字说明的是**限流器本身很便宜**（9,758 req/s 含一半拒绝），
**不是**登录吞吐能力。

## 4. 并发梯度

| VUs | `me` QPS / P95 | `admin` QPS / P95 | `org` QPS / P95 |
|---|---|---|---|
| 8 | 564 / 16.2 ms | 472 / 19.3 ms | 692 / 13.3 ms |
| 16 | 747 / 25.8 ms | 622 / 31.1 ms | 914 / 21.2 ms |
| 24 | 768 / 37.8 ms | 608 / 47.1 ms | 953 / 30.6 ms |
| 32 | 828 / 48.4 ms | 663 / 58.2 ms | 1,037 / 38.4 ms |

读法：

- 三个场景到 32 VUs 都还在缓慢上升，**没有出现陡壁**；`org` 最快（1,037 QPS），
  `admin` 与 `me` 在 600–830 QPS 区间。
- 延迟随并发线性增长而不是指数增长，说明瓶颈是"单请求固定成本 × 并发"，
  不是锁竞争或队列堆积。
- 同机压测的波动可达 20%（压测器与被测服务抢同一颗 CPU）。判断趋势看 8/16/32 三点，
  不要单独引用某一个 VU 的数字。

## 5. 发现一：`max_open_conns: 1` 吃掉 3.5–4 倍容量

`configs/config.dev.yaml` 里 `max_open_conns: 1`（SQLite 必须如此）被最初几轮基线直接继承，
于是所有请求串行在**一个** MySQL 连接上。表现很有迷惑性：QPS 从 2 VUs 就不再增长，
延迟随 VUs 线性上升，看起来像"数据库慢"，实际是连接池只有一个。

同一台机器、同一条命令，只换配置：

| 场景 | 池 = 1 | 池 = 20 | 提升 |
|---|---|---|---|
| `context` | 2,226 QPS / 7.63 ms | 5,782 QPS / 1.87 ms | 2.6× |
| `me` | 206 QPS / 111.8 ms | 788 QPS / 29.1 ms | 3.8× |
| `admin` | 47 QPS / 485.7 ms | 176 QPS / 111.1 ms | 3.7× |
| `org` | 296 QPS / 80.0 ms | 878 QPS / 24.0 ms | 3.0× |

因此基准使用独立的 [`scripts/bench/config.mysql.yaml`](../scripts/bench/config.mysql.yaml)，
不修改 dev 配置。**部署到 MySQL 时若沿用 SQLite 的连接池设置，容量会少约四分之三。**

## 6. 发现二：权限决策的重复查询（S5 修复）

用 `general_log` 抓单次 `GET /api/v1/admin/users?page_size=20`，发现它执行了
**92 条 prepared statement**，其中 `SELECT * FROM iam_permissions WHERE code = ?`
被逐行逐操作重复查询约 70 次，政策快照（角色、授权、继承、约束、策略版本）被完整加载 **4 次**。

原因在 `biz` 层：

| 位置 | 问题 |
|---|---|
| `decideWithFacts` | 每次决策都重新解析操作定义（查 `iam_permissions`），20 行 × 2 个操作 = 40 次 |
| `listUserFilter` → `ListScope` | 自己加载一次快照 |
| `listUserFilter` 的 deny 扫描 | 又加载一次快照 |
| `listUserFilter` 的 contact 决策 | 走 `Decide`，第三次加载快照 |
| `ListUsers` | 第四次加载快照 |

修复（保持语义不变，只消除重复读）：

1. `AuthzFacts` 增加每请求的操作定义缓存，`decideWithFacts` 通过它解析，未命中才查库。
2. `ListScope` 拆出 `scopeWithFacts`，`listUserFilter` 只加载一次快照并**把它返回给调用方**，
   `ListUsers` 复用同一份，不再重复加载。

`AuthzFacts` 仍然是"一次请求的授权事实"，不跨请求复用，policy revision 语义不变。

结果：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 单请求 SELECT 数 | ≈92 | **20.03**（`Com_select` 增量 ÷ 请求数实测） |
| `admin` 16 VUs QPS | 176 | **622**（3.5×） |
| `admin` 16 VUs P95 | 111.1 ms | **31.1 ms**（3.6×） |
| `admin` 8 VUs QPS | 150 | 472 |
| `admin` 32 VUs QPS | 190 | 663 |
| `me` P95 | 29.1 ms | 25.8 ms |
| `org` P95 | 24.0 ms | 21.2 ms |

`admin` 从"最先触顶的端点"变成了与 `me` 同量级。剩余的 20 次查询里，
会话校验（6 读 1 写）与政策快照（7 读）是每请求固定成本，再往下压需要跨请求缓存，
不属于本阶段范围。

## 7. 索引审计（2 万行数据集）

`scripts/bench/explain.sql` 灌 2 万用户、2 万凭据、2 万会话、2 万会话角色、2 万授权、
2 万 MFA 记录，然后对**请求实际发出的每条查询**跑 `EXPLAIN`：

| 查询 | type | key | rows | 判定 |
|---|---|---|---|---|
| `users` count | index | `idx_users_created_id` | 19,929 | ✅ 覆盖索引，非全表 |
| `users` 分页（order by created_at desc, id desc） | index | `idx_users_created_id` | 20 | ✅ Backward index scan，无 filesort |
| `users` 按状态分页 | index | `idx_users_created_id` | 40 | ✅ 无 filesort |
| `users` 按 id 集合分页（受限 scope） | range | PRIMARY | 50 | ⚠️ 有 `Using filesort` |
| `users` 关键字搜索 | **ALL** | — | **19,929** | ❌ 全表扫 |
| 会话按凭据哈希 | const | `uk_sessions_credential_hash` | 1 | ✅ 唯一索引 |
| 会话角色 | ref | PRIMARY | 1 | ✅ |
| 单用户角色 | ref | `idx_iam_user_roles_user` | 1 | ✅ |
| 批量用户角色 | range | `idx_iam_user_roles_user` | 20 | ✅ index condition pushdown |
| 批量 MFA 状态 | range | PRIMARY | 20 | ✅ |
| 权限按 code | const | `uk_iam_permissions_code` | 1 | ✅ |
| 约束全读 | index | PRIMARY | 1 | ✅ |

**结论：没有缺失索引，本阶段不新增迁移。** 为了"有产出"而加索引只会增加写放大的代价。

两个已知限制（不是索引缺失，改索引解决不了）：

1. **关键字搜索全表扫**。`LOWER(username) LIKE '%kw%'` 的前导通配符让任何 B-tree 索引失效，
   2 万行时约 10 ms，10 万行后会成为管理端最慢的操作。可选方向：改成前缀匹配（`kw%`，可用索引）、
   生成列 + 索引（同样只能前缀）、或 MySQL 全文索引（中文需要 ngram 解析器）。这是语义变更，
   需要产品确认，故记为待办而不是现状修复。
2. **受限 scope 分页有 filesort**。`WHERE id IN (...) ORDER BY created_at DESC` 时优化器改用主键
   range + 排序。排序集是 scope 内的 id（通常几十到几百），开销可控；全量 scope 走的是
   `idx_users_created_id`，不受影响。

## 8. 大表增长与清理策略

审计期间确认：`iam_sessions`（过期后）、`iam_audit_events`、`event_outbox`、`event_deliveries`
**都没有定期清理**，只有 R14 的个人数据匿名化会动 `users`。增长估算（单实例、日活 1 万）：

| 表 | 增长来源 | 估算（年） | 现状 |
|---|---|---|---|
| `iam_sessions` | 每次登录一行，撤销/过期后不删 | ≈365 万行 | 无清理 |
| `iam_audit_events` | 所有敏感写入 | ≈100 万行（取决于管理操作量） | 无清理，且审计按设计不可变 |
| `event_outbox` | 每次域事件 | 与审计同量级 | 无清理 |
| `event_deliveries` | 每个事件 × 订阅方 | 上表的 1–N 倍 | 无清理 |

建议策略（**尚未实现**，需要与合规/运维确认保留期后再做）：

- `iam_sessions`：`expires_at` 早于 30 天且 `revoked_at` 非空的记录可删。删除前确认没有
  正在排障的会话取证需求。收益最大、风险最低，建议先做。
- `iam_audit_events`：不做原地删除。按 `created_at` 分区或定期导出 CSV 归档后删除整分区；
  保留期取决于合规合同。注意审计不可变是产品承诺，删除必须是"归档"而不是"丢掉"。
- `event_outbox` / `event_deliveries`：`delivered` 状态且 `created_at` 早于 30 天的可删；
  `retrying` 的记录必须保留，否则会丢失重试。

为什么现在不做：这些都是删除操作且不可逆，保留期需要法务/运维输入；同时缺少"删除前的
行数水位与告警"——在可观测性补齐之前删数据，出问题无法复盘。已记录为后续里程碑待办。

## 9. 单实例安全水位

以 P95 < 100 ms 为界（内部管理面目标），当前（S5 修复后）：

| 场景 | 安全水位 | 说明 |
|---|---|---|
| `org` | ≥ 1,037 QPS / 32 VUs | 未饱和，仍在上升 |
| `me` | ≈ 828 QPS / 32 VUs | 延迟随并发线性增长，无陡壁 |
| `admin` | ≈ 663 QPS / 32 VUs | 与 `me` 同量级，不再是瓶颈 |

扩容判据：

1. 目前单实例在 32 VUs 下三个场景 P95 均 < 60 ms，**距离 300 ms 延迟线还有 5 倍余量**，
   横向扩容没有收益。
2. 若未来要提吞吐，优先顺序是：会话校验的政策快照缓存（跨请求、按 policy revision 失效）
   → 关键字搜索方案 → 连接池与 MySQL 参数调优。
3. 真正需要扩容的信号是 P95 超过 100 ms 且 QPS 已不再随 VUs 增长，而不是 CPU 使用率。

## 10. 偏差：读数字前必看

1. **压测器与服务同机**：k6 和被测服务争抢同一颗 CPU 与回环网络，绝对 QPS 偏低。
2. **基准账号是 root**：`admin-rescue bootstrap` 只能造 root，每次请求都要展开完整权限集，
   `me` / `admin` 的数字是**权限计算的最坏情况**，普通 `member` 账号会更低。
3. **会话池 24 个**：VU 超过 24 时部分 VU 共享会话（32 VUs 有 8 个共享），
   这些请求会在 `iam_sessions` 的同一行上串行更新，数字偏悲观。
4. **MySQL 未调优**：容器默认参数（`innodb_buffer_pool_size` 等）未调整，生产会配不同参数。
5. **无 Redis**：走内存回退，会话校验的缓存命中路径没被覆盖；生产有 Redis 时 `me` 应更快。
6. **数据量小**：压测库只有 24 个用户。索引审计单独用 2 万行的库验证，但延迟数字仍来自小数据集。

## 11. 待办

| 项 | 来源 | 状态 |
|---|---|---|
| 关键字搜索全表扫 | §7 | 待产品确认语义（前缀 / 全文） |
| 受限 scope 分页 filesort | §7 | 可接受，scope 通常很小 |
| 跨请求的政策快照缓存 | §6 | 需要按 policy revision 失效，风险高于本阶段 |
| 大表清理与分区 | §8 | 待合规确认保留期 |
| 普通 member 账号基线 | §10 | 需要新夹具（当前只能造 root） |
