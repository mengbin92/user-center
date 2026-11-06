# 负载基线（bench）

单实例、MySQL 8.4、本机回环下的可复现基线。产物是 `docs/performance.md` 的数值来源，
不是容量承诺：同一份脚本在不同机器上会给出不同绝对值，只有同一台机器上的前后对比才可比。

## 一条命令

```bash
scripts/bench/run.sh                     # 16 VUs, 30s/场景, 5 个场景
scripts/bench/run.sh --vu 32 --duration 60s --scenarios me,admin
```

脚本按顺序做这些事：起（或复用）`mysql:8.4` 容器 → 迁移 → 关闭管理员强制 MFA（仅这个
一次性库）→ bootstrap 24 个 `benchNN` 账号 → 起服务 → 建会话池与组织 → 逐场景跑 k6 →
打印 markdown 表。退出时一定停掉服务进程；MySQL 容器保留以便下次跳过冷启动。

依赖：`docker`、`k6`、`go`、`python3`、`openssl`。

## 场景

| 场景 | 请求 | 说明 |
|---|---|---|
| `context` | `GET /api/v1/auth/context` | 未认证基线：CSRF Cookie 下发 + 中间件开销，不查库 |
| `me` | `GET /api/v1/me/authorization` | 会话校验 + 权限投影（每次请求 6 读 1 写） |
| `admin` | `GET /api/v1/admin/users?page_size=20` | 管理端列表 + 数据范围计算，最重 |
| `org` | `GET /api/v1/orgs/{id}/members` | 租户上下文 + 成员列表 |
| `login` | `GET /auth/context` + `POST /auth/login` | **不是吞吐场景**，见下 |

## 四个必须知道的偏差

1. **登录无法测吞吐**。`login:<ip>` 是 30 次/5 分钟硬编码，`login-user` 是 10 次失败/5 分钟，
   都不可配置。`login` 场景因此只回答两个问题：被限流后的响应成本，以及限流器本身的开销。
   它会让 `http_req_failed` 接近 50%，因为 429 被 k6 计为失败，这是预期结果。
2. **会话池上限 28**。建池本身要登录，超过 30 就会撞限流，脚本直接拒绝更大的 `--accounts`。
   池在 `artifacts/.bench-cache/` 里缓存 **30 分钟**（服务空闲超时的一半），重复跑不会重新登录；
   超期后脚本会重建，否则场景会静默变成一片 401。读场景一旦出现失败，脚本直接报错退出，
   不会把失效会话的数字当成基线。
3. **基准账号是 root**。`admin-rescue bootstrap` 只能造 root 账号，而 root 拥有全部权限，
   每次请求都要展开完整权限集。`me` / `admin` 的数字是**权限计算的最坏情况**，普通 `member`
   账号会明显更低。要测普通账号需要另造夹具，目前没做。
4. **压测器与服务同机**。k6 和服务争抢同一颗 CPU 与回环网络，绝对 QPS 偏低；
   跨机压测才能得到生产可用的数字。这里的一切结论都以"同一台机器上的相对变化"为准。

## 结果怎么看

每个场景一行：`QPS` 是完成的请求数除以时长，`P50/P95/P99` 是服务端响应时间（含 k6 排队），
`失败率` 除 `login` 外应为 0。跑完在 `artifacts/bench-<stamp>/summary.md` 留一份，
`<scenario>.json` 是原始数据，`<scenario>.log` 是 k6 完整输出。

## 索引审计

`explain.sql` 灌 2 万行夹具并对请求实际发出的每条查询跑 `EXPLAIN`。它需要独立的一次性库，
因为 24 行数据下优化器会用全表扫掩盖缺失索引：

```bash
docker exec -e MYSQL_PWD=... <container> mysql -uroot -e \
  "DROP DATABASE IF EXISTS usercenter_explain; CREATE DATABASE usercenter_explain;"
DB_DSN='root:...@tcp(127.0.0.1:3307)/usercenter_explain?parseTime=true&loc=UTC&charset=utf8mb4' \
  SESSION_SECRET=... CSRF_SECRET=... MFA_ENCRYPTION_KEY=... \
  go run ./cmd/migrate -config scripts/bench/config.mysql.yaml
docker exec -i -e MYSQL_PWD=... <container> mysql -uroot --force usercenter_explain < scripts/bench/explain.sql
```

脚本会先 `TRUNCATE` 再灌，可以重复执行。结论记录在
[`docs/performance.md` §7](../../docs/performance.md)。

## 清理

```bash
docker rm -f uc-bench-mysql      # 删除基准数据库
rm -rf artifacts/.bench-cache    # 丢弃缓存的会话池（下次会重新登录）
```
