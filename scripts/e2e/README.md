# E2E 冒烟

`smoke.sh` 是 v0.5.1 Docker E2E 的正式收纳版本，用于本地 compose 或开发实例。
`compose-e2e.sh` 则把「构建镜像 → 起栈 → 夹具 → 冒烟 → 落库证据」整条链路包成一个可重复的脚本，
CI 的 `e2e-compose` workflow 调用的就是它（本地与 CI 执行同一份逻辑）。

```bash
# 整条 compose 链路（构建 + 起栈 + 冒烟 + 证据），失败时自动收集日志
scripts/e2e/compose-e2e.sh --work-dir /tmp/uc-compose-e2e

# 只重跑冒烟，复用已起的栈
scripts/e2e/compose-e2e.sh --skip-build --keep
```

`compose-e2e.sh` 默认在结束时 `down -v`；`--keep` 保留栈便于排查。它不接受复用的 `.env`，
每次都生成一次性密钥与 OIDC 私钥。

```bash
# 开发实例（SQLite）
SMOKE_USER=root SMOKE_PASSWORD='ChangeMe-12345' scripts/e2e/smoke.sh

# compose 实例
SMOKE_USER=root SMOKE_PASSWORD='ChangeMe-12345' \
  scripts/e2e/smoke.sh --base-url http://127.0.0.1:8080 \
  --compose deployments/docker-compose/docker-compose.yml \
  --compose-env /path/to/compose.env
```

- `--base-url`：目标实例；默认 `http://127.0.0.1:8080`。
- `--snapshot-dir`：失败快照目录；默认 `artifacts/e2e-fail-<时间戳>/`，包含失败步骤、最后一次响应体/头、Cookie，指定 `--compose` 时还会附上 `docker compose logs`。
- `--compose` / `--compose-env`：失败时抓取容器日志。compose 文件对密钥用了 `:?` 强制校验，因此必须同时给 env 文件，否则连 `logs` 都无法解析。
- `--keep`：成功时保留临时请求文件；默认自动清理，不依赖临时目录残留。
- 需要的账号是**未启用 MFA 的密码账号**（Step-up 走密码重验路径）。

## compose 预热（一次性夹具）

冒烟账号不会被脚本创建，compose 环境需要先准备好：

```bash
# 1) 引导 root（容器内官方恢复工具，写审计）
docker compose --env-file compose.env -f deployments/docker-compose/docker-compose.yml \
  exec -T user-center /app/admin-rescue -action bootstrap \
  -username root -email root@example.com -password 'ChangeMe-12345'

# 2) 平台默认要求管理员启用 MFA；冒烟账号是密码账号，需要显式关闭该策略
docker compose --env-file compose.env -f deployments/docker-compose/docker-compose.yml \
  exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter \
  -e "INSERT INTO auth_settings (name,value,revision,updated_at) VALUES ('auth','{\"MFARequiredForAdmins\":false}',1,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE value=VALUES(value);"
```

> 第 2 步只是把「管理员必须启用 MFA」这一策略显式关掉，属于测试夹具；MFA 登录链路本身由 `go test` 中的 TOTP/WebAuthn 用例覆盖。

覆盖：健康检查、未登录 401、CSRF、登录、`/me` 与授权投影、OIDC 同意/WebAuthn 列表、discovery `end_session_endpoint`、Step-up、组织创建与租户审计/邀请/explain、跨租户未知组织 404、配额与 provider 配置视图、登出后会话失效。

`scripts/smoke.sh` 保留为兼容入口，转发到本脚本。
