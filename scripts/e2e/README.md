# E2E 冒烟

`smoke.sh` 是 v0.5.1 Docker E2E 的正式收纳版本，用于本地 compose 或开发实例：

```bash
# 开发实例（SQLite）
SMOKE_USER=root SMOKE_PASSWORD='ChangeMe-12345' scripts/e2e/smoke.sh

# compose 实例
SMOKE_USER=root SMOKE_PASSWORD='ChangeMe-12345' \
  scripts/e2e/smoke.sh --base-url http://127.0.0.1:8080 \
  --compose deployments/docker-compose/docker-compose.yml
```

- `--base-url`：目标实例；默认 `http://127.0.0.1:8080`。
- `--snapshot-dir`：失败快照目录；默认 `artifacts/e2e-fail-<时间戳>/`，包含失败步骤、最后一次响应体/头、Cookie，指定 `--compose` 时还会附上 `docker compose logs`。
- `--keep`：成功时保留临时请求文件；默认自动清理，不依赖临时目录残留。
- 需要的账号是**未启用 MFA 的密码账号**（Step-up 走密码重验路径）。

覆盖：健康检查、未登录 401、CSRF、登录、`/me` 与授权投影、OIDC 同意/WebAuthn 列表、discovery `end_session_endpoint`、Step-up、组织创建与租户审计/邀请/explain、跨租户未知组织 404、配额与 provider 配置视图、登出后会话失效。

`scripts/smoke.sh` 保留为兼容入口，转发到本脚本。
