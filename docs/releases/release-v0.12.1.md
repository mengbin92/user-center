# v0.12.1 · 2026-11-09

上一版：[v0.12.0](./release-v0.12.0.md) · 范围：CI 稳定性修复。

**版本判定：PATCH（v0.12.0 → v0.12.1）。** 无 API、无迁移、无配置变更。

## 问题

v0.12.0 的 `main` 分支 CI 在 `go test ./...` 阶段失败：

```
--- FAIL: TestConcurrentTOTPReplayOnlyCreatesOneSession
    expected {200, 400}, got {503, 400}
```

该用例并发提交同一个 TOTP 码，期望一个请求成功、另一个以「重放」被拒绝。CI 上第二个请求返回 503（依赖不可用）而不是 400。

## 根因

SQLite 串行化写入。两个并发请求都要消费同一个 `auth_flow_completions` 行；后到的写者没有配置 busy timeout，立即得到 `database is locked`，仓储层返回原始错误，业务层映射为 `ErrDependency`，HTTP 层呈现 503。

本地磁盘快、`internal/server` 约 56s，冲突窗口小，20–50 次重复未复现；CI 上同一包耗时 95s，窗口足够宽。

## 修复

- SQLite DSN 统一追加 `_busy_timeout=10000`（`withSQLiteBusyTimeout`，幂等）。后到的写者最多等待 10s 而不是立即失败；锁释放后按正常冲突路径返回 400。
- 该用例失败时输出两个响应体，后续若再抖动可直接看到是锁冲突还是业务拒绝。
- 新增 `TestWithSQLiteBusyTimeout` 覆盖已带参数、无参数与已自定义三种 DSN。

生产使用 MySQL，不受此变更影响；SQLite 仅用于测试与本地开发。

## 兼容性与升级

| 项目 | 说明 |
|---|---|
| 数据库 | 无迁移 |
| 配置 | 无变更；SQLite DSN 参数由程序补齐 |
| API | 无变更 |
| 行为 | 并发冲突由 503 变为等待后返回 400，属于修复而非契约变更 |

## 验证

| 项目 | 结果 |
|---|---|
| `gofmt -l .` | ✅ 无输出 |
| `go vet ./...` | ✅ 通过 |
| `go test ./...` | ✅ 全绿 |
| 目标用例 50 次重复 | ✅ 通过 |
| `./scripts/gen-check.sh` | ✅ 无生成物漂移 |
