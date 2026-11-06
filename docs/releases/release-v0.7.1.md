# v0.7.1 · 2026-11-06

上一版：[v0.7.0](./release-v0.7.0.md)

**版本判定：PATCH（v0.7.0 → v0.7.1）。** 只修 CI 与 E2E 脚本，无代码、无 API、无迁移变更。触发原因是 `v0.7.0` 打标后 `e2e-compose` 第一次在真实 GitHub runner 上运行并失败——本地同一份脚本连跑四次全绿。

## 修复

### compose E2E 在 Linux 上起不来

- **根因**：OIDC 私钥按 `0600` 生成，而镜像以非 root 的 `app` 用户运行。Linux 上 bind mount 保留源文件权限，服务启动即 `read OIDC signing key: open /run/secrets/oidc_signing_key: permission denied`，随后重启循环直到健康门禁超时。macOS 的 Docker Desktop 会放宽挂载权限，所以本地从未复现。
- **修复**：私钥放进 `0700` 目录，文件本身 `0444`（与 Kubernetes secret volume 一致）；目录权限保证宿主机上其他用户无法遍历。

### 镜像陈旧判定误报

- 原先比对镜像 `Created` 时间与构建开始时间。**Docker 在缓存完全命中时不会更新该时间戳**，于是合法的缓存构建被判成"陈旧镜像"并失败；同时该判断用了 GNU 专有的 `date -d`，在 macOS 上返回空值，本地实际一直在静默跳过。
- 现在只保留真正防住 v0.6.0 事故的那道门：`PIPESTATUS` 的真实退出码（禁止 `| tail` 吞码）。镜像内容由内容寻址保证，构建成功即可信；改为记录镜像 ID 供排障。

### 失败产物含会话 Cookie

- 失败快照整个目录被上传为 artifact，其中包含冒烟用的会话 Cookie。改为只上传诊断文件（`meta.txt` / `last-body` / `last-headers` / 容器日志）。

### 其他

- `buf-setup-action` 传入 `GITHUB_TOKEN`，避免匿名下载二进制触发限流警告。
- 健康门禁失败时直接打印服务日志最后 40 行；此前只看到 `Restarting (1)`，还得去下载 artifact 才能找到那一行原因。

## 验证

- 本地：`scripts/e2e/compose-e2e.sh` 通过（`E2E OK`、指标端点可抓取、容器日志 0 条 5xx）。
- CI（GitHub Actions，真实 Linux runner）：
  - `e2e-compose` on `develop`（手动触发）**通过**，耗时 2m6s；
  - `ci` on `develop` 通过（backend / mysql / generated / frontend / container 五个 job）。
- 说明：`v0.7.0` 的 tag 上 `e2e-compose` 为失败状态，是本次修复的触发原因；`v0.7.1` 未改写历史，而是在其上叠加修复。

## 升级注意

无。仅测试与 CI 脚本变化，运行时行为与 `v0.7.0` 完全一致。
