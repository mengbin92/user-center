# 新增功能代码审查记录（2026-11-04）

审查范围：v0.3.0 发布前后新增的功能——标准 OIDC Provider、TLS SMTP、OIDC 应用管理前端与相关契约，对照 v0.2.1 安全审查（见 [code-review-2026-11-03](code-review-2026-11-03.md)）之后产生的全部变更。本轮审查发现的问题均已修复，安全行为使用服务端拒绝用例验证。

## 主要发现与修复

| 优先级 | 原问题及影响 | 修复与验证 |
|---|---|---|
| P1 | OIDC 授权码/刷新令牌读取时未加行锁，刷新令牌轮换并发可双花；旧的（非 CAS）密钥轮换与停用允许并发覆盖 | `GetOIDCClient(ByClientID)` 在事务内 `FOR UPDATE`；`ConsumeOIDCRefreshToken` 行锁 + 过期/撤销重判；轮换与停用改为 `revision = expected` 条件更新，`RowsAffected==0` 返回版本冲突 |
| P1 | 刷新令牌重放无处置：被撤销的令牌再次使用时仅拒绝，不波及同族后续令牌 | 引入刷新令牌 family：检测到已撤销令牌重放时，同事务撤销该 client 下整个 family，并提交拒绝（持久化家族吊销） |
| P1 | MySQL 默认排序规则大小写不敏感，`client_id`/`redirect_uri` 精确匹配被弱化，可能匹配到非预期的授权码/客户端 | 查询后回读结果并做 Go 层精确比对，不一致按无效授权/未找到拒绝 |
| P1 | 授权码与刷新令牌未绑定签发时的身份版本，用户凭据/MFA 变更后旧授权仍可换发新令牌 | 授权码与刷新令牌持久化 `identity_version`（新列 + MySQL 004 迁移），换发令牌时与当前身份版本比对，失效即拒绝 |
| P1 | OIDC 客户端管理写缺少完整的版本约束：创建无 `expected_policy_revision`，停用/轮换无目标 `expected_revision` | proto 补齐版本字段（`make api` 重新生成），service 校验十进制版本与 reason，biz 在策略锁内复核；HTTP 拒绝陈旧/缺失版本的用例 |
| P1 | 管理操作复核（managementGuard）缺失：停用/轮换等高危 OIDC 写不要求 Step-up | biz 增加统一管理复核；SPA 在变更对话框内完成 Step-up 后重试 |
| P2 | 公开客户端创建后前端仍展示"保存密钥"对话框，引导用户保存一个不存在的密钥 | 对话框按 public 分支展示"已创建"与完成按钮，隐藏复制密钥入口 |
| P2 | OAuth 第三方登录在 OIDC 授权流程中断后回到登录页，授权上下文丢失 | 登录页把安全的 OIDC 续接（仅 `/oidc/authorize` 相对路径）透传给 provider start 的 `next`，登录完成后自动续接；拒绝外站/协议相对 URL |
| P2 | 登出/权限收缩后，遗留的密钥轮换 mutation 数据仍留在查询缓存 | 关键 mutation 支持显式 `gcTime`，权限撤销后立即丢弃已展示的密钥 |
| P2 | TLS SMTP 与 outbox 签名缺少回归测试；CI 镜像冒烟失败时不保留容器日志，Docker action 使用可变 tag | 补齐 smtp_tls/outbox_signing 回归测试；CI 固定 action digest、超时 20 分钟、失败 trap 打印日志 |

## 验证

- `go build ./...`、`go vet ./...`、`go test ./...`、`go test -race ./internal/...` 全部通过。
- 前端 48 项测试通过，TypeScript 与 Vite 生产构建通过。
- 新增回归测试覆盖：OIDC biz 层并发换发、data 层 SQLite/MySQL 存储边界、HTTP 拒绝用例、wiring 装配、前端登录续接与密钥对话框。
- 生成物（`*.pb.go`、`openapi.yaml`、`wire_gen.go`）由 `make api` / `make wire` / `npm run generate:api` 产出，未手工编辑。

## 未验证项

- 真实 GitHub/Google 提供方沙箱联调与生产 SMTP 送达沿用既有外部验收结论，本轮未重复执行。
