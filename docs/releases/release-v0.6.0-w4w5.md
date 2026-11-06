# V2.4 W4/W5 波次附记（不单独打标）

> 状态：**波次追溯记录**。V2.4 全部波次统一发布为 [v0.6.0](./release-v0.6.0.md)（见该文件的版本判定与决策说明）。本文件保留 W4/W5 的变更细节。
>
> 2026-11-06 更名：本文件原为 `release-v0.8.0.md`。`v0.8.0` 将作为下一版的真实版本号（认证加固与组织治理），故改名为 `release-v0.6.0-w4w5.md` 以免冲突。

上一版：[v0.6.0](./release-v0.6.0.md)

本版包含路线图 W4（R13）与 W5（R14）。W4 原标注「可整体滑动到 V2.5」、W5「未排期」，本次按用户要求一并交付，属于范围决策变更，已在路线图变更记录留痕。

## 数据库迁移

- `010_webauthn.sql`：`webauthn_credentials`（credential_id 唯一、COSE 公钥、sign_count、AAGUID、transports、计数器/时间）。
- `011_retention.sql`：`users.anonymized_at` + 保留期索引；`user_legal_holds`。
- 新增依赖 `github.com/fxamacker/cbor/v2`（纯 Go CBOR 解析，用于 attestationObject / COSE_Key）。

## R13 WebAuthn / Passkey（第二因素）

- 注册：`attestation none` 强制，校验 `clientDataJSON`（type/challenge/origin）、`rpIdHash`、`UP` 标志、COSE 公钥（ES256 / RS256），保存 `credential_id`、公钥、`sign_count`、AAGUID、transports、创建时间；挑战一次性、绑定用户/会话/身份版本/RP。
- 认证：验签 `authenticatorData || SHA256(clientDataJSON)`，校验 RP ID/origin，`sign_count` 回退返回 `WEBAUTHN_SIGN_COUNT_REGRESSION` 并写安全事件与告警审计；成功后原子更新计数器与最近使用时间。
- 凭据列表与删除；无 TOTP 且仅剩一枚凭据时返回 `LAST_SECOND_FACTOR`，要求先绑定替代第二因素；停用 TOTP 同样检查管理员策略。
- 管理员强制 MFA 策略接受 Passkey；登录 `LoginReply.webauthn` 下发断言挑战，`/auth/mfa/complete` 可用断言替代 TOTP/恢复码；Step-up 接受断言并写入会话绑定证明。
- **用户名 + 密码仍是第一因素**；注册/删除/Step-up 都要求重新输入当前密码。
- 安全中心新增 Passkey 面板，登录 MFA 页新增「使用 Passkey」入口。

## R14 个人信息保留与清理

- `cmd/retention` + `make retention`：默认保留期 365 天（按 `archived_at`），可用 `RETENTION_DAYS` / `-retention-days` 配置；默认 dry-run，实际写入必须同时传 `-apply` 与 `-acknowledge=I_HAVE_BACKED_UP`。
- 清理范围：用户名（含归一化）、昵称、邮箱（含验证状态）、凭据摘要、MFA 与恢复码、会话、第三方身份、WebAuthn 凭据；审计与 Outbox 事件不删除，只保留不可逆 `user_id`。
- 幂等：`anonymized_at` 标记；legal hold 命中跳过，并在事务内二次复核；`-hold-user` / `-release-user` 管理例外。
- 结构化日志 + JSON 报告（scanned/eligible/cleaned/skipped/failed）+ `identity.retention.cleanup` 审计事件；运维手册写明备份、双人确认、窗口期与复核流程。

## 工程前置

- v0.5.1 Docker E2E 脚本正式收纳到 `scripts/e2e/smoke.sh`：支持 `--base-url`、`--snapshot-dir`、`--compose`、自动清理与失败快照；`scripts/smoke.sh` 保留为兼容转发。
- 冒烟覆盖：健康检查、未登录 401、CSRF、登录、`/me`、授权投影、OIDC 同意/Passkey 列表、discovery `end_session_endpoint`、Step-up、组织创建与租户审计/邀请/explain、跨租户未知组织 404、配额/provider 视图、登出失效。

## 验证

`go vet ./...`、`go test ./...`（含 WebAuthn 真实 P-256 签名端到端、保留清理 dry-run/legal hold/幂等/未到期用例）、`cd web && npm test && npm run build` 全部通过；MySQL 8.4 容器真实应用 001–011 两次幂等通过；本地实例 E2E 冒烟通过；**compose 全栈冒烟连续两次通过**（正式结果见 [v0.6.0 发布说明](./release-v0.6.0.md#compose-冒烟结果2026-11-05)）。

## 未执行 / 已知限制

- compose 冒烟使用密码账号夹具（bootstrap root + 显式关闭「管理员必须 MFA」策略），管理员 MFA 登录链路由 `go test` 的 TOTP/WebAuthn 用例覆盖；部署到目标环境时仍建议按实际策略再跑一次 `scripts/e2e/smoke.sh --compose ...`。
- 真实浏览器 WebAuthn API 需 HTTPS/安全上下文，前端交互未在真实认证器上验收；服务端验证链由软件 P-256 认证器端到端覆盖。
- 清理任务不常驻、不自动调度，是否纳入定时任务由部署方按合规要求决定。
