# SMTP 真实环境验收记录（2026-11-03）

| 项 | 结果 |
|---|---|
| 提供方 | QQ 邮箱（smtp.qq.com） |
| 端口/安全 | 587 / STARTTLS（代码同时支持 465 implicit TLS） |
| 认证 | 授权码（运行时从线上 `notify-worker` 容器配置读取，未写入仓库/日志） |
| 发件人/收件人 | 同一 QQ 邮箱（自测） |
| 发信结果 | SMTP 服务器接受（`TestLiveSMTP` 通过） |
| 送达结果 | 通过 QQ IMAP 在收件箱找到主题「用户中心 SMTP 验收」，确认实际投递 |
| 秘密处理 | 仅保存在 `/tmp` 权限受限文件并随后删除；仓库与测试输出不含凭据 |

## 复现方式

```bash
SMTP_LIVE_TEST=1 \
SMTP_HOST=smtp.qq.com SMTP_PORT=587 \
SMTP_USER=... SMTP_PASS=... SMTP_FROM=... SMTP_TO=... \
go test ./internal/data -run TestLiveSMTP -v
```

该测试默认跳过，不会在 CI 中发送邮件。真实凭据必须通过环境变量注入。

## 代码调整

- `sendSMTP` 支持 465 implicit TLS 与 587/25 STARTTLS，TLS 最低 1.2。
- 继续拒绝空 host/port、CRLF 注入；SMTP 错误不记录原文。
- 运行时邮件配置从 `auth_email_settings` 读取，密码 AES-GCM 加密存储。
