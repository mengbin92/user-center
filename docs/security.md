# 安全设计

## 1. 资产与信任边界

| 资产 | 边界 |
|---|---|
| 密码摘要、TOTP 密文、恢复码摘要 | 仅 `user_credentials` / `identity_mfa`；任何普通查询不返回 |
| 会话令牌 | 仅浏览器 HttpOnly Cookie 与服务端哈希；不返回 JSON、不写日志 |
| 验证码 | HMAC 后存 Redis/内存；邮件正文外不落库 |
| 授权事实 | MySQL 为权威；前端只消费 `/me/authorization` 投影 |
| 审计 | 追加写；普通管理员不能删除 |
| 接入客户端凭据 | 仅创建/轮换时展示；DB 存摘要；gRPC Bearer 与方法白名单 |

浏览器、反向代理、数据库、Redis、SMTP 均视为独立信任域；跨域只通过明确契约。

## 2. 控制清单

| 威胁 | 控制 |
|---|---|
| 会话窃取/重放 | 随机不透明令牌、HttpOnly/SameSite、DB 哈希、身份版本校验、空闲+绝对过期、撤销全部会话 |
| CSRF | 双提交 Cookie + 中间件强制 header 校验（所有非 GET `/api/v1`） |
| 会话固定 | 登录/完成 MFA 均生成新会话，不复用匿名标识 |
| 暴力破解 | 登录 IP/用户限流；MFA 5 次失败锁定 5 分钟；挑战验证码 10 次尝试上限 |
| 账号枚举 | 登录统一“用户名或密码错误”；密码重置统一成功响应；注册邮箱冲突返回挑战失败 |
| 验证码重放 | 单次消费 + DB `(challenge_id,purpose)` 唯一完成记录 |
| TOTP 重放 | 持久化 `last_step`，拒绝已使用时间步 |
| 恢复码泄露 | 仅展示一次；SHA-256 存储；使用即删除 |
| 越权 | 操作权限 + Scope 边界 + 显式 deny + 有效期 + 约束；资源 owner 执行点校验 |
| 数据范围绕过 | 列表/详情/导出/会话接口统一 Scope 过滤；受限管理员不能通过分页/导出扩大范围 |
| 并发覆盖 | 用户 revision、policy revision、角色/分配 revision CAS |
| 高风险操作 | Step-up（主认证 + 第二因素，绑定 session 与 identity_version，5 分钟） |
| 管理员未绑定 MFA | 管理授权入口强制 `MFA_ENROLLMENT_REQUIRED`，但保留安全中心完成绑定 |
| 初始密码 | `password_change_required` + 中间件阻断 `/admin/*`，改密后清除 |
| 第三方登录 | 单次 state（Redis + HttpOnly Cookie）、服务端 code 交换、不按邮箱自动合并、已启用 MFA 时仍要求第二因素 |
| 接入客户端 | 凭据只存 SHA-256、一次性展示、按 gRPC 方法白名单校验、可轮换/停用 |
| Webhook | HMAC-SHA256 原始 body、至少一次投递、重试退避、消费端按 event_id 去重 |
| OIDC Provider | 授权码一次性消费、PKCE S256、redirect_uri 精确匹配、RS256、短时 access/refresh token、客户端密钥摘要 |
| 组织成员 | 组织角色校验、最后 owner 保护、平台管理员特权、成员邮箱按角色脱敏、变更 revision CAS；归档/成员增改删要求 Step-up |
| 审计缺失 | 敏感写与业务事务同提交写审计；安全事件独立表 |
| 密钥泄露 | 环境变量注入；AES-GCM 加密 TOTP；日志不打印凭据 |
| 开放重定向 | OAuth 回调只重定向到固定的前端路径；state 单次有效并绑定 HttpOnly Cookie |

## 3. 关键实现细节

- `Authorization` 决策的每个输入都来自服务端事实；`Scope{All:true}` 只在 grant 与 boundary 同时允许时生效。
- 无效/过期/未激活 grant 不参与 allow；deny 不受会话激活影响，只要有效期命中即拒绝。
- 角色继承在写入和决策读取时都验证无环。
- 管理员邮箱字段按 `identity.user.contact.read` 单独授权；无权限时返回空字符串，而不是遮罩字符串。
- 列表与概览在 SQL 计数/分页前应用 allow 与 deny；邮箱关键词检索也要求完整联系方式读取权限。
- 导出下载检查当前会话、任务归属、导出权限、policy/session-role revision 和授权有效期；权限变化后必须重新导出。CSV 公式前缀被转义，文件名经过 `filepath.Base`。
- 内部 gRPC 只接受数据库接入客户端凭据，不保留静态令牌旁路。资源授权验证调用方 service_owner、资源 owner 和执行点；会话撤销需要用户会话证明，禁止跨用户/应用。
- 错误不返回内部 SQL/驱动信息。JSON 请求上限 1 MiB，未知字段拒绝；ProtoJSON 保留 64 位整数精度。
- MySQL 或 Secure Cookie 配置要求三个安全密钥至少 32 字节并拒绝开发样例；配置 Redis 后连接失败拒绝启动。只有未配置 Redis 的开发环境使用内存临时状态。
- TOTP/恢复码与会话角色使用 CAS；MFA 清空状态时保留 revision，防止删除重建后的 ABA 竞态。密码、邮箱和 MFA 变更使旧近期证明失效。
- console 邮件仅记录收件人和主题；邮件正文、验证码及 SMTP 错误原文不写日志。配置读取/解密失败不伪装投递成功。
- 纯 OAuth 账号的 `mode=verify` 只接受当前已绑定身份；主认证证明与完整 Step-up 分离，均绑定会话和身份版本。主认证证明可用于首设密码或 MFA，有 MFA 时仍必须验证当前第二因素。

## 4. 已知限制（必须在上线评审中确认）

1. **OAuth 真实提供方尚未做生产沙箱验收**：GitHub/Google 适配器、state、绑定与登录流程已实现并有 mock 测试；上线前必须用真实 Client ID/Secret、HTTPS 回调和账号完成一轮验收。
2. **委派只约束角色分配/撤销**：委派校验覆盖目标角色、目标用户范围、动作与有效期；通过委派不能修改角色 Grant、继承或创建角色，策略变更仍要求直接权限。
3. **Outbox 为至少一次投递**：消费端按 `event_id` 去重；有订阅客户端时必须配置 `OUTBOX_SIGNING_SECRET`，为空则拒绝投递。队列按订阅方读取未入队历史事件，并使用可过期领取租约，进程中断后可恢复。
4. **审计读取本身不写审计**：当前只记录写操作与安全事件；有读取审计需求时需增加相应实现。
5. **组织域 IAM/多租户数据隔离仍是 V2.3**：V2.2 已交付组织、部门、成员与组织角色；尚未把角色/分配/资源策略迁移到 `organization:{id}` 授权上下文，也未做租户级数据分区。
6. **同步导出**：单次最多 100000 行，生成期间占用请求；超大导出需异步任务。
7. **管理员邮箱变更依赖新邮箱可达**：验证码发送到新邮箱，管理员权限 + Step-up 防止误操作，但无法证明旧邮箱归属；需要旧邮箱确认的场景应走用户自助流程。
8. **OIDC consent/end-session 尚未提供**：V2.1 对管理员注册的客户端自动同意，discovery 不宣告 end_session；交互式 consent 与 RP-initiated logout 计划在 V2.2。
9. **组织创建暂无配额/审批**：任意已登录且状态正常的账号可创建组织；如需企业审批或数量上限，应在 V2.3 增加组织创建策略。
10. **OpenAPI 不包含浏览器安全方案与原始路由**：Cookie/CSRF、OAuth start/callback、CSV 下载在 `docs/api.md` 中约定，不在 `openapi.yaml` 的 securitySchemes 中。

## 5. 上线检查

- [ ] `COOKIE_SECURE=true`，全站 HTTPS，HSTS 已配置
- [ ] `SESSION_SECRET`、`CSRF_SECRET`、`MFA_ENCRYPTION_KEY` 为随机值且已备份
- [ ] 接入客户端已创建并配置最小方法白名单，gRPC 端口只对受信网络开放
- [ ] root 已创建且密码不在仓库/镜像/Compose 中
- [ ] MySQL 运行账号无 DDL/跨库权限
- [ ] Redis 持久化与监控已配置
- [ ] 备份/恢复演练完成
- [ ] 管理员 MFA 流程与首次改密流程经产品/安全确认
- [ ] 审计导出权限仅授予审计角色
