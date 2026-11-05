# v0.6.1 · 2026-11-05

上一版：[v0.6.0](./release-v0.6.0.md)

**版本判定：PATCH（v0.6.0 → v0.6.1）。** 无新增能力、无数据库迁移、无破坏性契约变更；仅修复第二轮完整 code review 发现的缺陷，并补充回归测试。

本轮共修复 **1 个 P1、6 个 P2、9 个 P3**。P1 为组织成员管理中的自定义角色提权；P2 覆盖 OIDC 登出会话残留、邀请接受的并发竞态、邀请列表 PII、OIDC 应用编辑误清空登出白名单、并发改用户名 500、consent revision 不递增。

## 修复

### 组织与邀请

- **P1 自定义角色提权**：持有 `organization.member.manage` 的非管理员自定义角色，不能再把自己或他人提升为 `admin`、不能修改/降级现有 `admin`、不能邀请 `admin`。只有 platform/owner/admin 可授予 admin，只有 platform/owner 可修改现有 admin。
- **P2 邀请接受竞态**：重新邀请撤销旧 pending 记录时递增 `revision`；接受/撤销更新增加 `status='pending'` 条件。持有旧快照的在途令牌无法再把已撤销邀请改为 `accepted`。
- **P2 邀请列表 PII**：列表包含被邀请人邮箱，权限从普通成员读提升为 `organization.member.manage`；组织详情页仅对 owner/admin/platform 展示邀请 Tab。
- **P3 配额顺序**：先撤销同邮箱旧邀请再检查配额，避免“50 个 pending 时无法重发已有邀请”。
- **P3 撤销错误码**：重复撤销返回 `INVITATION_REVOKED`，不再误报“未找到”。
- **P3 归档部门**：添加成员、改成员、邀请、创建/更新部门均拒绝已归档部门。
- **P3 部门环检测**：由固定 32 层改为完整祖先链遍历，父部门查询失败直接报错。

### OIDC

- **P2 登出会话残留**：RP-initiated logout 即使 `post_logout_redirect_uri` 非法或不可回跳，也先撤销本地会话、删除 Step-up、写审计并清理 Cookie；错误页明确“已退出登录”。
- **P3 跨客户端 hint**：`client_id` 与 `id_token_hint` 的 `aud` 不一致时返回 `invalid_request`，仍撤销本地会话。
- **P3 会话校验 fail-closed**：带 Cookie 但会话校验依赖不可用时，所有路径（含公开路径）统一 503，避免清 Cookie 后服务端会话仍有效。
- **P2 应用编辑白名单**：管理端编辑 OIDC 应用时提交并保留 `post_logout_redirect_uris`，不再因未携带字段而清空已登记白名单。
- **P2 consent revision**：`UpsertConsent` 改为 upsert 并 `revision = revision + 1`，同步更新 scopes，恢复并发检测语义。

### 其他

- **P2 并发改用户名**：唯一索引冲突映射为 `USERNAME_EXISTS`（409），不再返回 500。
- **P3 组织事件契约**：`organization.member.*` 使用 `role_code`；`role.updated/archived` 补 `role_code`；`assignment.revoked` 补 `user_id/role_id`。
- **P3 租户导出审计**：租户审计导出写入租户审计流，平台导出路径不变。
- **P3 文档**：同步 OIDC consent/logout 现状、邀请列表权限、接受邀请的邮箱验证前置条件与 logout-CSRF 边界。

## 数据库与兼容性

- 无迁移，无需变更 schema。
- API 仅收紧权限与错误语义：邀请列表由成员可读改为 `organization.member.manage`；重复撤销错误码由“未找到”改为 `INVITATION_REVOKED`；登出失败改为先撤销会话。其余请求/响应字段兼容。

## 验证

- `go build ./...`、`go vet ./...`、`go test ./...` 全部通过。
- `go test -race ./internal/biz ./internal/data ./domain/...` 通过；OIDC/组织/邀请/用户名相关 HTTP 用例 race 通过。
- `cd web && npm test -- --run`：17 个文件、60 个测试通过；`npm run build` 通过。
- `gofmt -l` 无输出。
- 新增 HTTP 级拒绝测试：自定义 `member.manage` 角色自升/降级/添加/邀请 admin 均 403；普通成员读取邀请列表 403；非法登出回跳后会话失效且 Cookie 被清除。
- 新增仓库测试：撤销邀请递增 revision 且旧快照 CAS 失败；consent upsert revision 递增；事务回滚不留下 Outbox 事件。

## 未改动（已知边界）

- 平台 root/admin 跨租户治理覆盖是 `docs/security.md` 记录的设计选择，不按越权处理。
- 部门维护不加 Step-up、`CreateDepartment` 无 `reason` 字段，与 `docs/security.md` §3.1 现有约定一致。
- 历史审计/Outbox 载荷中的旧用户名不回写擦除；审计不可变，R14 只保证清理事件本身只含不可逆 `user_id`。
- RP-initiated logout 的 logout-CSRF 属协议固有行为，已在 `docs/security.md` 第 8 条说明。
