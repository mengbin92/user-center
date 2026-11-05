# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-11-05

**版本判定：MINOR**（v0.5.2 → v0.6.0）。V2.4 R1–R14、code review 修复与工程前置一次性连续交付；分波次 tag 会让 v0.6.0/v0.7.0 缺少后续 P1 安全修复，故统一发版，决策已同步至 [路线图 §5](roadmap-v2.4.md) 与 [发布说明](releases/release-v0.6.0.md)。

### Added (W1/W2)

- OIDC 交互式授权同意页：一次性服务端 handle、按 client+user 持久化已授予 scope、scope 扩张与 `prompt=consent` 重新征询、`prompt=none` 返回 `interaction_required`、`/me/oidc-consents` 列出与撤销。
- RP-initiated logout：discovery `end_session_endpoint`、`/oidc/logout`、客户端 `post_logout_redirect_uris` 精确白名单、会话撤销与 Cookie 清理、幂等重复调用。
- 组织邀请与接受：令牌哈希存储、邮件投递、邮箱匹配、过期/撤销/重复接受/上限/跨租户拒绝、接受后同步内置角色授权、审计事件。
- 组织域授权解释 `GET /orgs/{id}/iam/authorization:explain`，复用同一 `authorization.Evaluate` 路径。
- 租户审计导出 `POST /orgs/{id}/audits:export` + 租户下载通道，复用平台 CSV/签名与版本校验。
- 组织域事件进 Outbox（成员/部门/角色/分配/归档，最小无 PII 载荷），文档新增事件表。

### Added (W3)

- 内部 gRPC `Authenticate` / `CompleteMFA`，复用 HTTP 登录限流与失败计数、会话绑定应用、审计 `actor_service_id`。
- 审计详情页 `/admin/audits/:id`（before/after/diff 折叠、返回保留筛选）、身份提供方配置页 `/admin/settings/providers`、组织策略页 `/admin/settings/organization`。
- 用户名自助修改（Step-up + 当前密码 + revision CAS，管理端不可改）、单条分配预览、组织创建配额。

### Added (W4/W5)

- WebAuthn/Passkey 第二因素（R13）：attestation none、真实 COSE/ES256 验签、RP ID/origin 校验、sign_count 回退拒绝、Step-up 与登录 MFA、管理员策略联动、最后第二因素保护。
- 个人信息保留与清理（R14）：`cmd/retention`、365 天可配保留期、dry-run/双人确认、legal hold、幂等匿名化、最小审计标识。
- E2E 冒烟脚本正式收纳到 `scripts/e2e/smoke.sh`（`--base-url`、自动清理、失败快照）。
- 迁移 `010_webauthn.sql`、`011_retention.sql`；新增 `github.com/fxamacker/cbor/v2` 依赖。

### Changed

- 认证配置变更（`settings.auth.update`）现在推进 policy revision。
- 迁移新增 `007_oidc_consent.sql`、`008_org_invitations.sql`、`009_org_quota.sql`；权限目录新增 `settings.organization.read/update`，菜单新增应用授权、身份提供方、组织策略。

### Notes

- 本地 compose 全栈冒烟通过（MySQL 8.4 + Redis 7 + migrate 001–011 + user-center，连续两次全绿、日志 0 error/5xx）；MySQL 8.4 容器迁移真跑与本地 dev 实例 E2E 冒烟同样通过。首轮失败根因是 `docker compose build | tail` 掩盖构建失败导致复用旧镜像，已改为校验真实退出码与镜像创建时间。
- `scripts/e2e/smoke.sh` 新增 `--compose-env`，用于带 `:?` 强制校验的 compose 文件抓取失败日志。
- 范围决策：R13/R14 原分别标注「可滑动到 V2.5」与「未排期」，本次按用户要求一并交付（统一发 `v0.6.0`）。

## [0.5.2] - 2026-11-04

Full-project review follow-up. No schema change.

### Fixed

- The password-change gate skipped `/api/v1/orgs*`: `requiresAuth` only knew
  `/me` and `/admin`, so the `/orgs` branch was unreachable. An account with an
  initial password could create and read organizations before changing it.
  Tenant routes now share one path table with the gate.
- The user list reloaded all roles, grants, inheritance, assignments and
  constraints twice per row (about 16 queries per row). It now loads the policy
  snapshot once and resolves roles and MFA state in two batch queries.
- Archived organization roles accepted grant edits; the status check was only
  present in `UpdateRole`.
- Last-owner and `max_members`/duplicate-assignment checks ran outside the
  transaction, so concurrent requests could leave an organization without an
  owner or overfill a role. Both now run inside the transaction under a row
  lock (`FOR UPDATE`; SQLite skips it).
- Adding a member distinguished "unknown account" (404) from "disabled account"
  (400), letting a tenant administrator enumerate the platform directory.
- `authorization:explain` accepted `resource_id` and silently ignored it,
  returning an authoritative-looking but incomplete decision. It is now
  rejected with a validation error and the SPA no longer offers the field.
- `reason` was optional and silently defaulted at 33 call sites, contradicting
  the documented audit contract. Management writes now require a non-empty
  reason (max 512 characters).
- `memoryKV` never swept expired entries; rate-limit keys embed a time bucket,
  so a Redis-less deployment grew without bound.
- Webhook callbacks accepted plaintext `http` for any host and any link-local
  address (including the metadata endpoint). Public receivers now require
  `https`; link-local and unspecified hosts are always rejected.
- Outbox dispatch failures were discarded; they are now logged.
- The gRPC interceptor forwarded non-integration methods without authentication;
  it now denies by default.
- MySQL migrations were wrapped in a transaction even though DDL commits
  implicitly, so a partial migration could not be resumed. Progress is now
  recorded per statement.
- `GetRole` loaded every role and scanned linearly; it now reads one role plus
  its grants and inheritance.

### Changed

- SPA routes are code-split: account, organization and admin screens load on
  demand. The initial JS bundle drops from 779 kB to 303 kB (gzip 214 to 92 kB)
  and the build no longer emits the 500 kB chunk warning.
- `authorization:explain` returns `VALIDATION_FAILED` for resource-scoped
  requests instead of a partial explanation.
- Swagger/HTTP clients that omitted `reason` on management writes now receive
  400 `VALIDATION_FAILED`.

## [0.5.1] - 2026-11-04

### Fixed

- Unauthenticated requests to `/api/v1/orgs*` dereferenced a zero actor and
  panicked (the connection was dropped instead of returning 401). Every
  organization RPC now requires an authenticated actor and keeps the request
  metadata used by tenant audit.
- Accounts without MFA could never obtain a step-up proof: `Verify` always
  required a second factor, so every step-up-protected organization write was
  permanently blocked for them. Step-up now requires the enrolled factor when
  present and falls back to primary-password re-entry otherwise.

## [0.5.0] - 2026-11-04

V2.3 delivers organization-scoped IAM and tenant isolation.

### Added

- Authorization contexts: `platform` and `organization:{id}`. A grant only
  applies inside the context it was issued for, and a permission whose
  `context_types` lacks the request context is refused.
- Organization-scoped IAM API: list roles/permissions, create/update/archive
  custom roles, replace role grants, list/assign/revoke member assignments and
  read tenant audit at `/api/v1/orgs/{id}/iam/*` and
  `/api/v1/orgs/{id}/audits`.
- Built-in organization roles `org_owner/org_admin/org_member` materialized per
  organization; membership roles are projected onto them and stay in sync.
- Tenant-scoped audit: `iam_audit_events.organization_id`, filtered on read.
- Backfill for organizations created before V2.3 (`cmd/migrate` plus lazy
  provisioning on first access).
- SPA: organization "角色与授权" and "审计" tabs (custom roles, grants,
  assignments, tenant audit with action filter).

### Changed

- Organization endpoints are now permission-driven (`organization.member.*`,
  `organization.department.*`, `organization.iam.*`, `organization.audit.read`,
  `organization.settings.update`, `organization.archive`) instead of only
  comparing the membership role.
- Platform role/assignment queries exclude organization-context rows, and vice
  versa, at the SQL layer.

### Fixed

- Organization member list returned zero-valued ids, roles and status: the query
  scanned into an embedded unexported PO, which GORM could not populate. The
  scan now uses explicit fields, so member lists and member-based UIs are
  correct again.
- Organization roles leaked into platform views: `/me`, user details and the
  platform role directory no longer list organization-scoped assignments
  (`context_type='platform'` filter on role lookups).
- Concurrent creation of the same organization role returned a raw driver error;
  it now answers 409 `ORGANIZATION_ROLE_EXISTS`, and first-access backfill
  tolerates concurrent or interrupted provisioning.

### Security

- Cross-tenant role/assignment identifiers in URL or body resolve to
  `RESOURCE_NOT_FOUND`; tenant queries always carry the context in the WHERE
  clause.
- Custom organization roles may only grant organization-context permissions
  with allow semantics; `org_` codes and built-in roles are immutable.

## [0.4.0] - 2026-11-04

V2.2 delivers organization, department and membership management.

### Added

- Organization lifecycle: create/list/get/rename/archive; creator becomes owner.
- Organization members with owner/admin/member roles, username/email lookup,
  department assignment, role changes, removal and self-service leave.
- Last-owner protection: the final owner cannot be demoted, removed or leave.
- Departments with parent/child hierarchy, cycle detection, archive and member
  assignment.
- Platform admin organization directory and archive endpoints.
- Org member email masking for plain members; owner/admin/platform see contact.
- Audit events for organization/member/department changes.
- SPA organization switcher, `/orgs` list/create, `/orgs/:id` overview/members/
  departments/settings, and `/admin/organizations` platform directory.
- MySQL migration `005_organizations.sql`, permissions/menu seed and tests.

### Notes

- Organization roles are separate from platform IAM roles. Organization-scoped
  IAM contexts (`organization:{id}`), role assignments and tenant data isolation
  remain V2.3.
- No invitation acceptance flow yet: managers add existing enabled accounts
  directly.

## [0.3.0] - 2026-11-03

V2 starts with a standards-based OIDC Provider.

### Added

- OIDC discovery (`/.well-known/openid-configuration`), JWKS (`/oidc/jwks`),
  authorization endpoint (`/oidc/authorize`), token endpoint (`/oidc/token`) and
  userinfo endpoint (`/oidc/userinfo`).
- Authorization code flow with S256 PKCE, exact redirect URI matching,
  RS256 ID/access tokens, refresh tokens for `offline_access`, nonce and
  auth_time claims.
- OIDC client administration (`/admin/oidc-clients*`): one-time client secret,
  redirect URI/scope management, secret rotation, disable and audit.
- OIDC RSA signing key loading from `OIDC_SIGNING_KEY_PATH`/PEM with an
  ephemeral development fallback.
- Admin SPA page for OIDC applications and discovery/JWKS endpoint display.
- Real QQ SMTP acceptance: implicit TLS/STARTTLS support, end-to-end send and
  IMAP delivery verification (see `docs/acceptance-smtp-2026-11-03.md`).

### Notes

- V2.1 auto-consents clients pre-registered by an administrator; interactive
  consent and RP-initiated logout are V2.2.
- Organization/multi-tenancy, WebAuthn, SCIM and directory sync remain open V2
  milestones.

## [0.2.1] - 2026-11-03

Security-review and verification follow-up to 0.2.0.

### Security

- Enforce actor-aware scopes, root protection, delegation ceilings, atomic
  batch authorization, current policy/target revisions and non-empty reasons.
- Prevent challenge, TOTP, recovery-code and stale step-up replay; fail closed
  on authentication dependencies and keep sensitive writes with their audit.
- Recheck export authority, restrict integration callers and session revocation,
  remove the static integration-token bypass, and harden mail and startup secrets.
- Isolate frontend sessions and cached authorization; keep legacy governance
  roles pending until explicitly reassigned with a verified boundary.
- Refuse unsigned Outbox webhook delivery when `OUTBOX_SIGNING_SECRET` is absent.

### Changed

- Use strict ProtoJSON and decimal-string 64-bit values; update generated API
  types and management preconditions together.
- Add OAuth-only identity re-verification and explicit offline root MFA rescue.
- Recover Outbox leases and historical backlog; fix Docker command overrides.
- Save the first email settings row with a deterministic revision instead of a
  false `REVISION_CONFLICT`.
- Record findings, compatibility changes and validation in the review report
  (archived outside the repository).

### Added

- Adapter tests against local fake GitHub/Google OAuth servers and a local fake
  SMTP server.
- Docker image build plus container smoke test for native and linux/amd64
  targets; CI container job.
- Release notes for v0.2.1.

## [0.2.0] - 2026-11-02

Completes the remaining V1 governance, integration and migration capabilities
on top of the 0.1.0 extraction.

### Added

- Enforced admin MFA policy at the authorization seam; root/admin can still
  authenticate and enroll a second factor but management calls return
  `MFA_ENROLLMENT_REQUIRED` until TOTP is active.
- Forced first password change: initial-password accounts receive
  `password_change_required` at login and are blocked from `/admin/*` until
  the password is changed.
- GitHub/Google OAuth login and account binding with single-use state,
  HttpOnly state cookie, server-side code exchange and no email auto-merge.
- Administrator email change with a verification code sent to the new mailbox,
  step-up, identity version bump and session revocation.
- Assignment listing endpoint with user/role/status filters and pagination.
- IAM delegation CRUD and assignment enforcement for bounded manager roles;
  seeded permissions, menu and step-up protection.
- Integration client management (allowed gRPC methods, event subscriptions,
  callback URL), credential rotation with one-time display, and persisted
  client authentication replacing the static-token-only path.
- Transactional outbox webhook worker with HMAC-SHA256 signatures, retry
  backoff, delivery listing and manual retry.
- `cmd/import-legacy` offline importer with dry-run, conflict reporting,
  stable user IDs, password hashes, role assignments and import batch records.
- User export filters (`role_id`, `mfa_enabled`) and audit export `target`
  filter; delegation revocation fields in the API.
- Domain `Scope.Covers` for delegation boundary containment.
- Frontend: forced password/MFA prompts, OAuth buttons and callback handling,
  admin email change, assignment list filters, delegation and integrations
  pages.
- Tests for registration/password reset, admin email change, OAuth bind/login,
  OAuth+MFA, MFA enforcement, forced password change, integration clients +
  webhook delivery, legacy import, assignments and delegations.
- Adapter tests against a local fake GitHub/Google OAuth server and a local
  fake SMTP server; Docker image build plus container smoke test for both
  native and linux/amd64 targets; CI container job.

### Fixed

- Verification-code hashes now derive from the challenge purpose consistently;
  registration, password reset and email-change flows no longer fail with
  `CHALLENGE_INVALID`.
- Outbox delivery rows are scanned explicitly, so event/subscriber IDs and
  statuses are persisted and listed correctly.

## [0.1.0] - 2026-11-02

First runnable extraction of the user center from `micro-one-api` (baseline
`4116899a`).

### Added

- Standalone Kratos service with HTTP `/api/v1` and internal gRPC `:9090`,
  Wire assembly, MySQL migrations, Redis-backed challenges/rate limiting,
  SMTP/console mail adapter and SPA hosting.
- Account lifecycle: registration with email challenge, password login,
  password reset, profile update, enable/disable/archive, CSV export with
  permission rechecks.
- Security: bcrypt credentials, TOTP + recovery codes, step-up proofs,
  one-time email challenges, security events, admin MFA reset.
- Sessions: opaque HttpOnly cookie sessions, identity version validation,
  idle/absolute expiry, self-service and admin revocation, active session
  roles with constraint checks.
- IAM: resource/permission catalog, roles, inheritance, scoped assignments,
  explicit deny, validity windows, separation-of-duty constraints, menus,
  batch assignment, explain/simulate, policy revisions and immutable audit.
- React 19 SPA with user portal and admin console, generated OpenAPI types,
  CSRF-aware API client and permission-gated navigation.
- Tests: domain authorization, data repositories on SQLite, end-to-end HTTP
  flows including CSRF, scoped admin access, revision conflicts, export
  download and full MFA login.
- Dockerfile, docker-compose (MySQL/Redis/migrate/app), Makefile, dev scripts
  and architecture/API/data/migration/operations/security documentation.

### Known limitations

See `docs/security.md` §4 and `README.md` §实现范围与已知差异:
admin MFA enforcement, forced first password change, OAuth provider login,
legacy import tooling, outbox webhook delivery and delegation management are
not delivered in 0.1.0.
