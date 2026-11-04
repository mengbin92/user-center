# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
