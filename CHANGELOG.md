# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Enforce actor-aware scopes, root protection, delegation ceilings, atomic
  batch authorization, current policy/target revisions and non-empty reasons.
- Prevent challenge, TOTP, recovery-code and stale step-up replay; fail closed
  on authentication dependencies and keep sensitive writes with their audit.
- Recheck export authority, restrict integration callers and session revocation,
  remove the static integration-token bypass, and harden mail and startup secrets.
- Isolate frontend sessions and cached authorization; keep legacy governance
  roles pending until explicitly reassigned with a verified boundary.

### Changed

- Use strict ProtoJSON and decimal-string 64-bit values; update generated API
  types and management preconditions together.
- Add OAuth-only identity re-verification and explicit offline root MFA rescue.
- Recover Outbox leases and historical backlog; fix Docker command overrides.
- Record findings, compatibility changes and validation in
  [the review report](docs/code-review-2026-11-03.md).

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
  MFA enforcement, forced password change, integration clients + webhook
  delivery, legacy import, assignments and delegations.

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
