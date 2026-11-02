# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
