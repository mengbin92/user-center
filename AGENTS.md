# Repository Guidelines

`user-center` is a standalone Kratos service + React SPA extracted from
`micro-one-api`. It must never import the original repository.

## Layering

```text
client → DTO → service → DO → biz → DO → data → PO → MySQL
                              ▲             ▲
                              │ repo IF     │ implements
                              └─────────────┘
```

- `service`: proto ↔ DO only. Parses HTTP metadata, sets cookies, calls one
  usecase. Never touches `data` or `*gorm.DB`.
- `biz`: owns DO, usecases, repo interfaces, authorization decisions, typed
  errors, audit/outbox transaction semantics. Never imports proto HTTP stubs
  or persistence packages.
- `data`: owns PO and repo implementations. Maps driver errors to `biz`
  errors. Never imports `service` or protobuf DTOs.
- `domain/authorization`: pure types and algorithms; no storage/framework.
- `internal/wiring` / `cmd`: the only assembly point (Wire).
- `platform/httpx`: verified transport metadata shared by server and service.

## Add a resource

1. Define the proto in `api/usercenter/v1/`, then `make api`.
2. Add DO + repo interface + usecase in `biz`.
3. Implement the repo in `data`, returning the `biz` interface.
4. Add DTO conversion in `service`.
5. Register HTTP/gRPC in `internal/server`, Wire providers in each package.
6. `make wire`, `go test ./...`.

## Security invariants

- IDs/revisions are decimal strings on the wire; int64 internally.
- Every management mutation: `expected_revision`, `expected_policy_revision`
  where applicable, and `reason`.
- Authorization decisions are server-side from DB facts; the SPA projection
  is not an authority.
- Never log or return password hashes, session tokens, TOTP secrets, recovery
  codes, or verification codes.
- High-risk operations require step-up; archive/reset/role writes must write
  an audit event in the same transaction.
- Use `pkg/jsonx` for JSON in non-test code.

## Generated files

`make api`, `make config`, `make wire` regenerate proto/Wire outputs. Do not
hand-edit `*.pb.go`, `*_grpc.pb.go`, `*_http.pb.go`, `openapi.yaml`, or
`wire_gen.go`.

## Tests

`go test ./...` (domain, repos on SQLite, HTTP integration), `cd web && npm test`.
Add tests with behavior changes; security-sensitive paths need an HTTP-level
test proving the denial case, not only the happy path.
