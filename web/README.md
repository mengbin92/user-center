# user-center web

React 19 + TypeScript + Vite + Tailwind CSS v4 SPA for the standalone
`user-center` Kratos service.

## Scripts

```bash
npm install
npm run dev        # http://127.0.0.1:5173, /api proxied to :8080
npm run build      # tsc -b && vite build -> dist/
npm run preview    # serves dist/ on :4173 with the same /api proxy
npm test           # vitest + @testing-library/react
npm run typecheck  # tsc -b
npm run generate:api  # regenerate src/lib/api-types.ts from ../openapi.yaml
```

The production build in `web/dist` is served by the backend SPA handler when
`WEB_DIST` is unset. `VITE_API_BASE` may be set to an absolute API origin; by
default requests are same-origin.

## Security model

- The session lives in the HttpOnly `uc_session` cookie. No token is ever
  written to `localStorage` or `sessionStorage`.
- Mutating requests read the non-HttpOnly `uc_csrf` cookie and send
  `X-CSRF-Token`; every request sends `X-Request-ID` from `crypto.randomUUID()`.
- `401` clears the React Query cache and returns to `/login`; `403` renders an
  explicit no-permission state; `409` opens a revision/policy conflict dialog
  with the server-provided `current_revision` / `current_policy_revision` and a
  refresh action; `429` shows a retry message.
- High-risk mutations require a reason. When the API answers
  `STEP_UP_REQUIRED`, the client prompts for password + MFA/recovery code
  (`POST /api/v1/me/security:verify`) and retries the original mutation once.

## Layout

- `src/lib` — generated OpenAPI types, typed API client, HTTP/CSRF layer, auth
  projection, permission helpers, query client, mutation wrapper.
- `src/components` — Tailwind primitives (Button, Input, Card, Dialog, Table,
  Badge, Toast, Tabs, ReasonDialog, StepUpDialog, ConflictDialog).
- `src/features/auth` — public login/MFA, registration challenge, password
  reset, legal pages and OAuth callback placeholder.
- `src/features/account` — profile, security (MFA/recovery/email/step-up),
  sessions, session roles, security activity.
- `src/features/admin` — overview, users + detail, IAM roles/permissions/
  assignments/constraints/menus/explain, audits, exports, auth/email settings.
