// Authenticated read scenarios: session validation + one business query.
//
// Each run targets exactly one endpoint (SCENARIO=me|admin|org) so the numbers
// are not polluted by another endpoint's row contention. The session pool is
// built once by prepare.py and shared across scenarios, because the login
// endpoint is rate limited at 30/5min per IP — logging 24 accounts in every
// scenario would measure the limiter, not the read path.
import http from 'k6/http';
import { check } from 'k6';
import { poolFor, summarise } from './lib.js';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const ORG_ID = __ENV.ORG_ID || '';
const SCENARIO = __ENV.SCENARIO || 'me';

// open() only works in the init context; the file is written by run.sh before
// k6 starts.
const sessions = JSON.parse(open(__ENV.SESSIONS_FILE));

const paths = {
  me: '/api/v1/me/authorization',
  admin: '/api/v1/admin/users?page_size=20',
  org: ORG_ID ? `/api/v1/orgs/${ORG_ID}/members` : '',
};

if (!paths[SCENARIO]) {
  throw new Error(`SCENARIO must be one of me|admin|org and ORG_ID must be set for org (got "${SCENARIO}", org "${ORG_ID}")`);
}

export const options = {
  vus: Number(__ENV.VUS || 16),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    // A non-2xx here means a broken session or a rejected request, not load.
    http_req_failed: ['rate<0.001'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(50)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  if (sessions.length === 0) {
    throw new Error('session pool is empty');
  }
  return { pool: sessions };
}

export default function (data) {
  const session = poolFor(data.pool);
  const res = http.get(BASE_URL + paths[SCENARIO], {
    headers: { Cookie: session.cookie },
    tags: { name: SCENARIO },
  });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  return summarise(data);
}
