// Unauthenticated paths: the CSRF bootstrap and the login endpoint.
//
// These are deliberately NOT throughput scenarios for login. The service rate
// limits logins at 30/5min per client IP and 10 failures/5min per account, both
// hard-coded, so a realistic VU count saturates the limiter within seconds.
// What this measures is the cost of a rejected login and the limiter's actual
// behaviour, which is what the docs need to state honestly.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { cookieFrom, summarise } from './lib.js';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const USER = __ENV.USER || 'bench01';
const PASSWORD = __ENV.PASSWORD || 'BenchPass-12345';
const SCENARIO = __ENV.SCENARIO || 'context';

const status429 = new Counter('status_429');

export const options = {
  vus: Number(__ENV.VUS || 8),
  duration: __ENV.DURATION || '20s',
  thresholds: {
    // 429 is an expected outcome here, so the failure rate cannot be tight.
    http_req_failed: ['rate<1'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(50)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  if (SCENARIO === 'context') {
    const res = http.get(`${BASE_URL}/api/v1/auth/context`, { tags: { name: 'context' } });
    check(res, { 'status is 200': (r) => r.status === 200 });
    return;
  }

  // login: CSRF bootstrap then a real credential exchange.
  const ctx = http.get(`${BASE_URL}/api/v1/auth/context`, { tags: { name: 'context' } });
  const csrf = cookieFrom(ctx, 'uc_csrf');
  if (!csrf) {
    throw new Error('no csrf cookie');
  }
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ username: USER, password: PASSWORD }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
        Cookie: `uc_csrf=${csrf}`,
      },
      tags: { name: 'login' },
    },
  );
  if (res.status === 429) {
    status429.add(1);
  }
  check(res, { 'login accepted or rate limited': (r) => r.status === 200 || r.status === 429 });
}

export function handleSummary(data) {
  return summarise(data);
}
