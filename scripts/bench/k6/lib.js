// Shared helpers for the benchmark scenarios.
import http from 'k6/http';

// k6 joins repeated Set-Cookie headers, so a plain regex is enough for the two
// cookies we care about (both base64url / hex, no commas).
// cookieFrom extracts one cookie value from the joined Set-Cookie header.
export function cookieFrom(res, name) {
  const raw = res.headers['Set-Cookie'] || '';
  const match = raw.match(new RegExp('(?:^|[,\\s])' + name + '=([^;,\\s]+)'));
  return match ? match[1] : '';
}

// login creates one independent session and returns the Cookie header to send
// with every subsequent request. Tagged so setup traffic is easy to spot.
export function login(baseURL, username, password) {
  const ctx = http.get(`${baseURL}/api/v1/auth/context`, { tags: { name: 'setup' } });
  const csrf = cookieFrom(ctx, 'uc_csrf');
  if (!csrf) {
    throw new Error(`no csrf cookie for ${username} (status ${ctx.status})`);
  }
  const res = http.post(
    `${baseURL}/api/v1/auth/login`,
    JSON.stringify({ username: username, password: password }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
        Cookie: `uc_csrf=${csrf}`,
      },
      tags: { name: 'setup' },
    },
  );
  if (res.status !== 200) {
    throw new Error(`login failed for ${username}: ${res.status} ${res.body}`);
  }
  const session = cookieFrom(res, 'uc_session');
  if (!session) {
    throw new Error(`no session cookie for ${username}`);
  }
  return { username: username, cookie: `uc_csrf=${csrf}; uc_session=${session}` };
}

// accounts builds the credential list from the seed convention:
// <prefix><2-digit index> with one shared password.
export function accounts(prefix, count, password) {
  const out = [];
  for (let i = 1; i <= count; i++) {
    out.push({ user: prefix + String(i).padStart(2, '0'), pass: password });
  }
  return out;
}

// poolFor picks one session per VU. Sharing a single session would serialise
// every request on the session row's last-seen update, which is not the shape
// of real traffic.
export function poolFor(pool) {
  return pool[(__VU - 1) % pool.length];
}

function round(value, digits) {
  const factor = Math.pow(10, digits);
  return Math.round(value * factor) / factor;
}

// summarise writes one JSON file per scenario. Returning a file map instead of
// console.log keeps the k6 logrus escaping (\" inside msg="...") out of the
// parsing path.
export function summarise(data) {
  const m = data.metrics;
  const value = (metric, key, fallback) => {
    const entry = m[metric];
    if (!entry || !entry.values || entry.values[key] === undefined) {
      return fallback;
    }
    return entry.values[key];
  };
  const result = {
    scenario: __ENV.SCENARIO || 'unknown',
    vus: Number(__ENV.VUS || 0),
    duration: __ENV.DURATION || '',
    requests: value('http_reqs', 'count', 0),
    qps: round(value('http_reqs', 'rate', 0), 1),
    p50_ms: round(value('http_req_duration', 'p(50)', 0), 2),
    p95_ms: round(value('http_req_duration', 'p(95)', 0), 2),
    p99_ms: round(value('http_req_duration', 'p(99)', 0), 2),
    failed_pct: round(value('http_req_failed', 'rate', 0) * 100, 2),
    status_429: value('status_429', 'count', 0),
  };
  const out = {};
  out[__ENV.RESULT_FILE] = JSON.stringify(result) + '\n';
  return out;
}
