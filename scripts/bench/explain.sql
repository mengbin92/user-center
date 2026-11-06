-- Index audit fixture: 20k users plus their credentials, sessions, role
-- assignments and MFA state.
--
-- Loaded into a throwaway database (usercenter_explain) after `migrate`, so the
-- EXPLAIN output in docs/performance.md reflects a table size where the
-- optimiser can no longer hide a missing index behind a full scan of 24 rows.
--
-- Usage:
--   docker exec -i -e MYSQL_PWD=... <container> mysql -uroot usercenter_explain < scripts/bench/explain.sql

SET cte_max_recursion_depth = 100000;

-- Re-runnable: the fixture owns these tables in a throwaway database.
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE users;
TRUNCATE TABLE user_credentials;
TRUNCATE TABLE iam_sessions;
TRUNCATE TABLE iam_session_roles;
TRUNCATE TABLE iam_user_roles;
TRUNCATE TABLE identity_mfa;
SET FOREIGN_KEY_CHECKS = 1;

INSERT INTO users (username, username_normalized, display_name, email, email_normalized,
                   email_verified_at, status, revision, identity_version, created_at, updated_at)
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 20000)
SELECT CONCAT('load', n), CONCAT('load', n), CONCAT('Load User ', n),
       CONCAT('load', n, '@example.com'), CONCAT('load', n, '@example.com'),
       NOW(3) - INTERVAL n SECOND,
       IF(n % 20 = 0, 'disabled', 'enabled'), 1, 1,
       NOW(3) - INTERVAL n SECOND, NOW(3)
FROM seq;

INSERT INTO user_credentials (user_id, password_hash, algorithm, password_version, must_change_password, revision, updated_at)
SELECT id, '$2a$10$abcdefghijklmnopqrstuv', 'bcrypt', 1, 0, 1, NOW(3) FROM users;

INSERT INTO iam_sessions (id, user_id, application_code, credential_hash, user_agent, ip_masked,
                          issued_at, last_seen_at, expires_at, idle_expires_at, identity_version, revision)
SELECT CONCAT('bench-session-', LPAD(u.id, 8, '0')), u.id, 'user-center',
       SHA2(CONCAT('session-', u.id), 256), 'bench', '127.0.0.0/8',
       NOW(3) - INTERVAL (u.id % 3600) SECOND, NOW(3),
       NOW(3) + INTERVAL 12 HOUR, NOW(3) + INTERVAL 1 HOUR, 1, 1
FROM users AS u;

INSERT INTO iam_session_roles (session_id, role_id, created_at)
SELECT s.id, r.id, NOW(3)
FROM iam_sessions AS s
JOIN iam_roles AS r ON r.code = 'member' AND r.context_type = 'platform';

INSERT INTO iam_user_roles (user_id, role_id, boundary, starts_at, status, origin, revision, assigned_by, created_at, context_type, context_id)
SELECT u.id, r.id, '{"all":false,"self":true}', NOW(3) - INTERVAL 1 DAY, 'active', 'bootstrap', 1, 0, NOW(3) - INTERVAL 1 DAY, 'platform', 0
FROM users AS u
JOIN iam_roles AS r ON r.code = 'member' AND r.context_type = 'platform';

INSERT INTO identity_mfa (user_id, secret_ciphertext, key_version, revision)
SELECT id, IF(id % 3 = 0, 'ciphertext-placeholder', ''), 1, 1 FROM users;

ANALYZE TABLE users, user_credentials, iam_sessions, iam_user_roles, identity_mfa;

-- Every query below is one that a request actually issues; see the "index
-- audit" section of docs/performance.md for the expected plan.

SELECT '--- users count' AS audit;
EXPLAIN SELECT count(*) FROM users;

SELECT '--- users page (order by created_at desc, id desc)' AS audit;
EXPLAIN SELECT * FROM users ORDER BY created_at DESC, id DESC LIMIT 20;

SELECT '--- users page scoped by status' AS audit;
EXPLAIN SELECT * FROM users WHERE status = 'enabled' ORDER BY created_at DESC, id DESC LIMIT 20;

SELECT '--- users page scoped by allowed ids' AS audit;
-- MySQL 8.4 rejects LIMIT inside an IN subquery, so the id set is written out
-- the way the repository builds it (scoped(id IN (...))).
EXPLAIN SELECT * FROM users
WHERE id IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
             26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50)
ORDER BY created_at DESC, id DESC LIMIT 20;

SELECT '--- users keyword search (lower like)' AS audit;
EXPLAIN SELECT * FROM users WHERE LOWER(username) LIKE '%load12%' OR LOWER(display_name) LIKE '%load12%';

SELECT '--- users filter by role' AS audit;
EXPLAIN SELECT * FROM users WHERE id IN (
  SELECT user_id FROM iam_user_roles
  WHERE role_id = 3 AND status = 'active' AND starts_at <= NOW(3) AND (expires_at IS NULL OR expires_at > NOW(3))
);

SELECT '--- session lookup by credential hash' AS audit;
EXPLAIN SELECT * FROM iam_sessions WHERE credential_hash = SHA2('session-7', 256) LIMIT 1;

SELECT '--- active roles for a session' AS audit;
-- A literal id, not UUID(): a function call on the right-hand side hides the
-- primary key from the optimiser and the plan degrades to a full scan.
EXPLAIN SELECT * FROM iam_session_roles WHERE session_id = 'bench-session-00000007' ORDER BY role_id;

SELECT '--- roles for one user (platform)' AS audit;
EXPLAIN SELECT r.id, r.code, r.name FROM iam_user_roles AS ur
JOIN iam_roles AS r ON r.id = ur.role_id
WHERE ur.user_id = 7 AND ur.status = 'active' AND r.status = 'active'
  AND ur.context_type = 'platform' AND ur.context_id = 0;

SELECT '--- assignments for a page of users' AS audit;
EXPLAIN SELECT ur.user_id, r.id, r.code, r.name FROM iam_user_roles AS ur
JOIN iam_roles AS r ON r.id = ur.role_id
WHERE ur.user_id IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20);

SELECT '--- mfa state for a page of users' AS audit;
EXPLAIN SELECT * FROM identity_mfa WHERE user_id IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20);

SELECT '--- permission by code' AS audit;
EXPLAIN SELECT * FROM iam_permissions WHERE code = 'identity.user.list' LIMIT 1;

SELECT '--- constraints (full read)' AS audit;
EXPLAIN SELECT * FROM iam_role_constraints ORDER BY id;
