-- 014: seed password_history for accounts that predate the history window.
--
-- 012 created the table empty, and the change path only records the NEW hash.
-- An account upgraded from 012 therefore had its current password outside the
-- window: after A -> B the user could set A again immediately, because A was
-- never recorded anywhere. A fresh account does not have this hole -- register
-- seeds the first hash -- so only pre-existing accounts needed the backfill.
--
-- created_at comes from password_changed_at when known and falls back to
-- updated_at. It is bookkeeping only: the window is trimmed by id, and the
-- "age unknown" meaning of a NULL password_changed_at is deliberately NOT
-- changed here, so enabling expiry still cannot lock anyone out on upgrade day.
--
-- NOT EXISTS makes the statement idempotent: re-running the file (or resuming
-- after a partially applied attempt) cannot duplicate rows. 012 is left
-- untouched on purpose -- it has already been applied in the field.

INSERT INTO password_history (user_id, password_hash, created_at)
SELECT c.user_id, c.password_hash, COALESCE(c.password_changed_at, c.updated_at)
FROM user_credentials AS c
WHERE c.password_hash <> ''
  AND NOT EXISTS (SELECT 1 FROM password_history AS h WHERE h.user_id = c.user_id);
