-- 012: password policy history and expiry (V2.5 S6).
--
-- password_history stores bcrypt hashes, never plaintext or reversibly
-- encrypted values: a table of recoverable old passwords is a liability, and
-- bcrypt is all that is needed to answer "has this password been used before".
-- Rows are folded to the configured window on every write, so the table stays
-- bounded at (users x history_count) instead of growing forever.
--
-- password_changed_at is nullable on purpose: existing rows stay NULL and are
-- treated as "age unknown" rather than "expired", so enabling expiry never
-- locks out accounts that predate this migration.

ALTER TABLE user_credentials
    ADD COLUMN password_changed_at DATETIME(3) NULL;

CREATE TABLE IF NOT EXISTS password_history (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_password_history_user (user_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
