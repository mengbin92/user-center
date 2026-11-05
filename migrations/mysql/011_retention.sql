-- 011: personal-data retention (V2.4 R14).
-- anonymized_at makes cleanup idempotent; legal holds exempt an archived
-- account from the retention job until explicitly released.

ALTER TABLE users
    ADD COLUMN anonymized_at DATETIME(3) NULL,
    ADD KEY idx_users_retention (status, archived_at, anonymized_at);

CREATE TABLE IF NOT EXISTS user_legal_holds (
    user_id BIGINT NOT NULL,
    reason VARCHAR(512) NOT NULL,
    created_at DATETIME(3) NOT NULL,
    released_at DATETIME(3) NULL,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
