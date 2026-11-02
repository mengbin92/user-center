-- 002: delegation, integration clients, legacy import batches.

CREATE TABLE IF NOT EXISTS iam_delegations (
    id BIGINT NOT NULL AUTO_INCREMENT,
    manager_role_id BIGINT NOT NULL,
    target_role_id BIGINT NOT NULL,
    target_kind VARCHAR(32) NOT NULL DEFAULT 'role',
    actions TEXT NOT NULL,
    target_user_scope TEXT NOT NULL,
    grant_ceiling TEXT NOT NULL,
    can_redelegate BOOLEAN NOT NULL DEFAULT FALSE,
    starts_at DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NULL,
    revoked_at DATETIME(3) NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_by BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_delegation_manager (manager_role_id, target_role_id, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS integration_clients (
    id BIGINT NOT NULL AUTO_INCREMENT,
    client_id VARCHAR(64) NOT NULL,
    code VARCHAR(64) NOT NULL,
    service_owner VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    credential_hash CHAR(64) NOT NULL,
    credential_version INT NOT NULL DEFAULT 1,
    allowed_methods TEXT NULL,
    event_subscriptions TEXT NULL,
    callback_url VARCHAR(512) NOT NULL DEFAULT '',
    expires_at DATETIME(3) NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_integration_client_id (client_id),
    UNIQUE KEY uk_integration_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS legacy_import_batches (
    batch_id VARCHAR(64) NOT NULL,
    source_commit VARCHAR(64) NOT NULL DEFAULT '',
    snapshot_position VARCHAR(128) NOT NULL DEFAULT '',
    counts TEXT NULL,
    fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    state VARCHAR(24) NOT NULL,
    error VARCHAR(512) NOT NULL DEFAULT '',
    created_at DATETIME(3) NOT NULL,
    completed_at DATETIME(3) NULL,
    PRIMARY KEY (batch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
