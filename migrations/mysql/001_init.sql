-- 001_init.sql — user-center initial MySQL schema.
-- Seeds are applied by `cmd/migrate` in Go (data.SeedCatalog) so the same
-- catalog is available to SQLite tests.

CREATE TABLE IF NOT EXISTS users (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(128) NOT NULL,
    username_normalized VARCHAR(128) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    email VARCHAR(254) NULL,
    email_normalized VARCHAR(254) NULL,
    email_verified_at DATETIME(3) NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'enabled',
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    identity_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    archived_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username_normalized (username_normalized),
    UNIQUE KEY uk_users_email_normalized (email_normalized),
    KEY idx_users_status_id (status, id),
    KEY idx_users_created_id (created_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(255) NOT NULL DEFAULT '',
    algorithm VARCHAR(32) NOT NULL DEFAULT 'bcrypt',
    password_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS identity_mfa (
    user_id BIGINT NOT NULL,
    secret_ciphertext VARCHAR(512) NOT NULL DEFAULT '',
    key_version INT NOT NULL DEFAULT 1,
    pending_secret VARCHAR(512) NOT NULL DEFAULT '',
    pending_session VARCHAR(64) NOT NULL DEFAULT '',
    pending_until DATETIME(3) NULL,
    recovery_hashes TEXT NULL,
    last_step BIGINT NOT NULL DEFAULT 0,
    failures INT NOT NULL DEFAULT 0,
    locked_until DATETIME(3) NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_oauth_identities (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    provider VARCHAR(32) NOT NULL,
    provider_subject VARCHAR(191) NOT NULL,
    issuer VARCHAR(191) NOT NULL DEFAULT '',
    display VARCHAR(191) NOT NULL DEFAULT '',
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_oauth_identity (provider, issuer, provider_subject),
    KEY idx_oauth_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_sessions (
    id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    application_code VARCHAR(64) NOT NULL,
    credential_hash CHAR(64) NOT NULL,
    user_agent VARCHAR(255) NOT NULL DEFAULT '',
    ip_masked VARCHAR(64) NOT NULL DEFAULT '',
    issued_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    idle_expires_at DATETIME(3) NOT NULL,
    revoked_at DATETIME(3) NULL,
    identity_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sessions_credential_hash (credential_hash),
    KEY idx_sessions_user_valid (user_id, revoked_at, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_session_roles (
    session_id VARCHAR(64) NOT NULL,
    role_id BIGINT NOT NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (session_id, role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL DEFAULT 0,
    session_id VARCHAR(64) NOT NULL DEFAULT '',
    kind VARCHAR(32) NOT NULL,
    result VARCHAR(16) NOT NULL,
    ip_masked VARCHAR(64) NOT NULL DEFAULT '',
    user_agent_summary VARCHAR(255) NOT NULL DEFAULT '',
    request_id VARCHAR(64) NOT NULL DEFAULT '',
    occurred_at DATETIME(3) NOT NULL,
    PRIMARY KEY (event_id),
    KEY idx_security_user_time (user_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_flow_completions (
    challenge_id VARCHAR(64) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    user_id BIGINT NOT NULL,
    result_ref VARCHAR(128) NOT NULL DEFAULT '',
    completed_at DATETIME(3) NOT NULL,
    PRIMARY KEY (challenge_id, purpose)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_policy_state (
    id BIGINT NOT NULL,
    policy_revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    catalog_revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    authorization_mode VARCHAR(16) NOT NULL DEFAULT 'iam',
    cutover_state VARCHAR(16) NOT NULL DEFAULT 'complete',
    cutover_batch_id VARCHAR(64) NOT NULL DEFAULT '',
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_resources (
    id BIGINT NOT NULL AUTO_INCREMENT,
    code VARCHAR(128) NOT NULL,
    name VARCHAR(128) NOT NULL,
    owner VARCHAR(64) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uk_iam_resources_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_permissions (
    id BIGINT NOT NULL AUTO_INCREMENT,
    resource_id BIGINT NOT NULL,
    code VARCHAR(128) NOT NULL,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT '',
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    binding VARCHAR(16) NOT NULL DEFAULT 'unbound',
    supported_scopes TEXT NULL,
    context_types TEXT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    description VARCHAR(512) NOT NULL DEFAULT '',
    sort INT NOT NULL DEFAULT 0,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_iam_permissions_code (code),
    KEY idx_iam_permissions_resource (resource_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_roles (
    id BIGINT NOT NULL AUTO_INCREMENT,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512) NOT NULL DEFAULT '',
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    max_members BIGINT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    creation_delegation_id BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_iam_roles_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_role_permissions (
    role_id BIGINT NOT NULL,
    operation VARCHAR(128) NOT NULL,
    effect VARCHAR(16) NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (role_id, operation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_role_inheritance (
    role_id BIGINT NOT NULL,
    inherits_role_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, inherits_role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_user_roles (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    boundary TEXT NOT NULL,
    starts_at DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    origin VARCHAR(32) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    assigned_by BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_iam_user_roles_user (user_id, status, expires_at),
    KEY idx_iam_user_roles_role (role_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_role_constraints (
    id BIGINT NOT NULL AUTO_INCREMENT,
    kind VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    role_ids TEXT NOT NULL,
    max_count BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_menu_items (
    id BIGINT NOT NULL AUTO_INCREMENT,
    parent_id BIGINT NOT NULL DEFAULT 0,
    route_key VARCHAR(128) NOT NULL,
    name VARCHAR(128) NOT NULL,
    icon_key VARCHAR(64) NOT NULL DEFAULT '',
    sort INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    required_all TEXT NULL,
    required_any TEXT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_iam_menu_route (route_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_audit_events (
    event_id VARCHAR(64) NOT NULL,
    actor_user_id BIGINT NOT NULL DEFAULT 0,
    actor_service_id VARCHAR(64) NOT NULL DEFAULT '',
    actor_session_id VARCHAR(64) NOT NULL DEFAULT '',
    action VARCHAR(128) NOT NULL,
    target VARCHAR(191) NOT NULL DEFAULT '',
    before_data TEXT NULL,
    after_data TEXT NULL,
    diff TEXT NULL,
    result VARCHAR(16) NOT NULL,
    reason VARCHAR(512) NOT NULL DEFAULT '',
    request_id VARCHAR(64) NOT NULL DEFAULT '',
    authorization_versions TEXT NULL,
    occurred_at DATETIME(3) NOT NULL,
    PRIMARY KEY (event_id),
    KEY idx_audit_time (occurred_at, event_id),
    KEY idx_audit_actor (actor_user_id, occurred_at),
    KEY idx_audit_action (action, occurred_at),
    KEY idx_audit_target (target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_settings (
    name VARCHAR(64) NOT NULL,
    `value` TEXT NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_email_settings (
    name VARCHAR(64) NOT NULL,
    `value` TEXT NOT NULL,
    secret TEXT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS export_jobs (
    id BIGINT NOT NULL AUTO_INCREMENT,
    kind VARCHAR(32) NOT NULL,
    actor_user_id BIGINT NOT NULL,
    actor_session_id VARCHAR(64) NOT NULL DEFAULT '',
    scope_snapshot VARCHAR(255) NOT NULL DEFAULT '',
    requested_fields TEXT NULL,
    status VARCHAR(16) NOT NULL,
    artifact_name VARCHAR(255) NOT NULL DEFAULT '',
    error VARCHAR(512) NOT NULL DEFAULT '',
    created_at DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_export_actor (actor_user_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS event_outbox (
    event_id VARCHAR(64) NOT NULL,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id BIGINT NOT NULL,
    aggregate_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
    event_type VARCHAR(64) NOT NULL,
    schema_version INT NOT NULL DEFAULT 1,
    payload TEXT NOT NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (event_id),
    KEY idx_outbox_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS event_deliveries (
    event_id VARCHAR(64) NOT NULL,
    subscriber_id VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    next_retry_at DATETIME(3) NOT NULL,
    last_error VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (event_id, subscriber_id),
    KEY idx_delivery_retry (status, next_retry_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
