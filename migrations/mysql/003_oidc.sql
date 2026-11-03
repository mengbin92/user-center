-- 003: standard OIDC provider tables.

CREATE TABLE IF NOT EXISTS oidc_clients (
    id BIGINT NOT NULL AUTO_INCREMENT,
    client_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    service_owner VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    secret_hash CHAR(64) NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL,
    scopes TEXT NOT NULL,
    public BOOLEAN NOT NULL DEFAULT FALSE,
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds INT NOT NULL DEFAULT 900,
    refresh_token_ttl_seconds INT NOT NULL DEFAULT 86400,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_oidc_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    code_hash CHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    redirect_uri VARCHAR(512) NOT NULL,
    scope VARCHAR(512) NOT NULL,
    nonce VARCHAR(255) NOT NULL DEFAULT '',
    code_challenge VARCHAR(128) NOT NULL DEFAULT '',
    code_challenge_method VARCHAR(8) NOT NULL DEFAULT '',
    auth_time DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    consumed_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (code_hash),
    KEY idx_oidc_code_client (client_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
    token_hash CHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    scope VARCHAR(512) NOT NULL,
    auth_time DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    revoked_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (token_hash),
    KEY idx_oidc_refresh_client (client_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
