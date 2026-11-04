-- 007: OIDC consent records and RP-initiated logout whitelist (V2.4 R1/R2).
--
-- Consent is keyed by (client_id, user_id): one row per user-client pair holds
-- the scopes already granted. The authorize request that is waiting for a
-- decision lives in oidc_consent_requests; only the SHA-256 of the one-time
-- handle is stored, so a database leak cannot resume the flow.

CREATE TABLE IF NOT EXISTS oidc_consents (
    client_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (client_id, user_id),
    KEY idx_oidc_consent_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS oidc_consent_requests (
    handle_hash VARCHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    redirect_uri VARCHAR(512) NOT NULL,
    scope VARCHAR(512) NOT NULL,
    state VARCHAR(512) NOT NULL DEFAULT '',
    nonce VARCHAR(255) NOT NULL DEFAULT '',
    code_challenge VARCHAR(128) NOT NULL DEFAULT '',
    code_challenge_method VARCHAR(8) NOT NULL DEFAULT '',
    auth_time DATETIME(3) NOT NULL,
    identity_version BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    consumed_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (handle_hash),
    KEY idx_oidc_consent_request_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE oidc_clients
    ADD COLUMN post_logout_redirect_uris TEXT NULL;

-- Tenant audit exports reuse export_jobs and its signed download channel; the
-- owning organization keeps cross-tenant downloads out of reach.
ALTER TABLE export_jobs
    ADD COLUMN organization_id BIGINT NOT NULL DEFAULT 0,
    ADD KEY idx_export_jobs_org (organization_id, created_at);
