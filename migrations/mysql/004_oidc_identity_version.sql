-- Grants created before this migration have no identity proof and must be reissued.
ALTER TABLE oidc_authorization_codes ADD COLUMN identity_version BIGINT UNSIGNED NOT NULL DEFAULT 0, ADD KEY idx_oidc_code_expiry (expires_at);
ALTER TABLE oidc_refresh_tokens ADD COLUMN identity_version BIGINT UNSIGNED NOT NULL DEFAULT 0, ADD KEY idx_oidc_refresh_expiry (expires_at);
ALTER TABLE oidc_refresh_tokens ADD COLUMN family_id VARCHAR(64) NOT NULL DEFAULT '', ADD KEY idx_oidc_refresh_family (client_id, family_id);
