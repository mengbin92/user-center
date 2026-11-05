-- 010: WebAuthn / Passkey credentials (V2.4 R13).
-- Only the public COSE key is stored; no attestation certificate chain is kept
-- (attestation format is restricted to "none").

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    name VARCHAR(128) NOT NULL DEFAULT '',
    public_key TEXT NOT NULL,
    sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    aaguid VARCHAR(64) NOT NULL DEFAULT '',
    transports VARCHAR(255) NOT NULL DEFAULT '',
    created_at DATETIME(3) NOT NULL,
    last_used_at DATETIME(3) NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_webauthn_credential (credential_id),
    KEY idx_webauthn_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
