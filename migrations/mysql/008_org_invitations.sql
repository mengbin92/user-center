-- 008: organization invitations (V2.4 R3).
--
-- Only the token hash is persisted. The e-mail is stored normalized (lowercase)
-- so acceptance can compare it with the logged-in account without ambiguity.

CREATE TABLE IF NOT EXISTS organization_invitations (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    email VARCHAR(254) NOT NULL,
    email_normalized VARCHAR(254) NOT NULL,
    role VARCHAR(16) NOT NULL,
    department_id BIGINT NULL,
    token_hash VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL,
    invited_by BIGINT NOT NULL DEFAULT 0,
    accepted_by BIGINT NOT NULL DEFAULT 0,
    expires_at DATETIME(3) NOT NULL,
    accepted_at DATETIME(3) NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_org_invitation_token (token_hash),
    KEY idx_org_invitation_org (organization_id, status),
    KEY idx_org_invitation_email (email_normalized)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
