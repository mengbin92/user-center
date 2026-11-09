-- 015: SCIM 2.0 provisioning (V2.6).
-- A SCIM bearer token is bound to exactly one organization. That binding is the
-- tenant boundary for every /scim/v2 request; there is no cross-tenant read or
-- write path. Only a digest of the token is stored.
CREATE TABLE IF NOT EXISTS scim_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    name VARCHAR(128) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    credential_version INT NOT NULL DEFAULT 1,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_by BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    last_used_at DATETIME(3) NULL,
    disabled_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_scim_token_hash (token_hash),
    KEY idx_scim_tokens_org (organization_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- externalId is the IdP's stable identifier. It is authoritative for matching:
-- a renamed or re-emailed user is still the same provisioning object. The
-- mapping is per (organization, kind), so two tenants can use the same
-- externalId without colliding.
CREATE TABLE IF NOT EXISTS scim_identities (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    kind VARCHAR(16) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    local_id BIGINT NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_scim_identity (organization_id, kind, external_id),
    UNIQUE KEY uk_scim_identity_local (organization_id, kind, local_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- SCIM Groups are a provisioning view over organization members. They are kept
-- separate from organization_departments, which carry a code/parent hierarchy
-- SCIM has no equivalent for.
CREATE TABLE IF NOT EXISTS scim_groups (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_scim_group_name (organization_id, display_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    KEY idx_scim_group_member_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
