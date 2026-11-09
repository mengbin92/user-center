-- Tenant schema tables (MySQL). {{schema}} is replaced with the
-- organization's schema name at provisioning time. This file is the DDL
-- that creates a tenant database; keep it in sync with platform migrations.

CREATE TABLE IF NOT EXISTS {{schema}}.`organization_members` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role VARCHAR(16) NOT NULL,
    department_id BIGINT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    invited_by BIGINT NOT NULL DEFAULT 0,
    joined_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_organization_member (organization_id, user_id),
    KEY idx_organization_members_user (user_id, status),
    KEY idx_organization_members_department (organization_id, department_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`organization_departments` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    parent_id BIGINT NOT NULL DEFAULT 0,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_organization_department_code (organization_id, code),
    KEY idx_organization_departments_parent (organization_id, parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`organization_invitations` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_roles` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_role_permissions` (
    role_id BIGINT NOT NULL,
    operation VARCHAR(128) NOT NULL,
    effect VARCHAR(16) NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (role_id, operation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_role_inheritance` (
    role_id BIGINT NOT NULL,
    inherits_role_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, inherits_role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_user_roles` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_role_constraints` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    kind VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    role_ids TEXT NOT NULL,
    max_count BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_delegations` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`iam_audit_events` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`scim_identities` (
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

CREATE TABLE IF NOT EXISTS {{schema}}.`scim_groups` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_scim_group_name (organization_id, display_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`scim_group_members` (
    group_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    KEY idx_scim_group_member_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`directory_objects` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    source_id BIGINT NOT NULL,
    organization_id BIGINT NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    local_id BIGINT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_directory_object (source_id, external_id),
    KEY idx_directory_object_local (source_id, local_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS {{schema}}.`directory_sync_runs` (
    id BIGINT NOT NULL AUTO_INCREMENT,
    source_id BIGINT NOT NULL,
    organization_id BIGINT NOT NULL,
    mode VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    started_at DATETIME(3) NOT NULL,
    finished_at DATETIME(3) NULL,
    fetched INT NOT NULL DEFAULT 0,
    created_count INT NOT NULL DEFAULT 0,
    updated_count INT NOT NULL DEFAULT 0,
    disabled_count INT NOT NULL DEFAULT 0,
    unchanged_count INT NOT NULL DEFAULT 0,
    failed_count INT NOT NULL DEFAULT 0,
    cursor_before VARCHAR(512) NOT NULL DEFAULT '',
    cursor_after VARCHAR(512) NOT NULL DEFAULT '',
    report_json TEXT NULL,
    error_text TEXT NULL,
    PRIMARY KEY (id),
    KEY idx_directory_runs_source (source_id, id DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
