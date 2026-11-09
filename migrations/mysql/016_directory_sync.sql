-- 016: enterprise directory synchronization (V2.6).
-- A source is bound to exactly one organization. Non-sensitive connection
-- settings live in config_json; the external credential is stored encrypted in
-- secret_enc and is never returned by any read endpoint.
CREATE TABLE IF NOT EXISTS directory_sources (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    kind VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    config_json TEXT NOT NULL,
    secret_enc TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    cursor_value VARCHAR(512) NOT NULL DEFAULT '',
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_by BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    last_run_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_directory_source_name (organization_id, name),
    KEY idx_directory_sources_due (status, last_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per run is the audit trail for reconciliation. The report carries
-- per-object outcomes so a partial failure never looks like a clean success.
CREATE TABLE IF NOT EXISTS directory_sync_runs (
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

-- Tracks which local row each external object produced. last_seen_at is the
-- reconciliation watermark: objects absent from a full snapshot are stale.
CREATE TABLE IF NOT EXISTS directory_objects (
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
