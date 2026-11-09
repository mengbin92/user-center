-- 017: registry of per-organization tenant schemas (V2.6 phase 4 cutover).
-- Cross-tenant queries (my organizations, owned-organization quota, platform
-- audit view) need to know which organization databases exist. The registry
-- lives on the platform schema and is the only cross-tenant index.
CREATE TABLE IF NOT EXISTS tenant_schemas (
    organization_id BIGINT NOT NULL,
    schema_name VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ready',
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (organization_id),
    UNIQUE KEY uk_tenant_schema_name (schema_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
