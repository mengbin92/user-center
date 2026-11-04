-- 006: organization-scoped IAM contexts and tenant isolation (V2.3).
--
-- Roles and assignments gain an explicit authorization context. Existing rows
-- are platform policy and are backfilled by the column default. Organization
-- rows are only ever read or written with their context in the WHERE clause.

ALTER TABLE iam_roles
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id BIGINT NOT NULL DEFAULT 0,
    DROP INDEX uk_iam_roles_code,
    ADD UNIQUE KEY uk_iam_roles_context_code (context_type, context_id, code),
    ADD KEY idx_iam_roles_context (context_type, context_id, status);

ALTER TABLE iam_user_roles
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id BIGINT NOT NULL DEFAULT 0,
    ADD KEY idx_iam_user_roles_context (context_type, context_id, user_id, status);

ALTER TABLE iam_audit_events
    ADD COLUMN organization_id BIGINT NOT NULL DEFAULT 0,
    ADD KEY idx_iam_audit_org (organization_id, occurred_at);
