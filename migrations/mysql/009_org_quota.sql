-- 009: index for the per-user organization quota check (V2.4 R12).
-- The quota guard locks the owner's organization rows inside the create
-- transaction; the index keeps that lock range small.

ALTER TABLE organizations
    ADD KEY idx_organizations_owner (created_by, status);
