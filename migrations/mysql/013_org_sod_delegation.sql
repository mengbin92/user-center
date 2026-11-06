-- 013: organization-scoped role constraints and delegations (V2.5 S12).
--
-- Constraints and delegations get the same (context_type, context_id) pair that
-- roles and assignments already use, rather than a second way of expressing
-- scope. The DEFAULT is the backfill: every existing row becomes platform
-- policy, which is exactly what it meant before this migration, so no UPDATE
-- statement is needed and re-running the migration cannot move a row between
-- contexts.
--
-- Platform and organization role ids share one AUTO_INCREMENT sequence in
-- iam_roles, so a constraint's role_ids can never accidentally match a role in
-- another context. That is a property of the schema, not of the algorithm:
-- code filters by context explicitly (see biz.ConstraintsForContext) so the
-- isolation does not depend on how ids happen to be allocated.

ALTER TABLE iam_role_constraints
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_constraints_context (context_type, context_id);

ALTER TABLE iam_delegations
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_delegations_context (context_type, context_id);
