-- Tenant schema tables (SQLite, dev/test). {{schema}} is the ATTACHed
-- database name. Generated from the platform schema so both stay identical.

CREATE TABLE IF NOT EXISTS "{{schema}}"."organization_members" (`id` integer PRIMARY KEY AUTOINCREMENT,`organization_id` integer NOT NULL,`user_id` integer NOT NULL,`role` text NOT NULL,`department_id` integer,`status` text NOT NULL,`revision` integer NOT NULL DEFAULT 1,`invited_by` integer NOT NULL DEFAULT 0,`joined_at` datetime NOT NULL,`updated_at` datetime NOT NULL);

CREATE INDEX "{{schema}}"."idx_organization_members_organization_id" ON `organization_members`(`organization_id`);

CREATE INDEX "{{schema}}"."idx_organization_members_user_id" ON `organization_members`(`user_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."organization_departments" (`id` integer PRIMARY KEY AUTOINCREMENT,`organization_id` integer NOT NULL,`parent_id` integer NOT NULL DEFAULT 0,`code` text NOT NULL,`name` text NOT NULL,`status` text NOT NULL,`revision` integer NOT NULL DEFAULT 1,`created_at` datetime NOT NULL,`updated_at` datetime NOT NULL);

CREATE INDEX "{{schema}}"."idx_organization_departments_organization_id" ON `organization_departments`(`organization_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."organization_invitations" (`id` integer PRIMARY KEY AUTOINCREMENT,`organization_id` integer NOT NULL,`email` text NOT NULL,`email_normalized` text NOT NULL,`role` text NOT NULL,`department_id` integer,`token_hash` text NOT NULL,`status` text NOT NULL,`invited_by` integer NOT NULL DEFAULT 0,`accepted_by` integer NOT NULL DEFAULT 0,`expires_at` datetime NOT NULL,`accepted_at` datetime,`revision` integer NOT NULL DEFAULT 1,`created_at` datetime NOT NULL,`updated_at` datetime NOT NULL);

CREATE INDEX "{{schema}}"."idx_org_invitation_email" ON `organization_invitations`(`email_normalized`);

CREATE INDEX "{{schema}}"."idx_org_invitation_org" ON `organization_invitations`(`organization_id`,`status`);

CREATE UNIQUE INDEX "{{schema}}"."idx_organization_invitations_token_hash" ON `organization_invitations`(`token_hash`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_roles" (`id` integer PRIMARY KEY AUTOINCREMENT,`code` text NOT NULL,`name` text NOT NULL,`description` text,`builtin` numeric NOT NULL DEFAULT false,`status` text NOT NULL,`max_members` integer,`revision` integer NOT NULL DEFAULT 1,`creation_delegation_id` integer NOT NULL DEFAULT 0,`context_type` text NOT NULL DEFAULT "platform",`context_id` integer NOT NULL DEFAULT 0);

CREATE INDEX "{{schema}}"."idx_iam_roles_context" ON `iam_roles`(`context_type`,`context_id`);

CREATE UNIQUE INDEX "{{schema}}"."uk_iam_roles_context_code" ON `iam_roles`(`context_type`,`context_id`,`code`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_role_permissions" (`role_id` integer,`operation` text,`effect` text NOT NULL,`scope` text NOT NULL,PRIMARY KEY (`role_id`,`operation`));

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_role_inheritance" (`role_id` integer,`inherits_role_id` integer,PRIMARY KEY (`role_id`,`inherits_role_id`));

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_user_roles" (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL,`role_id` integer NOT NULL,`boundary` text NOT NULL,`starts_at` datetime NOT NULL,`expires_at` datetime,`status` text NOT NULL,`origin` text NOT NULL,`revision` integer NOT NULL DEFAULT 1,`assigned_by` integer NOT NULL DEFAULT 0,`created_at` datetime NOT NULL,`context_type` text NOT NULL DEFAULT "platform",`context_id` integer NOT NULL DEFAULT 0);

CREATE INDEX "{{schema}}"."idx_iam_user_roles_context" ON `iam_user_roles`(`context_type`,`context_id`);

CREATE INDEX "{{schema}}"."idx_iam_user_roles_role_id" ON `iam_user_roles`(`role_id`);

CREATE INDEX "{{schema}}"."idx_iam_user_roles_user_id" ON `iam_user_roles`(`user_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_role_constraints" (`id` integer PRIMARY KEY AUTOINCREMENT,`kind` text NOT NULL,`name` text NOT NULL,`role_ids` text NOT NULL,`max_count` integer NOT NULL DEFAULT 0,`enabled` numeric NOT NULL DEFAULT true,`revision` integer NOT NULL DEFAULT 1,`context_type` text NOT NULL DEFAULT "platform",`context_id` integer NOT NULL DEFAULT 0);

CREATE INDEX "{{schema}}"."idx_iam_constraints_context" ON `iam_role_constraints`(`context_type`,`context_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_delegations" (`id` integer PRIMARY KEY AUTOINCREMENT,`manager_role_id` integer NOT NULL,`target_role_id` integer NOT NULL,`target_kind` text NOT NULL,`actions` text NOT NULL,`target_user_scope` text NOT NULL,`grant_ceiling` text NOT NULL,`can_redelegate` numeric NOT NULL DEFAULT false,`starts_at` datetime NOT NULL,`expires_at` datetime,`revoked_at` datetime,`revision` integer NOT NULL DEFAULT 1,`created_by` integer NOT NULL DEFAULT 0,`created_at` datetime NOT NULL,`context_type` text NOT NULL DEFAULT "platform",`context_id` integer NOT NULL DEFAULT 0);

CREATE INDEX "{{schema}}"."idx_iam_delegations_context" ON `iam_delegations`(`context_type`,`context_id`);

CREATE INDEX "{{schema}}"."idx_iam_delegations_manager_role_id" ON `iam_delegations`(`manager_role_id`);

CREATE INDEX "{{schema}}"."idx_iam_delegations_target_role_id" ON `iam_delegations`(`target_role_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."iam_audit_events" (`event_id` text,`actor_user_id` integer,`actor_service_id` text,`actor_session_id` text,`action` text NOT NULL,`target` text,`before_data` text,`after_data` text,`diff` text,`result` text NOT NULL,`reason` text,`request_id` text,`authorization_versions` text,`occurred_at` datetime NOT NULL,`organization_id` integer NOT NULL DEFAULT 0,PRIMARY KEY (`event_id`));

CREATE INDEX "{{schema}}"."idx_iam_audit_events_action" ON `iam_audit_events`(`action`);

CREATE INDEX "{{schema}}"."idx_iam_audit_events_actor_user_id" ON `iam_audit_events`(`actor_user_id`);

CREATE INDEX "{{schema}}"."idx_iam_audit_events_occurred_at" ON `iam_audit_events`(`occurred_at`);

CREATE INDEX "{{schema}}"."idx_iam_audit_events_target" ON `iam_audit_events`(`target`);

CREATE INDEX "{{schema}}"."idx_iam_audit_org" ON `iam_audit_events`(`organization_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."scim_identities" (`id` integer PRIMARY KEY AUTOINCREMENT,`organization_id` integer NOT NULL,`kind` text NOT NULL,`external_id` text NOT NULL,`local_id` integer NOT NULL,`revision` integer NOT NULL DEFAULT 1,`created_at` datetime NOT NULL,`updated_at` datetime NOT NULL);

CREATE UNIQUE INDEX "{{schema}}"."uk_scim_identity_local" ON `scim_identities`(`organization_id`,`kind`,`local_id`);

CREATE UNIQUE INDEX "{{schema}}"."uk_scim_identity" ON `scim_identities`(`organization_id`,`kind`,`external_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."scim_groups" (`id` integer PRIMARY KEY AUTOINCREMENT,`organization_id` integer NOT NULL,`display_name` text NOT NULL,`revision` integer NOT NULL DEFAULT 1,`created_at` datetime NOT NULL,`updated_at` datetime NOT NULL);

CREATE UNIQUE INDEX "{{schema}}"."uk_scim_group_name" ON `scim_groups`(`organization_id`,`display_name`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."scim_group_members" (`group_id` integer,`user_id` integer,PRIMARY KEY (`group_id`,`user_id`));

CREATE TABLE IF NOT EXISTS "{{schema}}"."directory_objects" (`id` integer PRIMARY KEY AUTOINCREMENT,`source_id` integer NOT NULL,`organization_id` integer NOT NULL,`external_id` text NOT NULL,`local_id` integer NOT NULL,`last_seen_at` datetime NOT NULL,`revision` integer NOT NULL DEFAULT 1);

CREATE INDEX "{{schema}}"."idx_directory_object_local" ON `directory_objects`(`source_id`,`local_id`);

CREATE UNIQUE INDEX "{{schema}}"."uk_directory_object" ON `directory_objects`(`source_id`,`external_id`);

CREATE TABLE IF NOT EXISTS "{{schema}}"."directory_sync_runs" (`id` integer PRIMARY KEY AUTOINCREMENT,`source_id` integer NOT NULL,`organization_id` integer NOT NULL,`mode` text NOT NULL,`status` text NOT NULL,`started_at` datetime NOT NULL,`finished_at` datetime,`fetched` integer NOT NULL,`created_count` integer NOT NULL,`updated_count` integer NOT NULL,`disabled_count` integer NOT NULL,`unchanged_count` integer NOT NULL,`failed_count` integer NOT NULL,`cursor_before` text NOT NULL,`cursor_after` text NOT NULL,`report_json` text,`error_text` text);

CREATE INDEX "{{schema}}"."idx_directory_runs_source" ON `directory_sync_runs`(`source_id`);
