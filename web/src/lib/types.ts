import type { components } from './api-types'

type Schemas = components['schemas']

export type ApiErrorBody = {
  code?: number
  reason?: string
  message?: string
  metadata?: Record<string, string>
}

export type ArchiveMenuItemRequest =
  Schemas['api.usercenter.v1.ArchiveMenuItemRequest']
export type ArchivePermissionRequest =
  Schemas['api.usercenter.v1.ArchivePermissionRequest']
export type ArchiveRoleRequest =
  Schemas['api.usercenter.v1.ArchiveRoleRequest']
export type ArchiveUserRequest =
  Schemas['api.usercenter.v1.ArchiveUserRequest']
export type Assignment = Schemas['api.usercenter.v1.Assignment']
export type AssignmentsReply = Schemas['api.usercenter.v1.AssignmentsReply']
export type AuditEvent = Schemas['api.usercenter.v1.AuditEvent']
export type AuditsReply = Schemas['api.usercenter.v1.AuditsReply']
export type AuthContext = Schemas['api.usercenter.v1.AuthContext']
export type AuthSettings = Schemas['api.usercenter.v1.AuthSettings']
export type AuthorizationReply = Schemas['api.usercenter.v1.AuthorizationReply']
export type BatchAssignReply = Schemas['api.usercenter.v1.BatchAssignReply']
export type BatchAssignRequest = Schemas['api.usercenter.v1.BatchAssignRequest']
export type BatchFailure = Schemas['api.usercenter.v1.BatchFailure']
export type BatchPreviewReply = Schemas['api.usercenter.v1.BatchPreviewReply']
export type ChallengeReply = Schemas['api.usercenter.v1.ChallengeReply']
export type ChangePasswordRequest =
  Schemas['api.usercenter.v1.ChangePasswordRequest']
export type CompleteMFARequest = Schemas['api.usercenter.v1.CompleteMFARequest']
export type ConfirmEmailRequest = Schemas['api.usercenter.v1.ConfirmEmailRequest']
export type ConfirmMFARequest = Schemas['api.usercenter.v1.ConfirmMFARequest']
export type Constraint = Schemas['api.usercenter.v1.Constraint']
export type ConstraintsReply = Schemas['api.usercenter.v1.ConstraintsReply']
export type CopyRoleRequest = Schemas['api.usercenter.v1.CopyRoleRequest']
export type CreateAssignmentRequest =
  Schemas['api.usercenter.v1.CreateAssignmentRequest']
export type CreateConstraintRequest =
  Schemas['api.usercenter.v1.CreateConstraintRequest']
export type CreateEmailChallengeRequest =
  Schemas['api.usercenter.v1.CreateEmailChallengeRequest']
export type CreateMenuItemRequest =
  Schemas['api.usercenter.v1.CreateMenuItemRequest']
export type CreatePasswordResetChallengeRequest =
  Schemas['api.usercenter.v1.CreatePasswordResetChallengeRequest']
export type CreatePasswordResetTaskRequest =
  Schemas['api.usercenter.v1.CreatePasswordResetTaskRequest']
export type CreatePermissionRequest =
  Schemas['api.usercenter.v1.CreatePermissionRequest']
export type CreateRegistrationChallengeRequest =
  Schemas['api.usercenter.v1.CreateRegistrationChallengeRequest']
export type CreateRoleRequest = Schemas['api.usercenter.v1.CreateRoleRequest']
export type CreateUserRequest = Schemas['api.usercenter.v1.CreateUserRequest']
export type DisableMFARequest = Schemas['api.usercenter.v1.DisableMFARequest']
export type EffectivePermission = Schemas['api.usercenter.v1.EffectivePermission']
export type EffectivePermissionsReply =
  Schemas['api.usercenter.v1.EffectivePermissionsReply']
export type EmailSettings = Schemas['api.usercenter.v1.EmailSettings']
export type ExplainAuthorizationReply =
  Schemas['api.usercenter.v1.ExplainAuthorizationReply']
export type ExplainAuthorizationRequest =
  Schemas['api.usercenter.v1.ExplainAuthorizationRequest']
export type ExportAuditEventsRequest =
  Schemas['api.usercenter.v1.ExportAuditEventsRequest']
export type ExportJob = Schemas['api.usercenter.v1.ExportJob']
export type ExportUsersRequest = Schemas['api.usercenter.v1.ExportUsersRequest']
export type ExportsReply = Schemas['api.usercenter.v1.ExportsReply']
export type ExternalIdentitiesReply =
  Schemas['api.usercenter.v1.ExternalIdentitiesReply']
export type ExternalIdentity = Schemas['api.usercenter.v1.ExternalIdentity']
export type Grant = Schemas['api.usercenter.v1.Grant']
export type GrantSource = Schemas['api.usercenter.v1.GrantSource']
export type ListMeta = Schemas['api.usercenter.v1.ListMeta']
export type LoginReply = Schemas['api.usercenter.v1.LoginReply']
export type LoginRequest = Schemas['api.usercenter.v1.LoginRequest']
export type MenuItem = Schemas['api.usercenter.v1.MenuItem']
export type MenusReply = Schemas['api.usercenter.v1.MenusReply']
export type OverviewReply = Schemas['api.usercenter.v1.OverviewReply']
export type PasswordResetTaskReply =
  Schemas['api.usercenter.v1.PasswordResetTaskReply']
export type Permission = Schemas['api.usercenter.v1.Permission']
export type PermissionSummary = Schemas['api.usercenter.v1.PermissionSummary']
export type PermissionsReply = Schemas['api.usercenter.v1.PermissionsReply']
export type PreviewBatchAssignRequest =
  Schemas['api.usercenter.v1.PreviewBatchAssignRequest']
export type PreviewReply = Schemas['api.usercenter.v1.PreviewReply']
export type PreviewRoleChangeRequest =
  Schemas['api.usercenter.v1.PreviewRoleChangeRequest']
export type PutRoleInheritanceRequest =
  Schemas['api.usercenter.v1.PutRoleInheritanceRequest']
export type PutRolePermissionsRequest =
  Schemas['api.usercenter.v1.PutRolePermissionsRequest']
export type PutSessionRolesRequest =
  Schemas['api.usercenter.v1.PutSessionRolesRequest']
export type RecoveryCodesReply = Schemas['api.usercenter.v1.RecoveryCodesReply']
export type Reference = Schemas['api.usercenter.v1.Reference']
export type ReferencesReply = Schemas['api.usercenter.v1.ReferencesReply']
export type RegisterReply = Schemas['api.usercenter.v1.RegisterReply']
export type RegisterRequest = Schemas['api.usercenter.v1.RegisterRequest']
export type ResetMFARequest = Schemas['api.usercenter.v1.ResetMFARequest']
export type ResetPasswordRequest = Schemas['api.usercenter.v1.ResetPasswordRequest']
export type Resource = Schemas['api.usercenter.v1.Resource']
export type ResourcesReply = Schemas['api.usercenter.v1.ResourcesReply']
export type RevokeAssignmentRequest =
  Schemas['api.usercenter.v1.RevokeAssignmentRequest']
export type RevokeUserSessionsRequest =
  Schemas['api.usercenter.v1.RevokeUserSessionsRequest']
export type Role = Schemas['api.usercenter.v1.Role']
export type RoleInheritanceReply =
  Schemas['api.usercenter.v1.RoleInheritanceReply']
export type RoleMember = Schemas['api.usercenter.v1.RoleMember']
export type RoleMembersReply = Schemas['api.usercenter.v1.RoleMembersReply']
export type RolePermissionsReply =
  Schemas['api.usercenter.v1.RolePermissionsReply']
export type RoleRef = Schemas['api.usercenter.v1.RoleRef']
export type RolesReply = Schemas['api.usercenter.v1.RolesReply']
export type RotateRecoveryCodesRequest =
  Schemas['api.usercenter.v1.RotateRecoveryCodesRequest']
export type Scope = Schemas['api.usercenter.v1.Scope']
export type SecurityEvent = Schemas['api.usercenter.v1.SecurityEvent']
export type SecurityEventsReply = Schemas['api.usercenter.v1.SecurityEventsReply']
export type SecurityStatus = Schemas['api.usercenter.v1.SecurityStatus']
export type SessionInfo = Schemas['api.usercenter.v1.SessionInfo']
export type SessionRole = Schemas['api.usercenter.v1.SessionRole']
export type SessionRolesReply = Schemas['api.usercenter.v1.SessionRolesReply']
export type SessionsReply = Schemas['api.usercenter.v1.SessionsReply']
export type SetPermissionStatusRequest =
  Schemas['api.usercenter.v1.SetPermissionStatusRequest']
export type SetRoleStatusRequest =
  Schemas['api.usercenter.v1.SetRoleStatusRequest']
export type SetUserStatusRequest =
  Schemas['api.usercenter.v1.SetUserStatusRequest']
export type SetupMFAReply = Schemas['api.usercenter.v1.SetupMFAReply']
export type SetupMFARequest = Schemas['api.usercenter.v1.SetupMFARequest']
export type SimulateAuthorizationReply =
  Schemas['api.usercenter.v1.SimulateAuthorizationReply']
export type SimulateAuthorizationRequest =
  Schemas['api.usercenter.v1.SimulateAuthorizationRequest']
export type UpdateAuthSettingsRequest =
  Schemas['api.usercenter.v1.UpdateAuthSettingsRequest']
export type UpdateConstraintRequest =
  Schemas['api.usercenter.v1.UpdateConstraintRequest']
export type UpdateEmailSettingsRequest =
  Schemas['api.usercenter.v1.UpdateEmailSettingsRequest']
export type UpdateMeRequest = Schemas['api.usercenter.v1.UpdateMeRequest']
export type UpdateMenuItemRequest =
  Schemas['api.usercenter.v1.UpdateMenuItemRequest']
export type UpdatePermissionRequest =
  Schemas['api.usercenter.v1.UpdatePermissionRequest']
export type UpdateRoleRequest = Schemas['api.usercenter.v1.UpdateRoleRequest']
export type UpdateUserRequest = Schemas['api.usercenter.v1.UpdateUserRequest']
export type User = Schemas['api.usercenter.v1.User']
export type UsersReply = Schemas['api.usercenter.v1.UsersReply']
export type VerifySecurityReply = Schemas['api.usercenter.v1.VerifySecurityReply']
export type VerifySecurityRequest = Schemas['api.usercenter.v1.VerifySecurityRequest']

export type AssignmentItem = Schemas['api.usercenter.v1.AssignmentItem']
export type AssignmentListReply =
  Schemas['api.usercenter.v1.AssignmentListReply']
export type CreateDelegationRequest =
  Schemas['api.usercenter.v1.CreateDelegationRequest']
export type Delegation = Schemas['api.usercenter.v1.Delegation']
export type DelegationCeiling = Schemas['api.usercenter.v1.DelegationCeiling']
export type DelegationsReply = Schemas['api.usercenter.v1.DelegationsReply']
export type RevokeDelegationRequest =
  Schemas['api.usercenter.v1.RevokeDelegationRequest']
export type IntegrationClient = Schemas['api.usercenter.v1.IntegrationClient']
export type IntegrationClientsReply =
  Schemas['api.usercenter.v1.IntegrationClientsReply']
export type IntegrationClientCredentialReply =
  Schemas['api.usercenter.v1.IntegrationClientCredentialReply']
export type CreateIntegrationClientRequest =
  Schemas['api.usercenter.v1.CreateIntegrationClientRequest']
export type UpdateIntegrationClientRequest =
  Schemas['api.usercenter.v1.UpdateIntegrationClientRequest']
export type RotateIntegrationClientCredentialRequest =
  Schemas['api.usercenter.v1.RotateIntegrationClientCredentialRequest']
export type DisableIntegrationClientRequest =
  Schemas['api.usercenter.v1.DisableIntegrationClientRequest']
export type EventDelivery = Schemas['api.usercenter.v1.EventDelivery']
export type EventDeliveriesReply =
  Schemas['api.usercenter.v1.EventDeliveriesReply']
export type RetryEventDeliveryRequest =
  Schemas['api.usercenter.v1.RetryEventDeliveryRequest']
export type CreateEmailChangeChallengeRequest =
  Schemas['api.usercenter.v1.CreateEmailChangeChallengeRequest']
export type ConfirmEmailChangeRequest =
  Schemas['api.usercenter.v1.ConfirmEmailChangeRequest']
export type OIDCClient = Schemas['api.usercenter.v1.OIDCClient']
export type OIDCClientsReply = Schemas['api.usercenter.v1.OIDCClientsReply']
export type OIDCClientCredentialReply =
  Schemas['api.usercenter.v1.OIDCClientCredentialReply']
export type CreateOIDCClientRequest =
  Schemas['api.usercenter.v1.CreateOIDCClientRequest']
export type UpdateOIDCClientRequest =
  Schemas['api.usercenter.v1.UpdateOIDCClientRequest']
export type RotateOIDCClientSecretRequest =
  Schemas['api.usercenter.v1.RotateOIDCClientSecretRequest']
export type DisableOIDCClientRequest =
  Schemas['api.usercenter.v1.DisableOIDCClientRequest']

// The discovery document is served by the OIDC transport, not the OpenAPI
// surface, so it is described here rather than generated from openapi.yaml.
export type OIDCDiscovery = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
}

export type ApiList<T> = {
  items: T[]
  meta: ListMeta
}
