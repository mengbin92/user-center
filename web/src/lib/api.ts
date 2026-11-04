import { http } from './http'
import type { operations } from './api-types'
import type {
  ArchiveMenuItemRequest,
  ArchivePermissionRequest,
  ArchiveRoleRequest,
  ArchiveUserRequest,
  Assignment,
  AssignmentsReply,
  AuditEvent,
  AuditsReply,
  AuthContext,
  AuthSettings,
  AuthorizationReply,
  BatchAssignReply,
  BatchAssignRequest,
  BatchPreviewReply,
  ChallengeReply,
  ChangePasswordRequest,
  CompleteMFARequest,
  ConfirmEmailRequest,
  ConfirmMFARequest,
  Constraint,
  ConstraintsReply,
  CopyRoleRequest,
  CreateAssignmentRequest,
  CreateConstraintRequest,
  CreateEmailChallengeRequest,
  CreateMenuItemRequest,
  CreatePasswordResetChallengeRequest,
  CreatePasswordResetTaskRequest,
  CreatePermissionRequest,
  CreateRegistrationChallengeRequest,
  CreateRoleRequest,
  CreateUserRequest,
  DisableMFARequest,
  EffectivePermissionsReply,
  EmailSettings,
  ExplainAuthorizationReply,
  ExplainAuthorizationRequest,
  ExportAuditEventsRequest,
  ExportJob,
  ExportUsersRequest,
  ExportsReply,
  ExternalIdentitiesReply,
  LoginReply,
  LoginRequest,
  MenuItem,
  MenusReply,
  OverviewReply,
  PasswordResetTaskReply,
  Permission,
  PermissionsReply,
  PreviewBatchAssignRequest,
  PreviewReply,
  PreviewRoleChangeRequest,
  PutRoleInheritanceRequest,
  PutRolePermissionsRequest,
  PutSessionRolesRequest,
  RecoveryCodesReply,
  ReferencesReply,
  RegisterReply,
  RegisterRequest,
  ResetMFARequest,
  ResetPasswordRequest,
  ResourcesReply,
  RevokeAssignmentRequest,
  RevokeUserSessionsRequest,
  Role,
  RoleInheritanceReply,
  RoleMembersReply,
  RolePermissionsReply,
  RolesReply,
  RotateRecoveryCodesRequest,
  SecurityEventsReply,
  SecurityStatus,
  SessionRolesReply,
  SessionsReply,
  SetPermissionStatusRequest,
  SetRoleStatusRequest,
  SetUserStatusRequest,
  SetupMFAReply,
  SetupMFARequest,
  SimulateAuthorizationReply,
  SimulateAuthorizationRequest,
  UpdateAuthSettingsRequest,
  UpdateConstraintRequest,
  UpdateEmailSettingsRequest,
  UpdateMeRequest,
  UpdateMenuItemRequest,
  UpdatePermissionRequest,
  UpdateRoleRequest,
  UpdateUserRequest,
  User,
  UsersReply,
  VerifySecurityReply,
  VerifySecurityRequest,
  AssignmentListReply,
  ConfirmEmailChangeRequest,
  CreateDelegationRequest,
  CreateEmailChangeChallengeRequest,
  CreateIntegrationClientRequest,
  CreateOIDCClientRequest,
  Delegation,
  DelegationsReply,
  DisableIntegrationClientRequest,
  DisableOIDCClientRequest,
  EventDeliveriesReply,
  EventDelivery,
  IntegrationClient,
  IntegrationClientCredentialReply,
  IntegrationClientsReply,
  OIDCClient,
  OIDCClientCredentialReply,
  OIDCClientsReply,
  OIDCDiscovery,
  RotateOIDCClientSecretRequest,
  RetryEventDeliveryRequest,
  RevokeDelegationRequest,
  RotateIntegrationClientCredentialRequest,
  UpdateIntegrationClientRequest,
  UpdateOIDCClientRequest,
  AddOrganizationMemberRequest,
  AdminArchiveOrganizationRequest,
  ArchiveDepartmentRequest,
  ArchiveOrganizationRequest,
  CreateDepartmentRequest,
  CreateOrganizationRequest,
  Department,
  DepartmentsReply,
  Organization,
  OrganizationMember,
  OrganizationMembersReply,
  OrganizationsReply,
  UpdateDepartmentRequest,
  UpdateOrganizationMemberRequest,
  UpdateOrganizationRequest,
} from './types'

type QueryValue = string | number | boolean | null | undefined
export type QueryParams = Record<string, QueryValue>

function compact(params?: QueryParams): QueryParams | undefined {
  if (!params) return undefined
  const out: QueryParams = {}
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    out[key] = value
  }
  return Object.keys(out).length > 0 ? out : undefined
}

function enc(value: string): string {
  return encodeURIComponent(value)
}

async function get<T>(url: string, params?: QueryParams): Promise<T> {
  const response = await http.get<T>(url, { params: compact(params) })
  return response.data
}

async function getBlob(
  url: string,
): Promise<{ blob: Blob; filename: string | null }> {
  const response = await http.get<Blob>(url, { responseType: 'blob' })
  const disposition = response.headers['content-disposition']
  let filename: string | null = null
  if (typeof disposition === 'string') {
    const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(disposition)
    const plain = /filename="?([^";]+)"?/i.exec(disposition)
    filename = utf8 ? decodeURIComponent(utf8[1]) : plain ? plain[1] : null
  }
  return { blob: response.data, filename }
}

async function post<T>(url: string, body?: unknown): Promise<T> {
  const response = await http.post<T>(url, body ?? {})
  return response.data
}

async function patch<T>(url: string, body: unknown): Promise<T> {
  const response = await http.patch<T>(url, body)
  return response.data
}

async function put<T>(url: string, body: unknown): Promise<T> {
  const response = await http.put<T>(url, body)
  return response.data
}

async function del<T = void>(url: string, params?: QueryParams): Promise<T> {
  const response = await http.delete<T>(url, { params: compact(params) })
  return response.data
}

export type ListUsersParams = {
  keyword?: string
  status?: string
  role_id?: string
  mfa_enabled?: string
  page_size?: number
  page_token?: string
}

export type ListAuditsParams = {
  action?: string
  actor_user_id?: string
  target?: string
  from?: string
  to?: string
  page_size?: number
  page_token?: string
}

export type ListPermissionsParams = {
  category?: string
  status?: string
  keyword?: string
}

export type ListRolesParams = {
  status?: string
  keyword?: string
}

export type PageParams = {
  page_size?: number
  page_token?: string
}

export type ListAssignmentsParams = {
  user_id?: string
  role_id?: string
  status?: string
  page_size?: number
  page_token?: string
}

export type ListDelegationsParams = {
  manager_role_id?: string
  target_role_id?: string
  status?: string
}

export type ListEventDeliveriesParams = {
  status?: string
  page_size?: number
  page_token?: string
}

export type ListOrganizationsParams = {
  status?: string
}

export const api = {
  auth: {
    context: () => get<AuthContext>('/api/v1/auth/context'),
    login: (body: LoginRequest) => post<LoginReply>('/api/v1/auth/login', body),
    completeMfa: (body: CompleteMFARequest) =>
      post<LoginReply>('/api/v1/auth/mfa/complete', body),
    logout: () => post<void>('/api/v1/auth/logout', {}),
    createRegistrationChallenge: (body: CreateRegistrationChallengeRequest) =>
      post<ChallengeReply>('/api/v1/auth/registration-challenges', body),
    register: (body: RegisterRequest) =>
      post<RegisterReply>('/api/v1/auth/register', body),
    createPasswordResetChallenge: (
      body: CreatePasswordResetChallengeRequest,
    ) => post<ChallengeReply>('/api/v1/auth/password-reset-challenges', body),
    resetPassword: (body: ResetPasswordRequest) =>
      post<void>('/api/v1/auth/password-reset', body),
  },

  me: {
    get: () => get<User>('/api/v1/me'),
    update: (body: UpdateMeRequest) => patch<User>('/api/v1/me', body),
    authorization: () =>
      get<AuthorizationReply>('/api/v1/me/authorization'),
    security: () => get<SecurityStatus>('/api/v1/me/security'),
    changePassword: (body: ChangePasswordRequest) =>
      post<void>('/api/v1/me/password:change', body),
    setupMfa: (body: SetupMFARequest) =>
      post<SetupMFAReply>('/api/v1/me/mfa:setup', body),
    confirmMfa: (body: ConfirmMFARequest) =>
      post<RecoveryCodesReply>('/api/v1/me/mfa:confirm', body),
    disableMfa: (body: DisableMFARequest) =>
      post<void>('/api/v1/me/mfa:disable', body),
    rotateRecoveryCodes: (body: RotateRecoveryCodesRequest) =>
      post<RecoveryCodesReply>('/api/v1/me/mfa/recovery-codes:rotate', body),
    verifySecurity: (body: VerifySecurityRequest) =>
      post<VerifySecurityReply>('/api/v1/me/security:verify', body),
    createEmailChallenge: (body: CreateEmailChallengeRequest) =>
      post<ChallengeReply>('/api/v1/me/email-challenges', body),
    confirmEmail: (body: ConfirmEmailRequest) =>
      post<User>('/api/v1/me/email:confirm', body),
    externalIdentities: () =>
      get<ExternalIdentitiesReply>('/api/v1/me/external-identities'),
    deleteExternalIdentity: (id: string) =>
      del(`/api/v1/me/external-identities/${enc(id)}`),
    securityEvents: (params?: PageParams) =>
      get<SecurityEventsReply>('/api/v1/me/security-events', params),
    sessions: () => get<SessionsReply>('/api/v1/me/sessions'),
    revokeSession: (id: string) => del(`/api/v1/me/sessions/${enc(id)}`),
    revokeOtherSessions: () =>
      post<void>('/api/v1/me/sessions:revoke-others', {}),
    sessionRoles: () =>
      get<SessionRolesReply>('/api/v1/me/session-roles'),
    putSessionRoles: (body: PutSessionRolesRequest) =>
      put<SessionRolesReply>('/api/v1/me/session-roles', body),
  },

  orgs: {
    listMine: () => get<OrganizationsReply>('/api/v1/orgs'),
    create: (body: CreateOrganizationRequest) =>
      post<Organization>('/api/v1/orgs', body),
    get: (id: string) => get<Organization>(`/api/v1/orgs/${enc(id)}`),
    update: (id: string, body: UpdateOrganizationRequest) =>
      patch<Organization>(`/api/v1/orgs/${enc(id)}`, body),
    archive: (id: string, body: ArchiveOrganizationRequest) =>
      post<Organization>(`/api/v1/orgs/${enc(id)}:archive`, body),
    listMembers: (id: string) =>
      get<OrganizationMembersReply>(`/api/v1/orgs/${enc(id)}/members`),
    addMember: (id: string, body: AddOrganizationMemberRequest) =>
      post<OrganizationMember>(`/api/v1/orgs/${enc(id)}/members`, body),
    updateMember: (
      id: string,
      userId: string,
      body: UpdateOrganizationMemberRequest,
    ) =>
      patch<OrganizationMember>(
        `/api/v1/orgs/${enc(id)}/members/${enc(userId)}`,
        body,
      ),
    // The proto has no body for DELETE, so reason is mapped to a query arg.
    removeMember: (
      id: string,
      userId: string,
      reason: string,
      expectedRevision: string,
    ) =>
      del(`/api/v1/orgs/${enc(id)}/members/${enc(userId)}`, {
        reason,
        expected_revision: expectedRevision,
      }),
    leave: (id: string) =>
      post<void>(`/api/v1/orgs/${enc(id)}/members:leave`, { id }),
    listDepartments: (id: string) =>
      get<DepartmentsReply>(`/api/v1/orgs/${enc(id)}/departments`),
    createDepartment: (id: string, body: CreateDepartmentRequest) =>
      post<Department>(`/api/v1/orgs/${enc(id)}/departments`, body),
    updateDepartment: (
      id: string,
      departmentId: string,
      body: UpdateDepartmentRequest,
    ) =>
      patch<Department>(
        `/api/v1/orgs/${enc(id)}/departments/${enc(departmentId)}`,
        body,
      ),
    archiveDepartment: (
      id: string,
      departmentId: string,
      body: ArchiveDepartmentRequest,
    ) =>
      post<Department>(
        `/api/v1/orgs/${enc(id)}/departments/${enc(departmentId)}:archive`,
        body,
      ),
  },

  admin: {
    overview: () => get<OverviewReply>('/api/v1/admin/overview'),
    listOrganizations: (params?: ListOrganizationsParams) =>
      get<OrganizationsReply>('/api/v1/admin/organizations', params),
    archiveOrganization: (id: string, body: AdminArchiveOrganizationRequest) =>
      post<Organization>(
        `/api/v1/admin/organizations/${enc(id)}:archive`,
        body,
      ),
    listUsers: (params?: ListUsersParams) =>
      get<UsersReply>('/api/v1/admin/users', params),
    createUser: (body: CreateUserRequest) =>
      post<User>('/api/v1/admin/users', body),
    getUser: (id: string) => get<User>(`/api/v1/admin/users/${enc(id)}`),
    updateUser: (id: string, body: UpdateUserRequest) =>
      patch<User>(`/api/v1/admin/users/${enc(id)}`, body),
    setUserStatus: (id: string, body: SetUserStatusRequest) =>
      post<User>(`/api/v1/admin/users/${enc(id)}:set-status`, body),
    archiveUser: (id: string, body: ArchiveUserRequest) =>
      post<User>(`/api/v1/admin/users/${enc(id)}:archive`, body),
    createPasswordResetRequest: (
      id: string,
      body: CreatePasswordResetTaskRequest,
    ) =>
      post<PasswordResetTaskReply>(
        `/api/v1/admin/users/${enc(id)}/password-reset-requests`,
        body,
      ),
    resetMfa: (id: string, body: ResetMFARequest) =>
      post<void>(`/api/v1/admin/users/${enc(id)}/mfa:reset`, body),
    createEmailChange: (
      id: string,
      body: CreateEmailChangeChallengeRequest,
    ) =>
      post<ChallengeReply>(
        `/api/v1/admin/users/${enc(id)}/email-changes`,
        body,
      ),
    confirmEmailChange: (id: string, body: ConfirmEmailChangeRequest) =>
      post<User>(
        `/api/v1/admin/users/${enc(id)}/email-changes:confirm`,
        body,
      ),
    userSessions: (id: string) =>
      get<SessionsReply>(`/api/v1/admin/users/${enc(id)}/sessions`),
    revokeUserSessions: (id: string, body: RevokeUserSessionsRequest) =>
      post<void>(`/api/v1/admin/users/${enc(id)}/sessions:revoke`, body),
    effectivePermissions: (id: string) =>
      get<EffectivePermissionsReply>(
        `/api/v1/admin/users/${enc(id)}/effective-permissions`,
      ),
    userRoles: (id: string) =>
      get<AssignmentsReply>(`/api/v1/admin/users/${enc(id)}/roles`),
    exportUsers: (body: ExportUsersRequest) =>
      post<ExportJob>('/api/v1/admin/users:export', body),
    listExports: (params?: PageParams) =>
      get<ExportsReply>('/api/v1/admin/exports', params),
    getExport: (id: string) =>
      get<ExportJob>(`/api/v1/admin/exports/${enc(id)}`),
    downloadExport: (id: string) =>
      getBlob(`/api/v1/admin/exports/${enc(id)}/download`),
  },

  audits: {
    list: (params?: ListAuditsParams) =>
      get<AuditsReply>('/api/v1/admin/audits', params),
    get: (id: string) =>
      get<AuditEvent>(`/api/v1/admin/audits/${enc(id)}`),
    export: (body: ExportAuditEventsRequest) =>
      post<ExportJob>('/api/v1/admin/audits:export', body),
  },

  iam: {
    listRoles: (params?: ListRolesParams) =>
      get<RolesReply>('/api/v1/admin/iam/roles', params),
    createRole: (body: CreateRoleRequest) =>
      post<Role>('/api/v1/admin/iam/roles', body),
    getRole: (id: string) =>
      get<Role>(`/api/v1/admin/iam/roles/${enc(id)}`),
    updateRole: (id: string, body: UpdateRoleRequest) =>
      patch<Role>(`/api/v1/admin/iam/roles/${enc(id)}`, body),
    archiveRole: (id: string, body: ArchiveRoleRequest) =>
      post<Role>(`/api/v1/admin/iam/roles/${enc(id)}:archive`, body),
    copyRole: (id: string, body: CopyRoleRequest) =>
      post<Role>(`/api/v1/admin/iam/roles/${enc(id)}:copy`, body),
    setRoleStatus: (id: string, body: SetRoleStatusRequest) =>
      post<Role>(`/api/v1/admin/iam/roles/${enc(id)}:set-status`, body),
    rolePermissions: (id: string) =>
      get<RolePermissionsReply>(
        `/api/v1/admin/iam/roles/${enc(id)}/permissions`,
      ),
    putRolePermissions: (id: string, body: PutRolePermissionsRequest) =>
      put<RolePermissionsReply>(
        `/api/v1/admin/iam/roles/${enc(id)}/permissions`,
        body,
      ),
    roleInheritance: (id: string) =>
      get<RoleInheritanceReply>(
        `/api/v1/admin/iam/roles/${enc(id)}/inheritance`,
      ),
    putRoleInheritance: (id: string, body: PutRoleInheritanceRequest) =>
      put<RoleInheritanceReply>(
        `/api/v1/admin/iam/roles/${enc(id)}/inheritance`,
        body,
      ),
    roleMembers: (id: string) =>
      get<RoleMembersReply>(`/api/v1/admin/iam/roles/${enc(id)}/members`),
    previewRoleChange: (id: string, body: PreviewRoleChangeRequest) =>
      post<PreviewReply>(
        `/api/v1/admin/iam/roles/${enc(id)}:preview`,
        body,
      ),

    listPermissions: (params?: ListPermissionsParams) =>
      get<PermissionsReply>('/api/v1/admin/iam/permissions', params),
    getPermission: (id: string) =>
      get<Permission>(`/api/v1/admin/iam/permissions/${enc(id)}`),
    createPermission: (body: CreatePermissionRequest) =>
      post<Permission>('/api/v1/admin/iam/permissions', body),
    updatePermission: (id: string, body: UpdatePermissionRequest) =>
      patch<Permission>(`/api/v1/admin/iam/permissions/${enc(id)}`, body),
    archivePermission: (id: string, body: ArchivePermissionRequest) =>
      post<Permission>(
        `/api/v1/admin/iam/permissions/${enc(id)}:archive`,
        body,
      ),
    setPermissionStatus: (id: string, body: SetPermissionStatusRequest) =>
      post<Permission>(
        `/api/v1/admin/iam/permissions/${enc(id)}:set-status`,
        body,
      ),
    permissionReferences: (id: string) =>
      get<ReferencesReply>(
        `/api/v1/admin/iam/permissions/${enc(id)}/references`,
      ),
    listResources: () =>
      get<ResourcesReply>('/api/v1/admin/iam/resources'),

    listMenus: () => get<MenusReply>('/api/v1/admin/iam/menus'),
    createMenuItem: (body: CreateMenuItemRequest) =>
      post<MenuItem>('/api/v1/admin/iam/menus', body),
    updateMenuItem: (id: string, body: UpdateMenuItemRequest) =>
      patch<MenuItem>(`/api/v1/admin/iam/menus/${enc(id)}`, body),
    archiveMenuItem: (id: string, body: ArchiveMenuItemRequest) =>
      post<MenuItem>(`/api/v1/admin/iam/menus/${enc(id)}:archive`, body),

    listConstraints: () =>
      get<ConstraintsReply>('/api/v1/admin/iam/constraints'),
    createConstraint: (body: CreateConstraintRequest) =>
      post<Constraint>('/api/v1/admin/iam/constraints', body),
    updateConstraint: (id: string, body: UpdateConstraintRequest) =>
      patch<Constraint>(`/api/v1/admin/iam/constraints/${enc(id)}`, body),
    deleteConstraint: (id: string, params: NonNullable<operations['IAMService_DeleteConstraint']['parameters']['query']>) =>
      del(`/api/v1/admin/iam/constraints/${enc(id)}`, params),

    listAssignments: (params?: ListAssignmentsParams) =>
      get<AssignmentListReply>('/api/v1/admin/iam/assignments', params),
    createAssignment: (body: CreateAssignmentRequest) =>
      post<Assignment>('/api/v1/admin/iam/assignments', body),
    revokeAssignment: (id: string, body: RevokeAssignmentRequest) =>
      post<Assignment>(
        `/api/v1/admin/iam/assignments/${enc(id)}:revoke`,
        body,
      ),
    previewBatchAssign: (body: PreviewBatchAssignRequest) =>
      post<BatchPreviewReply>(
        '/api/v1/admin/iam/assignments:batch-preview',
        body,
      ),
    batchAssign: (body: BatchAssignRequest) =>
      post<BatchAssignReply>('/api/v1/admin/iam/assignments:batch-assign', body),

    listDelegations: (params?: ListDelegationsParams) =>
      get<DelegationsReply>('/api/v1/admin/iam/delegations', params),
    createDelegation: (body: CreateDelegationRequest) =>
      post<Delegation>('/api/v1/admin/iam/delegations', body),
    revokeDelegation: (id: string, body: RevokeDelegationRequest) =>
      post<Delegation>(
        `/api/v1/admin/iam/delegations/${enc(id)}:revoke`,
        body,
      ),

    explain: (body: ExplainAuthorizationRequest) =>
      post<ExplainAuthorizationReply>(
        '/api/v1/admin/iam/authorization:explain',
        body,
      ),
    simulate: (body: SimulateAuthorizationRequest) =>
      post<SimulateAuthorizationReply>(
        '/api/v1/admin/iam/authorization:simulate',
        body,
      ),
  },

  integrations: {
    listClients: () =>
      get<IntegrationClientsReply>('/api/v1/admin/integration-clients'),
    createClient: (body: CreateIntegrationClientRequest) =>
      post<IntegrationClientCredentialReply>(
        '/api/v1/admin/integration-clients',
        body,
      ),
    updateClient: (id: string, body: UpdateIntegrationClientRequest) =>
      patch<IntegrationClient>(
        `/api/v1/admin/integration-clients/${enc(id)}`,
        body,
      ),
    rotateCredential: (
      id: string,
      body: RotateIntegrationClientCredentialRequest,
    ) =>
      post<IntegrationClientCredentialReply>(
        `/api/v1/admin/integration-clients/${enc(id)}:rotate-credential`,
        body,
      ),
    disableClient: (id: string, body: DisableIntegrationClientRequest) =>
      post<IntegrationClient>(
        `/api/v1/admin/integration-clients/${enc(id)}:disable`,
        body,
      ),
    listEventDeliveries: (params?: ListEventDeliveriesParams) =>
      get<EventDeliveriesReply>('/api/v1/admin/event-deliveries', params),
    retryEventDelivery: (
      eventId: string,
      subscriberId: string,
      body: RetryEventDeliveryRequest,
    ) =>
      post<EventDelivery>(
        `/api/v1/admin/event-deliveries/${enc(eventId)}/subscribers/${enc(subscriberId)}:retry`,
        body,
      ),
  },

  oidc: {
    listClients: () =>
      get<OIDCClientsReply>('/api/v1/admin/oidc-clients'),
    createClient: (body: CreateOIDCClientRequest) =>
      post<OIDCClientCredentialReply>('/api/v1/admin/oidc-clients', body),
    updateClient: (id: string, body: UpdateOIDCClientRequest) =>
      patch<OIDCClient>(`/api/v1/admin/oidc-clients/${enc(id)}`, body),
    rotateSecret: (id: string, body: RotateOIDCClientSecretRequest) =>
      post<OIDCClientCredentialReply>(
        `/api/v1/admin/oidc-clients/${enc(id)}:rotate-secret`,
        body,
      ),
    disableClient: (id: string, body: DisableOIDCClientRequest) =>
      post<OIDCClient>(`/api/v1/admin/oidc-clients/${enc(id)}:disable`, body),
    // Public discovery document. This is a GET so the shared client never
    // attaches the CSRF header.
    discovery: () => get<OIDCDiscovery>('/.well-known/openid-configuration'),
  },

  settings: {
    auth: () => get<AuthSettings>('/api/v1/admin/settings/auth'),
    updateAuth: (body: UpdateAuthSettingsRequest) =>
      patch<AuthSettings>('/api/v1/admin/settings/auth', body),
    email: () => get<EmailSettings>('/api/v1/admin/settings/email'),
    updateEmail: (body: UpdateEmailSettingsRequest) =>
      patch<EmailSettings>('/api/v1/admin/settings/email', body),
  },
}

export type ApiClient = typeof api
