import { lazy, Suspense, type ComponentType } from 'react'
import { Navigate, Route, Routes } from 'react-router'

import { AccountLayout } from './account-layout'
import { AdminLayout } from './admin-layout'
import {
  NotFoundPage,
  RequireAdmin,
  RequireAuth,
  RequirePermission,
} from './guards'
import { AuthCallbackPage } from '../features/auth/callback-page'
import { ForgotPasswordPage } from '../features/auth/forgot-password-page'
import { PrivacyPage, TermsPage } from '../features/auth/legal-pages'
import { ConsentPage } from '../features/auth/consent-page'
import { AcceptInvitationPage } from '../features/orgs/accept-invitation-page'
import { LoginPage } from '../features/auth/login-page'
import { RegisterPage } from '../features/auth/register-page'
import { ResetPasswordPage } from '../features/auth/reset-password-page'


// Route-level splitting keeps the initial bundle small: the admin and tenant
// screens are only fetched when the route is visited.
type PageModule = Record<string, ComponentType<any>>

function lazyPage(loader: () => Promise<PageModule>, name: string) {
  return lazy(async () => {
    const module = await loader()
    return { default: module[name] }
  })
}

const ActivityPage = lazyPage(() => import('../features/account/activity-page'), 'ActivityPage')
const ConsentsPage = lazyPage(() => import('../features/account/consents-page'), 'ConsentsPage')
const ProfilePage = lazyPage(() => import('../features/account/profile-page'), 'ProfilePage')
const SessionRolesPage = lazyPage(() => import('../features/account/roles-page'), 'SessionRolesPage')
const SecurityPage = lazyPage(() => import('../features/account/security-page'), 'SecurityPage')
const SessionsPage = lazyPage(() => import('../features/account/sessions-page'), 'SessionsPage')
const AdminAssignmentsPage = lazyPage(() => import('../features/admin/assignments-page'), 'AdminAssignmentsPage')
const AdminApplicationsPage = lazyPage(() => import('../features/admin/applications-page'), 'AdminApplicationsPage')
const AdminAuditsPage = lazyPage(() => import('../features/admin/audits-page'), 'AdminAuditsPage')
const AdminAuditDetailPage = lazyPage(() => import('../features/admin/audit-detail-page'), 'AdminAuditDetailPage')
const AdminConstraintsPage = lazyPage(() => import('../features/admin/constraints-page'), 'AdminConstraintsPage')
const AdminDelegationsPage = lazyPage(() => import('../features/admin/delegations-page'), 'AdminDelegationsPage')
const AdminExplainPage = lazyPage(() => import('../features/admin/explain-page'), 'AdminExplainPage')
const AdminExportsPage = lazyPage(() => import('../features/admin/exports-page'), 'AdminExportsPage')
const AdminIntegrationsPage = lazyPage(() => import('../features/admin/integrations-page'), 'AdminIntegrationsPage')
const AdminMenusPage = lazyPage(() => import('../features/admin/menus-page'), 'AdminMenusPage')
const AdminOverviewPage = lazyPage(() => import('../features/admin/overview-page'), 'AdminOverviewPage')
const AdminOrganizationsPage = lazyPage(() => import('../features/admin/organizations-page'), 'AdminOrganizationsPage')
const AdminPermissionsPage = lazyPage(() => import('../features/admin/permissions-page'), 'AdminPermissionsPage')
const AdminRoleDetailPage = lazyPage(() => import('../features/admin/role-detail-page'), 'AdminRoleDetailPage')
const AdminRolesPage = lazyPage(() => import('../features/admin/roles-page'), 'AdminRolesPage')
const AdminAuthSettingsPage = lazyPage(() => import('../features/admin/settings-auth-page'), 'AdminAuthSettingsPage')
const AdminEmailSettingsPage = lazyPage(() => import('../features/admin/settings-email-page'), 'AdminEmailSettingsPage')
const AdminProvidersPage = lazyPage(() => import('../features/admin/settings-providers-page'), 'AdminProvidersPage')
const AdminOrganizationSettingsPage = lazyPage(() => import('../features/admin/settings-organization-page'), 'AdminOrganizationSettingsPage')
const AdminUserDetailPage = lazyPage(() => import('../features/admin/user-detail-page'), 'AdminUserDetailPage')
const AdminUsersPage = lazyPage(() => import('../features/admin/users-page'), 'AdminUsersPage')
const OrganizationDetailPage = lazyPage(() => import('../features/orgs/org-detail-page'), 'OrganizationDetailPage')
const OrganizationsPage = lazyPage(() => import('../features/orgs/orgs-page'), 'OrganizationsPage')

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center text-sm text-slate-500">
      页面加载中…
    </div>
  )
}

export function AppRoutes() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/" element={<Navigate to="/account" replace />} />

        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/terms" element={<TermsPage />} />
        <Route path="/privacy" element={<PrivacyPage />} />
        <Route path="/auth/callback/:provider" element={<AuthCallbackPage />} />

        <Route element={<RequireAuth />}>
          <Route path="/consent" element={<ConsentPage />} />
          <Route path="/accept-invitation" element={<AcceptInvitationPage />} />

          <Route path="/account" element={<AccountLayout />}>
            <Route index element={<ProfilePage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="sessions" element={<SessionsPage />} />
            <Route path="roles" element={<SessionRolesPage />} />
            <Route path="activity" element={<ActivityPage />} />
            <Route path="consents" element={<ConsentsPage />} />
          </Route>

          <Route path="/orgs" element={<AccountLayout />}>
            <Route index element={<OrganizationsPage />} />
            <Route path=":orgId" element={<OrganizationDetailPage />} />
          </Route>

          <Route
            path="/admin"
            element={
              <RequireAdmin>
                <AdminLayout />
              </RequireAdmin>
            }
          >
            <Route
              index
              element={
                <RequirePermission permission="identity.user.list">
                  <AdminOverviewPage />
                </RequirePermission>
              }
            />
            <Route
              path="users"
              element={
                <RequirePermission permission="identity.user.list">
                  <AdminUsersPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/:id"
              element={
                <RequirePermission permission="identity.user.read">
                  <AdminUserDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="organizations"
              element={
                <RequirePermission permission="organization.admin.read">
                  <AdminOrganizationsPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/roles"
              element={
                <RequirePermission permission="iam.role.read">
                  <AdminRolesPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/roles/:id"
              element={
                <RequirePermission permission="iam.role.read">
                  <AdminRoleDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/permissions"
              element={
                <RequirePermission permission="iam.permission.read">
                  <AdminPermissionsPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/assignments"
              element={
                <RequirePermission permission="iam.assignment.read">
                  <AdminAssignmentsPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/delegations"
              element={
                <RequirePermission permission="iam.delegation.read">
                  <AdminDelegationsPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/constraints"
              element={
                <RequirePermission permission="iam.constraint.read">
                  <AdminConstraintsPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/menus"
              element={
                <RequirePermission permission="iam.menu.read">
                  <AdminMenusPage />
                </RequirePermission>
              }
            />
            <Route
              path="iam/explain"
              element={
                <RequirePermission permission="iam.authorization.explain">
                  <AdminExplainPage />
                </RequirePermission>
              }
            />
            <Route
              path="audits"
              element={
                <RequirePermission permission="audit.read">
                  <AdminAuditsPage />
                </RequirePermission>
              }
            />
            <Route
              path="settings/providers"
              element={
                <RequirePermission permission="settings.auth.read">
                  <AdminProvidersPage />
                </RequirePermission>
              }
            />
            <Route
              path="settings/organization"
              element={
                <RequirePermission permission="settings.organization.read">
                  <AdminOrganizationSettingsPage />
                </RequirePermission>
              }
            />
            <Route
              path="audits/:id"
              element={
                <RequirePermission permission="audit.read">
                  <AdminAuditDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="exports"
              element={
                <RequirePermission anyOf={['identity.user.export', 'audit.export']}>
                  <AdminExportsPage />
                </RequirePermission>
              }
            />
            <Route
              path="applications"
              element={
                <RequirePermission permission="oidc.client.read">
                  <AdminApplicationsPage />
                </RequirePermission>
              }
            />
            <Route
              path="integrations"
              element={
                <RequirePermission
                  anyOf={['integration.client.read', 'integration.delivery.read']}
                >
                  <AdminIntegrationsPage />
                </RequirePermission>
              }
            />
            <Route
              path="settings/auth"
              element={
                <RequirePermission permission="settings.auth.read">
                  <AdminAuthSettingsPage />
                </RequirePermission>
              }
            />
            <Route
              path="settings/email"
              element={
                <RequirePermission permission="settings.email.read">
                  <AdminEmailSettingsPage />
                </RequirePermission>
              }
            />
            <Route path="*" element={<Navigate to="/admin" replace />} />
          </Route>
        </Route>

        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  )
}
