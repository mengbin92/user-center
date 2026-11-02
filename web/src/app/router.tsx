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
import { LoginPage } from '../features/auth/login-page'
import { RegisterPage } from '../features/auth/register-page'
import { ResetPasswordPage } from '../features/auth/reset-password-page'
import { ActivityPage } from '../features/account/activity-page'
import { ProfilePage } from '../features/account/profile-page'
import { SessionRolesPage } from '../features/account/roles-page'
import { SecurityPage } from '../features/account/security-page'
import { SessionsPage } from '../features/account/sessions-page'
import { AdminAssignmentsPage } from '../features/admin/assignments-page'
import { AdminAuditsPage } from '../features/admin/audits-page'
import { AdminConstraintsPage } from '../features/admin/constraints-page'
import { AdminDelegationsPage } from '../features/admin/delegations-page'
import { AdminExplainPage } from '../features/admin/explain-page'
import { AdminExportsPage } from '../features/admin/exports-page'
import { AdminIntegrationsPage } from '../features/admin/integrations-page'
import { AdminMenusPage } from '../features/admin/menus-page'
import { AdminOverviewPage } from '../features/admin/overview-page'
import { AdminPermissionsPage } from '../features/admin/permissions-page'
import { AdminRoleDetailPage } from '../features/admin/role-detail-page'
import { AdminRolesPage } from '../features/admin/roles-page'
import { AdminAuthSettingsPage } from '../features/admin/settings-auth-page'
import { AdminEmailSettingsPage } from '../features/admin/settings-email-page'
import { AdminUserDetailPage } from '../features/admin/user-detail-page'
import { AdminUsersPage } from '../features/admin/users-page'

export function AppRoutes() {
  return (
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
        <Route path="/account" element={<AccountLayout />}>
          <Route index element={<ProfilePage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="roles" element={<SessionRolesPage />} />
          <Route path="activity" element={<ActivityPage />} />
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
            path="exports"
            element={
              <RequirePermission anyOf={['identity.user.export', 'audit.export']}>
                <AdminExportsPage />
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
  )
}
