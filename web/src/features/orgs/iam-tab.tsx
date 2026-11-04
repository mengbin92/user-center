import { KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Button } from '../../components/button'
import {
  Card,
  CardHeader,
  EmptyState,
  InlineAlert,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import {
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Organization, OrgRole } from '../../lib/types'

function scopeAll() {
  return { all: true }
}

function grantsOf(role: OrgRole) {
  return (role.grants ?? []).map((grant) => ({
    operation: grant.operation ?? '',
    effect: grant.effect ?? 'allow',
    scope: grant.scope ?? scopeAll(),
  }))
}

export function OrganizationIAMTab({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const active = org.status === 'active'
  const canManage = active && (org.role === 'owner' || org.role === 'platform')

  const rolesQuery = useQuery({
    queryKey: ['orgs', orgId, 'iam', 'roles'],
    queryFn: () => api.orgs.listRoles(orgId),
    retry: false,
  })
  const permissionsQuery = useQuery({
    queryKey: ['orgs', orgId, 'iam', 'permissions'],
    queryFn: () => api.orgs.listRolePermissions(orgId),
    retry: false,
  })
  const assignmentsQuery = useQuery({
    queryKey: ['orgs', orgId, 'iam', 'assignments'],
    queryFn: () => api.orgs.listAssignments(orgId),
    retry: false,
  })
  const membersQuery = useQuery({
    queryKey: ['orgs', orgId, 'members'],
    queryFn: () => api.orgs.listMembers(orgId),
    retry: false,
  })

  const roles = rolesQuery.data?.items ?? []
  const permissions = useMemo(
    () => (permissionsQuery.data?.items ?? []).filter((p) => !!p.code),
    [permissionsQuery.data],
  )
  const assignments = (assignmentsQuery.data?.items ?? []).filter(
    (item) => item.status === 'active',
  )
  const members = membersQuery.data?.items ?? []
  const customRoles = roles.filter((role) => !role.builtin)

  const invalidate = [
    ['orgs', orgId, 'iam', 'roles'],
    ['orgs', orgId, 'iam', 'assignments'],
  ]

  // Create role
  const [createOpen, setCreateOpen] = useState(false)
  const [code, setCode] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [formError, setFormError] = useState<string | null>(null)

  const openCreate = () => {
    setCode('')
    setName('')
    setDescription('')
    setSelected([])
    setFormError(null)
    setCreateOpen(true)
  }

  const togglePermission = (operation: string) => {
    setSelected((current) =>
      current.includes(operation)
        ? current.filter((item) => item !== operation)
        : [...current, operation],
    )
  }

  const createRole = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.createRole(orgId, {
        id: orgId,
        code: code.trim(),
        name: name.trim(),
        description: description.trim(),
        grants: selected.map((operation) => ({
          operation,
          effect: 'allow',
          scope: scopeAll(),
        })),
        reason,
      }),
    successMessage: '组织角色已创建',
    invalidate,
    onSuccess: () => {
      setCreateOpen(false)
      setFormError(null)
    },
    onError: (error) => setFormError(error.message),
  })

  // Edit grants
  const [editing, setEditing] = useState<OrgRole | null>(null)
  const [editSelected, setEditSelected] = useState<string[]>([])
  const [editError, setEditError] = useState<string | null>(null)
  const openEdit = (role: OrgRole) => {
    setEditing(role)
    setEditSelected(grantsOf(role).map((grant) => grant.operation))
    setEditError(null)
  }
  const saveGrants = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.putRolePermissions(orgId, String(editing?.id ?? ''), {
        id: orgId,
        role_id: String(editing?.id ?? ''),
        grants: editSelected.map((operation) => ({
          operation,
          effect: 'allow',
          scope: scopeAll(),
        })),
        expected_revision: String(editing?.revision ?? ''),
        reason,
      }),
    successMessage: '角色权限已更新',
    invalidate,
    onSuccess: () => setEditing(null),
    onError: (error) => setEditError(error.message),
  })

  // Archive role
  const [archiving, setArchiving] = useState<OrgRole | null>(null)
  const [archiveError, setArchiveError] = useState<string | null>(null)
  const archiveRole = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.archiveRole(orgId, String(archiving?.id ?? ''), {
        id: orgId,
        role_id: String(archiving?.id ?? ''),
        expected_revision: String(archiving?.revision ?? ''),
        reason,
      }),
    successMessage: '组织角色已归档',
    invalidate,
    onSuccess: () => setArchiving(null),
    onError: (error) => setArchiveError(error.message),
  })

  // Assign role
  const [assignOpen, setAssignOpen] = useState(false)
  const [assignUser, setAssignUser] = useState('')
  const [assignRoleId, setAssignRoleId] = useState('')
  const [assignExpires, setAssignExpires] = useState('')
  const [assignError, setAssignError] = useState<string | null>(null)
  const openAssign = () => {
    setAssignUser('')
    setAssignRoleId('')
    setAssignExpires('')
    setAssignError(null)
    setAssignOpen(true)
  }
  const assignRole = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.assignRole(orgId, {
        id: orgId,
        user_id: assignUser,
        role_id: assignRoleId,
        expires_at: assignExpires ? new Date(assignExpires).toISOString() : '',
        reason,
      }),
    successMessage: '角色已分配',
    invalidate,
    onSuccess: () => setAssignOpen(false),
    onError: (error) => setAssignError(error.message),
  })

  // Revoke assignment
  const [revoking, setRevoking] = useState<{
    id?: string
    revision?: string
    label?: string
  } | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const revoke = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.revokeAssignment(
        orgId,
        String(revoking?.id ?? ''),
        reason,
        String(revoking?.revision ?? ''),
      ),
    successMessage: '授权已撤销',
    invalidate,
    onSuccess: () => setRevoking(null),
    onError: (error) => setRevokeError(error.message),
  })

  return (
    <div className="space-y-4">
      <InlineAlert tone="info" title="组织域 IAM">
        角色、权限与授权只在本组织内生效。平台角色不会获得组织内权限，组织角色也不会影响平台管理。
      </InlineAlert>

      <Card>
        <CardHeader
          title="组织角色"
          description="内置角色由成员角色决定；自定义角色可在本组织内自由授予权限。"
          actions={
            canManage ? (
              <Button size="sm" onClick={openCreate}>
                <Plus className="h-3.5 w-3.5" />
                新建角色
              </Button>
            ) : null
          }
        />
        <QueryBoundary query={rolesQuery} loadingLabel="读取组织角色…">
          {roles.length === 0 ? (
            <EmptyState title="暂无组织角色" />
          ) : (
            <Table minWidth="min-w-[720px]">
              <THead>
                <TR>
                  <TH>角色</TH>
                  <TH>code</TH>
                  <TH>类型</TH>
                  <TH>权限数</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {roles.map((role) => {
                  const grants = grantsOf(role)
                  return (
                    <TR key={role.id}>
                      <TD>
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="h-3.5 w-3.5 text-slate-400" />
                          <span className="font-medium text-slate-800">
                            {role.name || role.code}
                          </span>
                        </div>
                        {role.description ? (
                          <div className="mt-0.5 text-[11px] text-slate-500">
                            {role.description}
                          </div>
                        ) : null}
                      </TD>
                      <TD className="font-mono text-[11px]">{role.code}</TD>
                      <TD>
                        <span
                          className={
                            role.builtin
                              ? 'rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600'
                              : 'rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] text-indigo-700'
                          }
                        >
                          {role.builtin ? '内置' : '自定义'}
                        </span>
                      </TD>
                      <TD>{grants.length}</TD>
                      <TD className="font-mono text-[11px]">{role.revision}</TD>
                      <TD className="text-right">
                        {canManage && !role.builtin ? (
                          <span className="inline-flex gap-1">
                            <Button
                              size="sm"
                              variant="secondary"
                              onClick={() => openEdit(role)}
                            >
                              编辑权限
                            </Button>
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() => {
                                setArchiving(role)
                                setArchiveError(null)
                              }}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-400">—</span>
                        )}
                      </TD>
                    </TR>
                  )
                })}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <Card>
        <CardHeader
          title="角色授权"
          description="仅自定义角色需要单独分配；owner/admin/member 由成员角色自动同步。"
          actions={
            canManage ? (
              <Button
                size="sm"
                onClick={openAssign}
                disabled={customRoles.length === 0}
              >
                <KeyRound className="h-3.5 w-3.5" />
                分配角色
              </Button>
            ) : null
          }
        />
        <QueryBoundary query={assignmentsQuery} loadingLabel="读取授权…">
          {assignments.length === 0 ? (
            <EmptyState title="暂无角色授权" />
          ) : (
            <Table minWidth="min-w-[720px]">
              <THead>
                <TR>
                  <TH>成员</TH>
                  <TH>角色</TH>
                  <TH>来源</TH>
                  <TH>过期时间</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {assignments.map((item) => {
                  const builtin = ['org_owner', 'org_admin', 'org_member'].includes(
                    item.role_code ?? '',
                  )
                  return (
                    <TR key={item.id}>
                      <TD>
                        <div className="font-medium text-slate-800">
                          {item.display_name || item.username}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {item.username}
                        </div>
                      </TD>
                      <TD>
                        <span className="font-medium">{item.role_name}</span>
                        <div className="font-mono text-[11px] text-slate-500">
                          {item.role_code}
                        </div>
                      </TD>
                      <TD>{item.origin}</TD>
                      <TD>{formatDateTime(item.expires_at) || '长期'}</TD>
                      <TD className="font-mono text-[11px]">{item.revision}</TD>
                      <TD className="text-right">
                        {canManage && !builtin ? (
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => {
                              setRevoking({
                                id: item.id,
                                revision: item.revision,
                                label: `${item.username} · ${item.role_code}`,
                              })
                              setRevokeError(null)
                            }}
                          >
                            撤销
                          </Button>
                        ) : (
                          <span className="text-[11px] text-slate-400">—</span>
                        )}
                      </TD>
                    </TR>
                  )
                })}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="新建组织角色"
        description="角色只在本组织内生效，可授予的权限来自组织域权限目录。"
        size="lg"
        dismissible={!createRole.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createRole.isPending}
            >
              取消
            </Button>
            <Button
              size="sm"
              onClick={() =>
                createRole.mutate('create organization role')
              }
              loading={createRole.isPending}
              disabled={!code.trim() || !name.trim()}
            >
              创建
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {formError ? <InlineAlert tone="danger" title="创建失败">{formError}</InlineAlert> : null}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="code">
              <Input
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="auditor"
              />
            </Field>
            <Field label="名称">
              <Input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="审计员"
              />
            </Field>
          </div>
          <Field label="描述">
            <Input
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="只读审计角色"
            />
          </Field>
          <div className="space-y-1">
            <div className="text-[11px] font-medium text-slate-600">权限</div>
            <div className="max-h-64 space-y-1 overflow-y-auto rounded-md border border-slate-200 p-2">
              {permissions.map((permission) => (
                <label
                  key={permission.code}
                  className="flex items-start gap-2 rounded px-1 py-1 text-[12px] hover:bg-slate-50"
                >
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={selected.includes(permission.code ?? '')}
                    onChange={() => togglePermission(permission.code ?? '')}
                  />
                  <span>
                    <span className="font-medium text-slate-700">
                      {permission.name}
                    </span>
                    <span className="ml-1 font-mono text-[11px] text-slate-500">
                      {permission.code}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={!!editing}
        onClose={() => setEditing(null)}
        title={`编辑权限 · ${editing?.name ?? ''}`}
        size="lg"
        dismissible={!saveGrants.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditing(null)}
              disabled={saveGrants.isPending}
            >
              取消
            </Button>
            <Button
              size="sm"
              onClick={() => saveGrants.mutate('update organization role permissions')}
              loading={saveGrants.isPending}
            >
              保存
            </Button>
          </>
        }
      >
        <div className="space-y-2">
          {editError ? <InlineAlert tone="danger" title="保存失败">{editError}</InlineAlert> : null}
          <div className="max-h-72 space-y-1 overflow-y-auto rounded-md border border-slate-200 p-2">
            {permissions.map((permission) => (
              <label
                key={permission.code}
                className="flex items-start gap-2 rounded px-1 py-1 text-[12px] hover:bg-slate-50"
              >
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={editSelected.includes(permission.code ?? '')}
                  onChange={() => {
                    const op = permission.code ?? ''
                    setEditSelected((current) =>
                      current.includes(op)
                        ? current.filter((item) => item !== op)
                        : [...current, op],
                    )
                  }}
                />
                <span>
                  <span className="font-medium text-slate-700">
                    {permission.name}
                  </span>
                  <span className="ml-1 font-mono text-[11px] text-slate-500">
                    {permission.code}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </div>
      </Dialog>

      <Dialog
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        title="分配组织角色"
        size="md"
        dismissible={!assignRole.isPending}
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setAssignOpen(false)}
              disabled={assignRole.isPending}
            >
              取消
            </Button>
            <Button
              size="sm"
              onClick={() => assignRole.mutate('assign organization role')}
              loading={assignRole.isPending}
              disabled={!assignUser || !assignRoleId}
            >
              分配
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {assignError ? <InlineAlert tone="danger" title="分配失败">{assignError}</InlineAlert> : null}
          <Field label="成员">
            <Select
              value={assignUser}
              onChange={(event) => setAssignUser(event.target.value)}
            >
              <option value="">选择成员</option>
              {members.map((member) => (
                <option key={member.user_id} value={member.user_id}>
                  {member.display_name || member.username}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="角色">
            <Select
              value={assignRoleId}
              onChange={(event) => setAssignRoleId(event.target.value)}
            >
              <option value="">选择自定义角色</option>
              {customRoles.map((role) => (
                <option key={role.id} value={role.id}>
                  {role.name} ({role.code})
                </option>
              ))}
            </Select>
          </Field>
          <Field label="过期时间（可选）">
            <Input
              type="datetime-local"
              value={assignExpires}
              onChange={(event) => setAssignExpires(event.target.value)}
            />
          </Field>
        </div>
      </Dialog>

      <ReasonDialog
        open={!!archiving}
        onClose={() => setArchiving(null)}
        onConfirm={(reason) => archiveRole.mutate(reason)}
        title={`归档角色 · ${archiving?.name ?? ''}`}
        description="归档后该角色不可再分配，历史授权保留。"
        tone="danger"
        confirmLabel="归档"
        busy={archiveRole.isPending}
        error={archiveError}
      />

      <ReasonDialog
        open={!!revoking}
        onClose={() => setRevoking(null)}
        onConfirm={(reason) => revoke.mutate(reason)}
        title="撤销角色授权"
        description={revoking?.label}
        tone="danger"
        confirmLabel="撤销"
        busy={revoke.isPending}
        error={revokeError}
      />
    </div>
  )
}
