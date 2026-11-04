import {
  LogOut,
  Pencil,
  Plus,
  Trash2,
  UserRound,
} from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router'

import { Button } from '../../components/button'
import {
  Card,
  CardHeader,
  EmptyState,
  InlineAlert,
} from '../../components/card'
import { ConfirmDialog } from '../../components/dialog'
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
import { useAuth } from '../../lib/auth'
import { formatDateTime, formatNumber } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { Organization, OrganizationMember } from '../../lib/types'
import {
  canEditMember,
  canLeaveOrganization,
  canRemoveMember,
  departmentName,
  departmentRows,
  grantableRoles,
  isOrganizationManager,
  organizationIsActive,
  organizationRoleLabel,
} from './org-utils'
import { OrganizationRoleBadge } from './org-shared'

function memberLabel(member?: OrganizationMember | null): string {
  if (!member) return ''
  return member.display_name || member.username || `#${member.user_id ?? ''}`
}

export function OrganizationMembersTab({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const navigate = useNavigate()
  const { user } = useAuth()
  const active = organizationIsActive(org)
  const canManage = active && isOrganizationManager(org.role)
  const canLeave = active && canLeaveOrganization(org.role)

  const membersQuery = useQuery({
    queryKey: ['orgs', orgId, 'members'],
    queryFn: () => api.orgs.listMembers(orgId),
    retry: false,
  })
  const departmentsQuery = useQuery({
    queryKey: ['orgs', orgId, 'departments'],
    queryFn: () => api.orgs.listDepartments(orgId),
    retry: false,
  })
  const departments = departmentsQuery.data?.items ?? []
  const departmentOptions = departmentRows(departments)

  const invalidateMembers = [
    ['orgs', orgId, 'members'],
    ['orgs', 'detail', orgId],
    ['orgs', 'mine'],
  ]

  // Add member
  const [addOpen, setAddOpen] = useState(false)
  const [identifier, setIdentifier] = useState('')
  const [addRole, setAddRole] = useState('member')
  const [addDepartmentId, setAddDepartmentId] = useState('')
  const [addError, setAddError] = useState<string | null>(null)

  const openAdd = () => {
    setIdentifier('')
    setAddRole('member')
    setAddDepartmentId('')
    setAddError(null)
    setAddOpen(true)
  }

  const addMember = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.addMember(orgId, {
        id: orgId,
        identifier: identifier.trim(),
        role: addRole,
        department_id: addDepartmentId,
        reason,
      }),
    successMessage: '成员已添加',
    invalidate: invalidateMembers,
    onSuccess: () => {
      setAddOpen(false)
      setAddError(null)
    },
    onError: (error) => setAddError(error.message),
  })

  const submitAdd = (reason: string) => {
    if (!identifier.trim()) {
      setAddError('请输入用户名或邮箱')
      return
    }
    setAddError(null)
    addMember.mutate(reason)
  }

  // Edit member
  const [editTarget, setEditTarget] = useState<OrganizationMember | null>(null)
  const [editRole, setEditRole] = useState('member')
  const [editDepartmentId, setEditDepartmentId] = useState('')
  const [editError, setEditError] = useState<string | null>(null)

  const openEdit = (member: OrganizationMember) => {
    setEditTarget(member)
    setEditRole(member.role || 'member')
    setEditDepartmentId(member.department_id || '')
    setEditError(null)
  }

  const updateMember = useApiMutation({
    mutationFn: (reason: string) => {
      const target = editTarget
      if (!target?.user_id) throw new Error('未选择成员')
      return api.orgs.updateMember(orgId, target.user_id, {
        id: orgId,
        user_id: target.user_id,
        role: editRole,
        department_id: editDepartmentId,
        expected_revision: target.revision ?? '0',
        reason,
      })
    },
    successMessage: '成员已更新',
    invalidate: invalidateMembers,
    onSuccess: () => {
      setEditTarget(null)
      setEditError(null)
    },
    onError: (error) => setEditError(error.message),
  })

  const submitEdit = (reason: string) => {
    if (!editTarget) return
    if (!editRole) {
      setEditError('请选择组织角色')
      return
    }
    setEditError(null)
    updateMember.mutate(reason)
  }

  // Remove member
  const [removeTarget, setRemoveTarget] =
    useState<OrganizationMember | null>(null)

  const removeMember = useApiMutation({
    mutationFn: (reason: string) => {
      const target = removeTarget
      if (!target?.user_id) throw new Error('未选择成员')
      return api.orgs.removeMember(
        orgId,
        target.user_id,
        reason,
        target.revision ?? '0',
      )
    },
    successMessage: '成员已移出组织',
    invalidate: invalidateMembers,
    onSuccess: () => setRemoveTarget(null),
  })

  // Leave organization
  const [leaveOpen, setLeaveOpen] = useState(false)
  const leave = useApiMutation({
    mutationFn: () => api.orgs.leave(orgId),
    successMessage: '已退出组织',
    invalidate: [['orgs', 'mine']],
    onSuccess: () => {
      setLeaveOpen(false)
      navigate('/orgs')
    },
  })

  const members = membersQuery.data?.items ?? []
  const roles = grantableRoles(org.role)

  return (
    <div className="space-y-4">
      {!active ? (
        <InlineAlert tone="warning" title="组织已归档">
          归档组织的成员不能再被调整。下方列表仅作只读展示。
        </InlineAlert>
      ) : null}

      <Card>
        <CardHeader
          title="组织成员"
          description={`共 ${formatNumber(
            membersQuery.data?.items?.length ?? org.member_count,
          )} 名成员。普通成员列表中的邮箱会由服务端脱敏为空。`}
          actions={
            <>
              {canLeave ? (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => setLeaveOpen(true)}
                  icon={<LogOut className="h-3.5 w-3.5" />}
                >
                  退出组织
                </Button>
              ) : null}
              {canManage ? (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={openAdd}
                  icon={<Plus className="h-3.5 w-3.5" />}
                >
                  添加成员
                </Button>
              ) : null}
            </>
          }
        />
        <QueryBoundary query={membersQuery} loadingLabel="读取成员列表…">
          {members.length === 0 ? (
            <EmptyState
              icon={UserRound}
              title="组织还没有成员"
              description="添加成员后可以为其分配组织角色与部门。"
              action={
                canManage ? (
                  <Button size="sm" variant="primary" onClick={openAdd}>
                    添加成员
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <Table minWidth="min-w-[920px]">
              <THead>
                <TR>
                  <TH>成员</TH>
                  <TH>组织角色</TH>
                  <TH>部门</TH>
                  <TH>状态</TH>
                  <TH>加入时间</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {members.map((member) => {
                  const isSelf = Boolean(user?.id) && member.user_id === user?.id
                  const editable = canManage && canEditMember(org.role, member.role)
                  const removable =
                    canManage &&
                    !isSelf &&
                    canRemoveMember(org.role, member.role)
                  return (
                    <TR key={member.id || `${member.organization_id}:${member.user_id}`}>
                      <TD>
                        <div className="flex items-center gap-2">
                          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-slate-100 text-[11px] font-semibold text-slate-600">
                            {memberLabel(member).slice(0, 1) || '?'}
                          </span>
                          <div className="min-w-0">
                            <div className="max-w-[200px] truncate text-xs font-medium text-slate-800">
                              {memberLabel(member)}
                              {isSelf ? (
                                <span className="ml-1 text-[10px] text-slate-400">
                                  （我）
                                </span>
                              ) : null}
                            </div>
                            <div className="max-w-[220px] truncate font-mono text-[10px] text-slate-400">
                              @{member.username || '—'} · id={member.user_id}
                            </div>
                            <div
                              className="max-w-[220px] truncate text-[10px] text-slate-400"
                              title={
                                member.email
                                  ? undefined
                                  : '普通成员的邮箱由服务端脱敏为空'
                              }
                            >
                              {member.email || '—'}
                            </div>
                          </div>
                        </div>
                      </TD>
                      <TD>
                        <OrganizationRoleBadge role={member.role} />
                      </TD>
                      <TD className="max-w-[160px] truncate text-[11px] text-slate-600">
                        {departmentName(departments, member.department_id)}
                      </TD>
                      <TD>
                        <span className="text-[11px] text-slate-600">
                          {member.status === 'active'
                            ? '正常'
                            : member.status || '—'}
                        </span>
                      </TD>
                      <TD className="whitespace-nowrap text-[11px] text-slate-500">
                        {formatDateTime(member.joined_at)}
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-500">
                        {member.revision}
                      </TD>
                      <TD className="text-right">
                        <div className="flex justify-end gap-1">
                          {editable ? (
                            <Button
                              size="xs"
                              variant="secondary"
                              onClick={() => openEdit(member)}
                              icon={<Pencil className="h-3 w-3" />}
                            >
                              编辑
                            </Button>
                          ) : null}
                          {removable ? (
                            <Button
                              size="xs"
                              variant="danger"
                              onClick={() => setRemoveTarget(member)}
                              icon={<Trash2 className="h-3 w-3" />}
                            >
                              移除
                            </Button>
                          ) : null}
                          {!editable && !removable ? (
                            <span className="text-[10px] text-slate-400">—</span>
                          ) : null}
                        </div>
                      </TD>
                    </TR>
                  )
                })}
              </TBody>
            </Table>
          )}
        </QueryBoundary>
      </Card>

      <ReasonDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onConfirm={submitAdd}
        title="添加组织成员"
        description="按用户名或邮箱查找账号；只有 owner 或平台管理员可以授予 owner 角色。"
        confirmLabel="添加成员"
        busy={addMember.isPending}
        error={addError}
        hint="添加原因会写入审计日志，至少 2 个字符。"
      >
        <Field
          label="用户名或邮箱"
          htmlFor="org-member-identifier"
          required
          hint="普通成员的联系方式会按服务端脱敏策略展示。"
        >
          <Input
            id="org-member-identifier"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            placeholder="username 或 user@example.com"
            autoComplete="off"
          />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="组织角色" htmlFor="org-member-role" required>
            <Select
              id="org-member-role"
              value={addRole}
              onChange={(event) => setAddRole(event.target.value)}
            >
              {roles.map((role) => (
                <option key={role} value={role}>
                  {organizationRoleLabel(role)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="部门" htmlFor="org-member-department">
            <Select
              id="org-member-department"
              value={addDepartmentId}
              onChange={(event) => setAddDepartmentId(event.target.value)}
            >
              <option value="">不分配部门</option>
              {departmentOptions.map(({ department, depth }) => (
                <option key={department.id} value={department.id}>
                  {`${'· '.repeat(depth)}${department.name || department.code}`}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      </ReasonDialog>

      <ReasonDialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        onConfirm={submitEdit}
        title={`编辑成员「${memberLabel(editTarget)}」`}
        description={`提交时会携带当前 revision ${editTarget?.revision ?? '—'}；若已被他人修改会返回 409 冲突。`}
        confirmLabel="保存变更"
        busy={updateMember.isPending}
        error={editError}
        hint="角色变更原因会写入审计日志，至少 2 个字符。"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="组织角色" htmlFor="org-member-edit-role" required>
            <Select
              id="org-member-edit-role"
              value={editRole}
              onChange={(event) => setEditRole(event.target.value)}
            >
              {roles.map((role) => (
                <option key={role} value={role}>
                  {organizationRoleLabel(role)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="部门" htmlFor="org-member-edit-department">
            <Select
              id="org-member-edit-department"
              value={editDepartmentId}
              onChange={(event) => setEditDepartmentId(event.target.value)}
            >
              <option value="">不分配部门</option>
              {departmentOptions.map(({ department, depth }) => (
                <option key={department.id} value={department.id}>
                  {`${'· '.repeat(depth)}${department.name || department.code}`}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        {editTarget?.role === 'owner' && editRole !== 'owner' ? (
          <InlineAlert tone="warning" title="转移拥有者">
            将拥有者降级前，服务端会确认组织中仍有其他有效拥有者。
          </InlineAlert>
        ) : null}
      </ReasonDialog>

      <ReasonDialog
        open={removeTarget !== null}
        onClose={() => setRemoveTarget(null)}
        onConfirm={(reason) => {
          if (removeTarget) removeMember.mutate(reason)
        }}
        title={`移除成员「${memberLabel(removeTarget)}」`}
        description="成员将从组织中移除，其平台账号不受影响。管理员只能移除普通成员。"
        confirmLabel="移除成员"
        tone="danger"
        busy={removeMember.isPending}
        hint="移除原因会写入审计日志，至少 2 个字符。"
      />

      <ConfirmDialog
        open={leaveOpen}
        onClose={() => setLeaveOpen(false)}
        onConfirm={() => leave.mutate(undefined)}
        title="退出当前组织"
        description="退出后你将无法再访问该组织的成员与部门。"
        confirmLabel="确认退出"
        tone="danger"
        loading={leave.isPending}
      >
        如果你是组织中唯一的拥有者，服务端会拒绝退出。请先转移拥有者角色。
      </ConfirmDialog>
    </div>
  )
}
