import { Network, Pencil, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
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
import { useApiMutation } from '../../lib/mutations'
import type { Department, Organization } from '../../lib/types'
import {
  canManageDepartments,
  departmentName,
  departmentRows,
  organizationIsActive,
} from './org-utils'
import { OrganizationStatusBadge } from './org-shared'

const DEPARTMENT_CODE_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/

export function OrganizationDepartmentsTab({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const active = organizationIsActive(org)
  const canManage = active && canManageDepartments(org.role)

  const departmentsQuery = useQuery({
    queryKey: ['orgs', orgId, 'departments'],
    queryFn: () => api.orgs.listDepartments(orgId),
    retry: false,
  })
  const departments = departmentsQuery.data?.items ?? []
  const rows = departmentRows(departments)
  const parentOptions = rows.filter(
    ({ department }) => department.status !== 'archived',
  )

  const invalidateDepartments = [
    ['orgs', orgId, 'departments'],
    ['orgs', orgId, 'members'],
    ['orgs', 'detail', orgId],
    ['orgs', 'mine'],
  ]

  // Create
  const [createOpen, setCreateOpen] = useState(false)
  const [createParentId, setCreateParentId] = useState('')
  const [createCode, setCreateCode] = useState('')
  const [createName, setCreateName] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)

  const openCreate = () => {
    setCreateParentId('')
    setCreateCode('')
    setCreateName('')
    setCreateError(null)
    setCreateOpen(true)
  }

  const createDepartment = useApiMutation({
    mutationFn: () =>
      api.orgs.createDepartment(orgId, {
        id: orgId,
        parent_id: createParentId,
        code: createCode.trim().toLowerCase(),
        name: createName.trim(),
      }),
    successMessage: '部门已创建',
    invalidate: invalidateDepartments,
    onSuccess: () => setCreateOpen(false),
    onError: (error) => setCreateError(error.message),
  })

  const submitCreate = () => {
    const code = createCode.trim().toLowerCase()
    if (!DEPARTMENT_CODE_PATTERN.test(code)) {
      setCreateError('部门 code 必须为 2-64 位小写字母、数字或短横线')
      return
    }
    if (!createName.trim()) {
      setCreateError('请填写部门名称')
      return
    }
    setCreateError(null)
    createDepartment.mutate(undefined)
  }

  // Update
  const [editTarget, setEditTarget] = useState<Department | null>(null)
  const [editParentId, setEditParentId] = useState('')
  const [editCode, setEditCode] = useState('')
  const [editName, setEditName] = useState('')
  const [editError, setEditError] = useState<string | null>(null)

  const openEdit = (department: Department) => {
    setEditTarget(department)
    setEditParentId(
      department.parent_id && department.parent_id !== '0'
        ? department.parent_id
        : '',
    )
    setEditCode(department.code || '')
    setEditName(department.name || '')
    setEditError(null)
  }

  const updateDepartment = useApiMutation({
    mutationFn: () => {
      const target = editTarget
      if (!target?.id) throw new Error('未选择部门')
      return api.orgs.updateDepartment(orgId, target.id, {
        id: orgId,
        department_id: target.id,
        parent_id: editParentId,
        code: editCode.trim().toLowerCase(),
        name: editName.trim(),
        expected_revision: target.revision ?? '0',
        reason: 'update department',
      })
    },
    successMessage: '部门已更新',
    invalidate: invalidateDepartments,
    onSuccess: () => setEditTarget(null),
    onError: (error) => setEditError(error.message),
  })

  const submitEdit = () => {
    const code = editCode.trim().toLowerCase()
    if (!DEPARTMENT_CODE_PATTERN.test(code)) {
      setEditError('部门 code 必须为 2-64 位小写字母、数字或短横线')
      return
    }
    if (!editName.trim()) {
      setEditError('请填写部门名称')
      return
    }
    setEditError(null)
    updateDepartment.mutate(undefined)
  }

  // Archive
  const [archiveTarget, setArchiveTarget] = useState<Department | null>(null)
  const archiveDepartment = useApiMutation({
    mutationFn: (reason: string) => {
      const target = archiveTarget
      if (!target?.id) throw new Error('未选择部门')
      return api.orgs.archiveDepartment(orgId, target.id, {
        id: orgId,
        department_id: target.id,
        expected_revision: target.revision ?? '0',
        reason,
      })
    },
    successMessage: '部门已归档',
    invalidate: invalidateDepartments,
    onSuccess: () => setArchiveTarget(null),
  })

  return (
    <div className="space-y-4">
      {!active ? (
        <InlineAlert tone="warning" title="组织已归档">
          归档组织的部门不再允许创建、修改或归档。
        </InlineAlert>
      ) : null}

      <Card>
        <CardHeader
          title="组织部门"
          description={`共 ${departments.length} 个部门。部门以 parent/child 关系组织，归档部门不会出现在上级选择列表中。`}
          actions={
            canManage ? (
              <Button
                size="sm"
                variant="primary"
                onClick={openCreate}
                icon={<Plus className="h-3.5 w-3.5" />}
              >
                新建部门
              </Button>
            ) : null
          }
        />
        <QueryBoundary query={departmentsQuery} loadingLabel="读取部门列表…">
          {departments.length === 0 ? (
            <EmptyState
              icon={Network}
              title="还没有部门"
              description="创建部门后，可以在添加或编辑成员时将其分配到部门。"
              action={
                canManage ? (
                  <Button size="sm" variant="primary" onClick={openCreate}>
                    新建部门
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <Table minWidth="min-w-[820px]">
              <THead>
                <TR>
                  <TH>部门</TH>
                  <TH>code</TH>
                  <TH>上级部门</TH>
                  <TH>状态</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map(({ department, depth }) => {
                  const archived = department.status === 'archived'
                  return (
                    <TR key={department.id}>
                      <TD>
                        <div
                          className="flex items-center gap-2"
                          style={{ paddingLeft: depth * 16 }}
                        >
                          <Network className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                          <span className="text-xs font-medium text-slate-800">
                            {department.name || '—'}
                          </span>
                        </div>
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-600">
                        {department.code}
                      </TD>
                      <TD className="text-[11px] text-slate-600">
                        {departmentName(departments, department.parent_id)}
                      </TD>
                      <TD>
                        <OrganizationStatusBadge status={department.status} />
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-500">
                        {department.revision}
                      </TD>
                      <TD className="text-right">
                        {canManage && !archived ? (
                          <div className="flex justify-end gap-1">
                            <Button
                              size="xs"
                              variant="secondary"
                              onClick={() => openEdit(department)}
                              icon={<Pencil className="h-3 w-3" />}
                            >
                              编辑
                            </Button>
                            <Button
                              size="xs"
                              variant="danger"
                              onClick={() => setArchiveTarget(department)}
                              icon={<Trash2 className="h-3 w-3" />}
                            >
                              归档
                            </Button>
                          </div>
                        ) : archived ? (
                          <span className="text-[10px] text-slate-400">
                            只读
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-400">—</span>
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
        title="新建部门"
        description="部门 code 在组织内唯一，上级部门可以留空。"
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createDepartment.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitCreate}
              loading={createDepartment.isPending}
            >
              创建部门
            </Button>
          </>
        }
      >
        <Field label="上级部门" htmlFor="dept-create-parent">
          <Select
            id="dept-create-parent"
            value={createParentId}
            onChange={(event) => setCreateParentId(event.target.value)}
          >
            <option value="">无（顶级部门）</option>
            {parentOptions.map(({ department, depth }) => (
              <option key={department.id} value={department.id}>
                {`${'· '.repeat(depth)}${department.name || department.code}`}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label="code"
          htmlFor="dept-create-code"
          required
          hint="2-64 位小写字母、数字或短横线。"
        >
          <Input
            id="dept-create-code"
            value={createCode}
            onChange={(event) => setCreateCode(event.target.value)}
            placeholder="engineering"
            autoComplete="off"
          />
        </Field>
        <Field label="名称" htmlFor="dept-create-name" required>
          <Input
            id="dept-create-name"
            value={createName}
            onChange={(event) => setCreateName(event.target.value)}
            placeholder="例如：研发部"
          />
        </Field>
        {createError ? (
          <InlineAlert tone="danger">{createError}</InlineAlert>
        ) : null}
      </Dialog>

      <Dialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={`编辑部门「${editTarget?.name ?? ''}」`}
        description={`提交时会携带当前 revision ${editTarget?.revision ?? '—'}；若已被他人修改会返回 409 冲突。`}
        size="md"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
              disabled={updateDepartment.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitEdit}
              loading={updateDepartment.isPending}
            >
              保存
            </Button>
          </>
        }
      >
        <Field
          label="上级部门"
          htmlFor="dept-edit-parent"
          hint="不能选择自身；服务端会拒绝形成环的层级。"
        >
          <Select
            id="dept-edit-parent"
            value={editParentId}
            onChange={(event) => setEditParentId(event.target.value)}
          >
            <option value="">无（顶级部门）</option>
            {parentOptions
              .filter(({ department }) => department.id !== editTarget?.id)
              .map(({ department, depth }) => (
                <option key={department.id} value={department.id}>
                  {`${'· '.repeat(depth)}${department.name || department.code}`}
                </option>
              ))}
          </Select>
        </Field>
        <Field label="code" htmlFor="dept-edit-code" required>
          <Input
            id="dept-edit-code"
            value={editCode}
            onChange={(event) => setEditCode(event.target.value)}
          />
        </Field>
        <Field label="名称" htmlFor="dept-edit-name" required>
          <Input
            id="dept-edit-name"
            value={editName}
            onChange={(event) => setEditName(event.target.value)}
          />
        </Field>
        {editError ? <InlineAlert tone="danger">{editError}</InlineAlert> : null}
      </Dialog>

      <ReasonDialog
        open={archiveTarget !== null}
        onClose={() => setArchiveTarget(null)}
        onConfirm={(reason) => {
          if (archiveTarget) archiveDepartment.mutate(reason)
        }}
        title={`归档部门「${archiveTarget?.name ?? ''}」`}
        description="归档部门会保留历史数据，但不再用于新的成员分配。"
        confirmLabel="归档部门"
        tone="danger"
        busy={archiveDepartment.isPending}
        hint="归档原因会写入审计日志，至少 2 个字符。"
      />
    </div>
  )
}
