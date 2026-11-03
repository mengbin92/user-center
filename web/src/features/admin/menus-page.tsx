import {
  Archive,
  Menu as MenuIcon,
  Pencil,
  Plus,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Dialog } from '../../components/dialog'
import { Field, Input, Select, Switch, Textarea } from '../../components/input'
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
import { splitList } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type { MenuItem } from '../../lib/types'

type MenuForm = {
  parentId: string
  routeKey: string
  name: string
  iconKey: string
  sort: string
  enabled: boolean
  requiredAll: string
  requiredAny: string
  reason: string
}

const EMPTY_FORM: MenuForm = {
  parentId: '0',
  routeKey: '',
  name: '',
  iconKey: '',
  sort: '0',
  enabled: true,
  requiredAll: '',
  requiredAny: '',
  reason: '',
}

export function AdminMenusPage() {
  const { can, authorization } = useAuth()
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState<MenuForm>(EMPTY_FORM)
  const [editTarget, setEditTarget] = useState<MenuItem | null>(null)
  const [editForm, setEditForm] = useState<MenuForm>(EMPTY_FORM)
  const [formError, setFormError] = useState<string | null>(null)
  const [archiveTarget, setArchiveTarget] = useState<MenuItem | null>(null)

  const menusQuery = useQuery({
    queryKey: ['admin', 'iam', 'menus'],
    queryFn: () => api.iam.listMenus(),
    retry: false,
  })

  const createMenu = useApiMutation({
    mutationFn: () =>
      api.iam.createMenuItem({
        parent_id: form.parentId === '0' ? undefined : form.parentId,
        route_key: form.routeKey.trim(),
        name: form.name.trim(),
        icon_key: form.iconKey.trim(),
        sort: Number(form.sort) || 0,
        required_all: splitList(form.requiredAll),
        required_any: splitList(form.requiredAny),
        expected_policy_revision: authorization?.policy_revision,
        reason: form.reason.trim(),
      }),
    successMessage: '菜单项已创建',
    invalidate: [['admin', 'iam', 'menus']],
    refreshAuth: true,
    onSuccess: () => {
      setCreateOpen(false)
      setForm(EMPTY_FORM)
    },
  })

  const updateMenu = useApiMutation({
    mutationFn: () => {
      if (!editTarget) throw new Error('未选择菜单')
      return api.iam.updateMenuItem(editTarget.id ?? '', {
        id: editTarget.id,
        name: editForm.name.trim(),
        icon_key: editForm.iconKey.trim(),
        sort: Number(editForm.sort) || 0,
        enabled: editForm.enabled,
        required_all: splitList(editForm.requiredAll),
        required_any: splitList(editForm.requiredAny),
        expected_revision: editTarget.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: editForm.reason.trim(),
      })
    },
    successMessage: '菜单项已更新',
    invalidate: [['admin', 'iam', 'menus']],
    refreshAuth: true,
    onSuccess: () => setEditTarget(null),
  })

  const archiveMenu = useApiMutation({
    mutationFn: (input: { menu: MenuItem; reason: string }) =>
      api.iam.archiveMenuItem(input.menu.id ?? '', {
        id: input.menu.id,
        expected_revision: input.menu.revision ?? '0',
        expected_policy_revision: authorization?.policy_revision,
        reason: input.reason,
      }),
    successMessage: '菜单项已归档',
    invalidate: [['admin', 'iam', 'menus']],
    refreshAuth: true,
    onSuccess: () => setArchiveTarget(null),
  })

  const submitCreate = (event: FormEvent) => {
    event.preventDefault()
    if (!form.routeKey.trim() || !form.name.trim()) {
      setFormError('路由键与名称不能为空')
      return
    }
    if (form.reason.trim().length < 2) {
      setFormError('请填写创建原因')
      return
    }
    setFormError(null)
    createMenu.mutate(undefined)
  }

  const openEdit = (menu: MenuItem) => {
    setEditTarget(menu)
    setEditForm({
      parentId: menu.parent_id ?? '0',
      routeKey: menu.route_key ?? '',
      name: menu.name ?? '',
      iconKey: menu.icon_key ?? '',
      sort: String(menu.sort ?? 0),
      enabled: menu.enabled ?? true,
      requiredAll: (menu.required_all ?? []).join(', '),
      requiredAny: (menu.required_any ?? []).join(', '),
      reason: '',
    })
    setFormError(null)
  }

  const submitEdit = () => {
    if (!editForm.name.trim()) {
      setFormError('名称不能为空')
      return
    }
    setFormError(null)
    updateMenu.mutate(undefined)
  }

  const menus = menusQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="菜单投影" />
      <PageHeader
        eyebrow="IAM"
        title="菜单投影"
        description="菜单项决定 /me/authorization 返回的 menu_keys。访问控制仍以服务端权限为准。"
        actions={
          can('iam.menu.update') ? (
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                setForm(EMPTY_FORM)
                setFormError(null)
                setCreateOpen(true)
              }}
              icon={<Plus className="h-3.5 w-3.5" />}
            >
              新增菜单
            </Button>
          ) : undefined
        }
      />

      <InlineAlert tone="info" title="权限策略 revision">
        修改菜单会刷新权限投影。当前策略 revision：
        <span className="ml-1 font-mono">
          {authorization?.policy_revision ?? '—'}
        </span>
      </InlineAlert>

      <Card>
        <QueryBoundary query={menusQuery} loadingLabel="读取菜单投影…">
          {menus.length === 0 ? (
            <EmptyState
              title="暂无菜单项"
              description="创建菜单项后，满足 required_all / required_any 的用户会看到对应导航。"
              icon={MenuIcon}
            />
          ) : (
            <Table minWidth="min-w-[900px]">
              <THead>
                <TR>
                  <TH>路由键</TH>
                  <TH>名称</TH>
                  <TH>图标</TH>
                  <TH>父级</TH>
                  <TH>排序</TH>
                  <TH>状态</TH>
                  <TH>权限要求</TH>
                  <TH>revision</TH>
                  <TH className="text-right">操作</TH>
                </TR>
              </THead>
              <TBody>
                {menus.map((menu) => {
                  const parent = menus.find((item) => item.id === menu.parent_id)
                  return (
                    <TR key={menu.id}>
                      <TD>
                        <div className="text-xs font-medium text-slate-800">
                          {menu.name}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {menu.route_key} · id={menu.id}
                        </div>
                      </TD>
                      <TD className="text-[11px] text-slate-600">{menu.name}</TD>
                      <TD className="font-mono text-[11px] text-slate-500">
                        {menu.icon_key || '—'}
                      </TD>
                      <TD className="text-[11px] text-slate-500">
                        {parent?.name || menu.parent_id || '—'}
                      </TD>
                      <TD className="tabular-nums text-[11px] text-slate-600">
                        {menu.sort ?? 0}
                      </TD>
                      <TD>
                        {menu.enabled ? (
                          <Badge tone="success" dot>
                            已启用
                          </Badge>
                        ) : (
                          <Badge tone="neutral">已停用</Badge>
                        )}
                      </TD>
                      <TD>
                        <div className="flex max-w-[220px] flex-wrap gap-1">
                          {(menu.required_all ?? []).map((code) => (
                            <Badge key={`all-${code}`} tone="info">
                              all: {code}
                            </Badge>
                          ))}
                          {(menu.required_any ?? []).map((code) => (
                            <Badge key={`any-${code}`} tone="warning">
                              any: {code}
                            </Badge>
                          ))}
                          {!menu.required_all?.length &&
                          !menu.required_any?.length ? (
                            <Badge tone="outline">无</Badge>
                          ) : null}
                        </div>
                      </TD>
                      <TD className="font-mono text-[11px] text-slate-500">
                        {menu.revision}
                      </TD>
                      <TD>
                        <div className="flex justify-end gap-0.5">
                          {can('iam.menu.update') ? (
                            <>
                              <Button
                                size="xs"
                                variant="ghost"
                                onClick={() => openEdit(menu)}
                                icon={<Pencil className="h-3 w-3" />}
                              >
                                编辑
                              </Button>
                              <Button
                                size="xs"
                                variant="ghost"
                                onClick={() => setArchiveTarget(menu)}
                                icon={<Archive className="h-3 w-3" />}
                              >
                                归档
                              </Button>
                            </>
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

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="新增菜单项"
        description="route_key 与前端路由一一对应，创建后不可修改。"
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
              disabled={createMenu.isPending}
            >
              取消
            </Button>
            <Button
              type="submit"
              form="create-menu-form"
              variant="primary"
              size="sm"
              loading={createMenu.isPending}
            >
              创建
            </Button>
          </>
        }
      >
        <form id="create-menu-form" className="space-y-3" onSubmit={submitCreate}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="路由键" htmlFor="menu-route" required hint="例如 admin/iam/roles">
              <Input
                id="menu-route"
                value={form.routeKey}
                onChange={(event) =>
                  setForm({ ...form, routeKey: event.target.value })
                }
                className="font-mono"
              />
            </Field>
            <Field label="名称" htmlFor="menu-name" required>
              <Input
                id="menu-name"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
              />
            </Field>
            <Field label="图标键" htmlFor="menu-icon">
              <Input
                id="menu-icon"
                value={form.iconKey}
                onChange={(event) =>
                  setForm({ ...form, iconKey: event.target.value })
                }
                placeholder="users"
                className="font-mono"
              />
            </Field>
            <Field label="排序" htmlFor="menu-sort">
              <Input
                id="menu-sort"
                value={form.sort}
                onChange={(event) => setForm({ ...form, sort: event.target.value })}
                inputMode="numeric"
              />
            </Field>
            <Field label="父级菜单" htmlFor="menu-parent">
              <Select
                id="menu-parent"
                value={form.parentId}
                onChange={(event) =>
                  setForm({ ...form, parentId: event.target.value })
                }
              >
                <option value="0">无（顶级）</option>
                {menus.map((menu) => (
                  <option key={menu.id} value={menu.id}>
                    {menu.name}（{menu.route_key}）
                  </option>
                ))}
              </Select>
            </Field>
            <div className="flex items-end pb-2">
              <Switch
                checked={form.enabled}
                onCheckedChange={(checked) => setForm({ ...form, enabled: checked })}
                label="启用菜单"
              />
            </div>
          </div>
          <Field
            label="required_all"
            htmlFor="menu-required-all"
            hint="逗号分隔的权限代码；用户必须同时拥有全部权限"
          >
            <Input
              id="menu-required-all"
              value={form.requiredAll}
              onChange={(event) =>
                setForm({ ...form, requiredAll: event.target.value })
              }
              placeholder="identity.user.list, iam.role.read"
              className="font-mono text-[11px]"
            />
          </Field>
          <Field
            label="required_any"
            htmlFor="menu-required-any"
            hint="逗号分隔的权限代码；拥有任一权限即可见"
          >
            <Input
              id="menu-required-any"
              value={form.requiredAny}
              onChange={(event) =>
                setForm({ ...form, requiredAny: event.target.value })
              }
              placeholder="audit.read, audit.export"
              className="font-mono text-[11px]"
            />
          </Field>
          <Field label="操作原因" htmlFor="menu-reason" required>
            <Textarea
              id="menu-reason"
              value={form.reason}
              onChange={(event) => setForm({ ...form, reason: event.target.value })}
              rows={2}
            />
          </Field>
          {formError ? (
            <InlineAlert tone="danger">{formError}</InlineAlert>
          ) : null}
        </form>
      </Dialog>

      <Dialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={`编辑菜单 · ${editTarget?.route_key ?? ''}`}
        description="路由键与父级不可修改；可调整名称、图标、排序、状态与权限要求。"
        size="lg"
        bodyClassName="space-y-3"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
              disabled={updateMenu.isPending}
            >
              取消
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={submitEdit}
              loading={updateMenu.isPending}
              disabled={!editForm.reason.trim()}
            >
              保存
            </Button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="路由键" htmlFor="edit-menu-route">
            <Input
              id="edit-menu-route"
              value={editForm.routeKey}
              disabled
              className="font-mono"
            />
          </Field>
          <Field label="名称" htmlFor="edit-menu-name" required>
            <Input
              id="edit-menu-name"
              value={editForm.name}
              onChange={(event) =>
                setEditForm({ ...editForm, name: event.target.value })
              }
            />
          </Field>
          <Field label="图标键" htmlFor="edit-menu-icon">
            <Input
              id="edit-menu-icon"
              value={editForm.iconKey}
              onChange={(event) =>
                setEditForm({ ...editForm, iconKey: event.target.value })
              }
              className="font-mono"
            />
          </Field>
          <Field label="排序" htmlFor="edit-menu-sort">
            <Input
              id="edit-menu-sort"
              value={editForm.sort}
              onChange={(event) =>
                setEditForm({ ...editForm, sort: event.target.value })
              }
              inputMode="numeric"
            />
          </Field>
          <Field label="父级" htmlFor="edit-menu-parent">
            <Input
              id="edit-menu-parent"
              value={editTarget?.parent_id || '0'}
              disabled
              className="font-mono"
            />
          </Field>
          <div className="flex items-end pb-2">
            <Switch
              checked={editForm.enabled}
              onCheckedChange={(checked) =>
                setEditForm({ ...editForm, enabled: checked })
              }
              label="启用菜单"
            />
          </div>
        </div>
        <Field label="required_all" htmlFor="edit-menu-required-all">
          <Input
            id="edit-menu-required-all"
            value={editForm.requiredAll}
            onChange={(event) =>
              setEditForm({ ...editForm, requiredAll: event.target.value })
            }
            className="font-mono text-[11px]"
          />
        </Field>
        <Field label="required_any" htmlFor="edit-menu-required-any">
          <Input
            id="edit-menu-required-any"
            value={editForm.requiredAny}
            onChange={(event) =>
              setEditForm({ ...editForm, requiredAny: event.target.value })
            }
            className="font-mono text-[11px]"
          />
        </Field>
        <Field label="操作原因" htmlFor="edit-menu-reason">
          <Input
            id="edit-menu-reason"
            value={editForm.reason}
            onChange={(event) =>
              setEditForm({ ...editForm, reason: event.target.value })
            }
            placeholder="请填写本次变更的原因" required
          />
        </Field>
        {formError ? (
          <InlineAlert tone="danger">{formError}</InlineAlert>
        ) : null}
      </Dialog>

      <ReasonDialog
        open={archiveTarget !== null}
        onClose={() => setArchiveTarget(null)}
        onConfirm={(reason) => {
          if (archiveTarget) archiveMenu.mutate({ menu: archiveTarget, reason })
        }}
        title="归档菜单项"
        description="归档后该菜单不再出现在 menu_keys 投影中，可通过审计追溯。"
        confirmLabel="确认归档"
        tone="danger"
        busy={archiveMenu.isPending}
      />
    </div>
  )
}
