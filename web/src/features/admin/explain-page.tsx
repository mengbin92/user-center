import {
  ArrowRight,
  GitBranch,
  Play,
  RefreshCw,
  SearchCheck,
} from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  EmptyState,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { Field, Input, Select } from '../../components/input'
import { Tabs } from '../../components/tabs'
import {
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
} from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime, formatScope } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'
import type {
  ExplainAuthorizationReply,
  SimulateAuthorizationReply,
} from '../../lib/types'
import {
  PermissionSelectOptions,
  useAllRoles,
  usePermissionCatalog,
} from './common'

export function AdminExplainPage() {
  const [tab, setTab] = useState('explain')
  const rolesQuery = useAllRoles()
  const catalogQuery = usePermissionCatalog()

  const [userId, setUserId] = useState('')
  const [operation, setOperation] = useState('')
  const [resourceId, setResourceId] = useState('')
  const [ownerUserId, setOwnerUserId] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [explainResult, setExplainResult] =
    useState<ExplainAuthorizationReply | null>(null)
  const [simulateResult, setSimulateResult] =
    useState<SimulateAuthorizationReply | null>(null)

  const [simUserId, setSimUserId] = useState('')
  const [simOperation, setSimOperation] = useState('')
  const [simOwnerUserId, setSimOwnerUserId] = useState('')
  const [addRoles, setAddRoles] = useState<Set<string>>(new Set())
  const [removeRoles, setRemoveRoles] = useState<Set<string>>(new Set())
  const [simError, setSimError] = useState<string | null>(null)

  const explain = useApiMutation({
    mutationFn: () =>
      api.iam.explain({
        user_id: userId.trim(),
        operation: operation.trim(),
        resource_id: resourceId.trim() || undefined,
        owner_user_id: ownerUserId.trim() || undefined,
      }),
    onSuccess: (data) => {
      setExplainResult(data)
      setFormError(null)
    },
  })

  const simulate = useApiMutation({
    mutationFn: () =>
      api.iam.simulate({
        user_id: simUserId.trim(),
        operation: simOperation.trim(),
        owner_user_id: simOwnerUserId.trim() || undefined,
        add_role_ids: [...addRoles],
        remove_role_ids: [...removeRoles],
      }),
    onSuccess: (data) => {
      setSimulateResult(data)
      setSimError(null)
    },
  })

  const runExplain = () => {
    if (!userId.trim() || !operation.trim()) {
      setFormError('用户 ID 与操作权限不能为空')
      return
    }
    explain.mutate(undefined)
  }

  const runSimulate = () => {
    if (!simUserId.trim() || !simOperation.trim()) {
      setSimError('用户 ID 与操作权限不能为空')
      return
    }
    simulate.mutate(undefined)
  }

  const toggleRole = (
    roleId: string,
    target: 'add' | 'remove',
  ) => {
    const setter = target === 'add' ? setAddRoles : setRemoveRoles
    setter((current) => {
      const next = new Set(current)
      if (next.has(roleId)) next.delete(roleId)
      else next.add(roleId)
      return next
    })
  }

  const roles = rolesQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="授权诊断" />
      <PageHeader
        eyebrow="IAM"
        title="授权诊断"
        description="解释某一操作的授权来源，或模拟角色增减后的权限差异。结果不授予任何权限。"
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => void rolesQuery.refetch()}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            刷新角色
          </Button>
        }
      />

      {rolesQuery.isError || catalogQuery.isError ? (
        <InlineAlert tone="warning" title="部分目录不可用">
          {rolesQuery.isError ? '角色列表加载失败，可能缺少 iam.role.read 权限。' : ''}
          {catalogQuery.isError
            ? ' 权限目录加载失败，可能缺少 iam.permission.read 权限。'
            : ''}
        </InlineAlert>
      ) : null}

      <Card>
        <div className="px-3 pt-2">
          <Tabs
            tabs={[
              { key: 'explain', label: '解释授权' },
              { key: 'simulate', label: '模拟变更' },
            ]}
            value={tab}
            onChange={setTab}
          />
        </div>

        {tab === 'explain' ? (
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="用户 ID" htmlFor="explain-user" required>
                <Input
                  id="explain-user"
                  value={userId}
                  onChange={(event) => setUserId(event.target.value)}
                  placeholder="十进制 ID"
                  inputMode="numeric"
                  className="font-mono"
                />
              </Field>
              <Field label="操作权限" htmlFor="explain-op" required>
                <Select
                  id="explain-op"
                  value={operation}
                  onChange={(event) => setOperation(event.target.value)}
                >
                  <option value="">选择操作权限</option>
                  <PermissionSelectOptions permissions={catalogQuery.data?.items} />
                </Select>
              </Field>
              <Field label="资源 ID" htmlFor="explain-resource" hint="可选">
                <Input
                  id="explain-resource"
                  value={resourceId}
                  onChange={(event) => setResourceId(event.target.value)}
                  className="font-mono"
                />
              </Field>
              <Field label="所有者用户 ID" htmlFor="explain-owner" hint="可选">
                <Input
                  id="explain-owner"
                  value={ownerUserId}
                  onChange={(event) => setOwnerUserId(event.target.value)}
                  className="font-mono"
                />
              </Field>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={runExplain}
                loading={explain.isPending}
                icon={<SearchCheck className="h-3.5 w-3.5" />}
              >
                解释授权
              </Button>
              <Link
                to="/admin/users"
                className="text-[11px] text-slate-500 hover:text-slate-800"
              >
                不确定用户 ID？在用户管理中查找
              </Link>
            </div>
            {formError ? (
              <InlineAlert tone="danger">{formError}</InlineAlert>
            ) : null}

            {explainResult ? (
              <div className="space-y-3">
                <div
                  className={
                    explainResult.allowed
                      ? 'flex flex-wrap items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3'
                      : 'flex flex-wrap items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 p-3'
                  }
                >
                  <Badge tone={explainResult.allowed ? 'success' : 'danger'} dot>
                    {explainResult.allowed ? '允许' : '拒绝'}
                  </Badge>
                  <span
                    className={
                      explainResult.allowed
                        ? 'text-xs text-emerald-800'
                        : 'text-xs text-rose-800'
                    }
                  >
                    {explainResult.reason || '无补充说明'}
                  </span>
                  <span className="ml-auto text-[10px] text-slate-500">
                    policy {explainResult.policy_revision ?? '—'} · user{' '}
                    {explainResult.user_revision ?? '—'}
                    {explainResult.valid_until
                      ? ` · 有效至 ${formatDateTime(explainResult.valid_until)}`
                      : ''}
                  </span>
                </div>

                <div>
                  <div className="mb-1.5 text-xs font-semibold text-slate-700">
                    授权来源
                  </div>
                  {explainResult.sources?.length ? (
                    <Table minWidth="min-w-[820px]">
                      <THead>
                        <TR>
                          <TH>角色</TH>
                          <TH>操作</TH>
                          <TH>效果</TH>
                          <TH>范围</TH>
                          <TH>继承路径</TH>
                          <TH>状态</TH>
                          <TH>过期</TH>
                        </TR>
                      </THead>
                      <TBody>
                        {explainResult.sources.map((source, index) => (
                          <TR
                            key={`${source.role_id}-${source.operation}-${index}`}
                          >
                            <TD>
                              <div className="text-xs text-slate-800">
                                {source.role_code || source.role_id}
                              </div>
                              <div className="font-mono text-[10px] text-slate-400">
                                {source.assignment_id}
                              </div>
                            </TD>
                            <TD className="font-mono text-[11px] text-slate-700">
                              {source.operation}
                            </TD>
                            <TD>
                              <Badge
                                tone={source.effect === 'allow' ? 'success' : 'danger'}
                              >
                                {source.effect === 'allow' ? '允许' : '拒绝'}
                              </Badge>
                            </TD>
                            <TD className="text-[11px] text-slate-600">
                              {formatScope(source.scope)}
                            </TD>
                            <TD>
                              <div className="flex flex-wrap items-center gap-1">
                                {(source.inheritance_path ?? []).length ? (
                                  source.inheritance_path?.map((path, pathIndex) => (
                                    <span
                                      key={`${path}-${pathIndex}`}
                                      className="flex items-center gap-1 font-mono text-[10px] text-slate-500"
                                    >
                                      {pathIndex > 0 ? (
                                        <ArrowRight className="h-2.5 w-2.5" />
                                      ) : null}
                                      {path}
                                    </span>
                                  ))
                                ) : (
                                  <span className="text-[10px] text-slate-400">
                                    直接
                                  </span>
                                )}
                              </div>
                            </TD>
                            <TD>
                              {source.active ? (
                                <Badge tone="success">生效</Badge>
                              ) : (
                                <Badge tone="neutral">未生效</Badge>
                              )}
                            </TD>
                            <TD className="text-[10px] text-slate-500">
                              {source.expires_at
                                ? formatDateTime(source.expires_at)
                                : '永久'}
                            </TD>
                          </TR>
                        ))}
                      </TBody>
                    </Table>
                  ) : (
                    <EmptyState title="没有匹配的授权来源" />
                  )}
                </div>
              </div>
            ) : (
              <EmptyState
                title="尚未解释"
                description="输入用户与操作权限，查看 allow/deny 的完整来源链。"
                icon={GitBranch}
              />
            )}
          </CardContent>
        ) : null}

        {tab === 'simulate' ? (
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="用户 ID" htmlFor="sim-user" required>
                <Input
                  id="sim-user"
                  value={simUserId}
                  onChange={(event) => setSimUserId(event.target.value)}
                  className="font-mono"
                  inputMode="numeric"
                />
              </Field>
              <Field label="操作权限" htmlFor="sim-op" required>
                <Select
                  id="sim-op"
                  value={simOperation}
                  onChange={(event) => setSimOperation(event.target.value)}
                >
                  <option value="">选择操作权限</option>
                  <PermissionSelectOptions permissions={catalogQuery.data?.items} />
                </Select>
              </Field>
              <Field label="所有者用户 ID" htmlFor="sim-owner" hint="可选">
                <Input
                  id="sim-owner"
                  value={simOwnerUserId}
                  onChange={(event) => setSimOwnerUserId(event.target.value)}
                  className="font-mono"
                />
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <div className="mb-1 text-xs font-medium text-emerald-700">
                  新增角色
                </div>
                <div className="grid max-h-40 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2">
                  {roles.map((role) => (
                    <label
                      key={role.id}
                      className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
                    >
                      <input
                        type="checkbox"
                        className="h-3.5 w-3.5 rounded border-slate-300 accent-emerald-600"
                        checked={addRoles.has(role.id ?? '')}
                        onChange={() => toggleRole(role.id ?? '', 'add')}
                      />
                      <span className="truncate text-slate-700">{role.name}</span>
                      <span className="font-mono text-[10px] text-slate-400">
                        {role.code}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div className="mb-1 text-xs font-medium text-rose-700">
                  移除角色
                </div>
                <div className="grid max-h-40 gap-1 overflow-y-auto rounded-md border border-slate-200 p-2">
                  {roles.map((role) => (
                    <label
                      key={role.id}
                      className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-slate-50"
                    >
                      <input
                        type="checkbox"
                        className="h-3.5 w-3.5 rounded border-slate-300 accent-rose-600"
                        checked={removeRoles.has(role.id ?? '')}
                        onChange={() => toggleRole(role.id ?? '', 'remove')}
                      />
                      <span className="truncate text-slate-700">{role.name}</span>
                      <span className="font-mono text-[10px] text-slate-400">
                        {role.code}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={runSimulate}
                loading={simulate.isPending}
                icon={<Play className="h-3.5 w-3.5" />}
              >
                运行模拟
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setAddRoles(new Set())
                  setRemoveRoles(new Set())
                  setSimulateResult(null)
                }}
              >
                重置
              </Button>
            </div>
            {simError ? (
              <InlineAlert tone="danger">{simError}</InlineAlert>
            ) : null}

            {simulateResult ? (
              <div className="space-y-3">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="text-[11px] text-slate-500">变更前</div>
                    <div className="mt-1">
                      <Badge
                        tone={
                          simulateResult.before_allowed ? 'success' : 'danger'
                        }
                        dot
                      >
                        {simulateResult.before_allowed ? '允许' : '拒绝'}
                      </Badge>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-600">
                      {simulateResult.before_reason || '—'}
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 p-3">
                    <div className="text-[11px] text-slate-500">变更后</div>
                    <div className="mt-1">
                      <Badge
                        tone={simulateResult.after_allowed ? 'success' : 'danger'}
                        dot
                      >
                        {simulateResult.after_allowed ? '允许' : '拒绝'}
                      </Badge>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-600">
                      {simulateResult.after_reason || '—'}
                    </p>
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <div className="mb-1 text-[11px] font-medium text-emerald-700">
                      新增权限
                    </div>
                    <div className="flex flex-wrap gap-1 rounded-md border border-slate-200 p-2">
                      {simulateResult.added_permissions?.length ? (
                        simulateResult.added_permissions.map((code) => (
                          <Badge key={code} tone="success">
                            {code}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-[11px] text-slate-400">无</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="mb-1 text-[11px] font-medium text-rose-700">
                      移除权限
                    </div>
                    <div className="flex flex-wrap gap-1 rounded-md border border-slate-200 p-2">
                      {simulateResult.removed_permissions?.length ? (
                        simulateResult.removed_permissions.map((code) => (
                          <Badge key={code} tone="danger">
                            {code}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-[11px] text-slate-400">无</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <EmptyState
                title="尚未模拟"
                description="选择角色增减后运行模拟，查看权限差异。"
                icon={GitBranch}
              />
            )}
          </CardContent>
        ) : null}
      </Card>
    </div>
  )
}
