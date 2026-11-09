import { Save, ShieldAlert } from 'lucide-react'
import { useEffect, useState } from 'react'

import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
} from '../../components/card'
import { Field, Input } from '../../components/input'
import { api } from '../../lib/api'
import { useApiMutation } from '../../lib/mutations'
import type { Organization } from '../../lib/types'
import {
  canArchiveOrganization,
  isOrganizationManager,
  organizationIsActive,
  organizationRoleLabel,
} from './org-utils'
import {
  ArchiveOrganizationButton,
  OrganizationRoleBadge,
} from './org-shared'
import { OrganizationSCIMTokens } from './scim-tokens'

export function OrganizationSettingsTab({
  org,
  orgId,
}: {
  org: Organization
  orgId: string
}) {
  const active = organizationIsActive(org)
  const canRename = active && isOrganizationManager(org.role)
  const canArchive = active && canArchiveOrganization(org.role)

  const [name, setName] = useState(org.name ?? '')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setName(org.name ?? '')
  }, [org.id, org.name, org.revision])

  const rename = useApiMutation({
    mutationFn: () =>
      api.orgs.update(orgId, {
        id: orgId,
        name: name.trim(),
        expected_revision: org.revision ?? '0',
        reason: 'rename organization',
      }),
    successMessage: '组织名称已更新',
    invalidate: [
      ['orgs', 'detail', orgId],
      ['orgs', 'mine'],
    ],
    onSuccess: () => setError(null),
    onError: (apiError) => setError(apiError.message),
  })

  const submitRename = () => {
    if (!name.trim()) {
      setError('组织名称不能为空')
      return
    }
    if (name.trim().length > 128) {
      setError('组织名称不能超过 128 个字符')
      return
    }
    setError(null)
    rename.mutate(undefined)
  }

  return (
    <div className="space-y-4">
      {!active ? (
        <InlineAlert tone="warning" title="组织已归档">
          归档组织不能再重命名或再次归档，仅可查看历史信息。
        </InlineAlert>
      ) : null}

      <Card>
        <CardHeader
          title="基本信息"
          description="重命名需要携带当前 revision；并发修改会返回 409 冲突。"
          actions={<OrganizationRoleBadge role={org.role} />}
        />
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label="组织名称"
              htmlFor="org-settings-name"
              hint={`当前 revision：${org.revision ?? '—'}`}
            >
              <Input
                id="org-settings-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={!canRename || rename.isPending}
              />
            </Field>
            <Field label="组织 code" htmlFor="org-settings-code" hint="code 创建后不可修改。">
              <Input
                id="org-settings-code"
                value={org.code ?? ''}
                readOnly
                disabled
              />
            </Field>
          </div>
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
          {canRename ? (
            <div className="flex justify-end">
              <Button
                size="sm"
                variant="primary"
                onClick={submitRename}
                loading={rename.isPending}
                disabled={!name.trim() || name.trim() === (org.name ?? '')}
                icon={<Save className="h-3.5 w-3.5" />}
              >
                保存名称
              </Button>
            </div>
          ) : (
            <p className="text-[11px] text-slate-500">
              当前组织角色为「{organizationRoleLabel(org.role)}」，仅组织管理员或拥有者可以重命名。
            </p>
          )}
        </CardContent>
      </Card>

      <OrganizationSCIMTokens orgId={orgId} />

      <Card>
        <CardHeader
          title="危险操作"
          description="归档会冻结组织及其成员、部门变更，操作不可在界面撤销。"
        />
        <CardContent className="space-y-3">
          <InlineAlert tone="danger" title="归档组织" icon={ShieldAlert}>
            归档后组织不再对成员开放，成员与部门变更会被冻结。该操作需要提供原因，并写入审计日志。
          </InlineAlert>
          {canArchive ? (
            <ArchiveOrganizationButton org={org} label="归档当前组织" />
          ) : (
            <p className="text-[11px] text-slate-500">
              只有组织拥有者或平台管理员可以归档组织。
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
