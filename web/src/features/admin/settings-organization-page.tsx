import { Building2 } from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
} from '../../components/card'
import { Field, Input } from '../../components/input'
import { QueryBoundary } from '../../components/query-state'
import { ReasonDialog } from '../../components/reason-dialog'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { useApiMutation } from '../../lib/mutations'

export function AdminOrganizationSettingsPage() {
  const { can } = useAuth()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [draft, setDraft] = useState({ quota_enabled: false, max_owned_per_user: 5, count_archived: false })
  const [touched, setTouched] = useState(false)

  const settings = useQuery({
    queryKey: ['admin', 'settings', 'organization'],
    queryFn: () => api.settings.organization(),
    retry: false,
  })

  const current = settings.data
  const values = touched ? draft : {
    quota_enabled: current?.quota_enabled ?? false,
    max_owned_per_user: Number(current?.max_owned_per_user ?? 5),
    count_archived: current?.count_archived ?? false,
  }

  const save = useApiMutation({
    mutationFn: (reason: string) =>
      api.settings.updateOrganization({
        ...values,
        update_mask: 'quota_enabled,max_owned_per_user,count_archived',
        expected_revision: current?.revision ?? '1',
        reason,
      }),
    successMessage: '组织策略已更新',
    invalidate: [['admin', 'settings', 'organization']],
    onSuccess: () => {
      setConfirmOpen(false)
      setTouched(false)
    },
  })

  return (
    <div className="space-y-4">
      <PageTitle title="组织策略" />
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-slate-900">
          组织创建配额
        </h1>
        <p className="mt-0.5 text-xs text-slate-500">
          默认关闭；开启后限制每位用户可拥有的组织数量。平台管理员（root/admin）豁免。
        </p>
      </div>

      <Card>
        <CardHeader
          title="配额设置"
          description={`revision ${current?.revision ?? '—'}`}
        />
        <CardContent className="space-y-3">
          <QueryBoundary query={settings} loadingLabel="读取组织策略…">
            <label className="flex items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                className="h-3.5 w-3.5"
                disabled={!can('settings.organization.update')}
                checked={values.quota_enabled}
                onChange={(event) => {
                  setTouched(true)
                  setDraft({ ...values, quota_enabled: event.target.checked })
                }}
              />
              启用每用户组织数量上限
            </label>
            <div className="w-56">
              <Field label="每用户上限（1-1000）">
                <Input
                  type="number"
                  min={1}
                  max={1000}
                  value={values.max_owned_per_user}
                  disabled={!can('settings.organization.update')}
                  onChange={(event) => {
                    setTouched(true)
                    setDraft({ ...values, max_owned_per_user: Number(event.target.value) })
                  }}
                />
              </Field>
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                className="h-3.5 w-3.5"
                disabled={!can('settings.organization.update')}
                checked={values.count_archived}
                onChange={(event) => {
                  setTouched(true)
                  setDraft({ ...values, count_archived: event.target.checked })
                }}
              />
              统计已归档组织（关闭时归档会释放配额）
            </label>
            {!values.quota_enabled ? (
              <InlineAlert tone="info">
                配额当前关闭，任意正常账号均可创建组织，不会触发计数与拒绝审计。
              </InlineAlert>
            ) : null}
            <div className="flex justify-end">
              <Button
                variant="primary"
                disabled={!can('settings.organization.update') || !touched}
                onClick={() => setConfirmOpen(true)}
              >
                保存策略
              </Button>
            </div>
          </QueryBoundary>
        </CardContent>
      </Card>

      <Card>
        <CardHeader title="行为说明" />
        <CardContent>
          <ul className="list-inside list-disc space-y-1 text-xs text-slate-600">
            <li>超限返回固定错误码 <code>ORGANIZATION_QUOTA_EXCEEDED</code>（HTTP 409）。</li>
            <li>计数在创建事务内完成并对该用户的组织行加锁，并发创建不能突破上限。</li>
            <li>拒绝会写平台审计，包含当前计数与上限。</li>
            <li>
              <Building2 className="mr-1 inline h-3 w-3" />
              平台管理员豁免配额，用于支持与治理操作。
            </li>
          </ul>
        </CardContent>
      </Card>

      <ReasonDialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={(reason) => void save.mutateAsync(reason)}
        title="保存组织策略"
        description="策略变更立即生效，并写入审计。"
        confirmLabel="保存"
        busy={save.isPending}
      />
    </div>
  )
}
