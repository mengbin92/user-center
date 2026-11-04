import { ArrowLeft, Building2, Users } from 'lucide-react'
import { Link, useParams, useSearchParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import {
  Card,
  CardContent,
  CardHeader,
  InlineAlert,
  PageHeader,
} from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { Tabs } from '../../components/tabs'
import { formatDateTime, formatNumber } from '../../lib/format'
import type { Organization } from '../../lib/types'
import { OrganizationAuditsTab } from './audits-tab'
import { OrganizationDepartmentsTab } from './departments-tab'
import { OrganizationIAMTab } from './iam-tab'
import { OrganizationMembersTab } from './members-tab'
import { OrganizationSettingsTab } from './settings-tab'
import {
  ArchiveOrganizationButton,
  OrganizationInfoGrid,
  OrganizationRoleBadge,
  OrganizationStatusBadge,
  useOrganization,
} from './org-shared'

const TAB_KEYS = [
  'overview',
  'members',
  'departments',
  'roles',
  'audits',
  'settings',
] as const
type TabKey = (typeof TAB_KEYS)[number]

function readTab(raw: string | null): TabKey {
  if (raw && (TAB_KEYS as readonly string[]).includes(raw)) {
    return raw as TabKey
  }
  return 'overview'
}

export function OrganizationDetailPage() {
  const { orgId = '' } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = readTab(searchParams.get('tab'))
  const orgQuery = useOrganization(orgId)
  const org = orgQuery.data

  const setTab = (key: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', key)
    setSearchParams(next, { replace: true })
  }

  return (
    <div className="space-y-4">
      <PageTitle title={org?.name || '组织详情'} />

      <div>
        <Link
          to="/orgs"
          className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 hover:text-slate-800"
        >
          <ArrowLeft className="h-3 w-3" />
          返回组织列表
        </Link>
      </div>

      <QueryBoundary query={orgQuery} loadingLabel="读取组织信息…">
        {org ? (
          <>
            <PageHeader
              eyebrow="Organization"
              title={
                <span className="inline-flex items-center gap-2">
                  <span className="grid h-8 w-8 place-items-center rounded-lg bg-indigo-50 text-indigo-600">
                    <Building2 className="h-4 w-4" />
                  </span>
                  {org.name || org.code}
                </span>
              }
              description={
                <span className="inline-flex flex-wrap items-center gap-1.5">
                  <span className="font-mono">{org.code}</span>
                  <span>·</span>
                  <OrganizationStatusBadge status={org.status} />
                  <OrganizationRoleBadge role={org.role} />
                  <span className="text-slate-400">revision {org.revision}</span>
                </span>
              }
            />

            <Tabs
              tabs={[
                { key: 'overview', label: '概览' },
                {
                  key: 'members',
                  label: '成员',
                  count: Number(org.member_count ?? 0),
                },
                { key: 'departments', label: '部门' },
                { key: 'roles', label: '角色与授权' },
                { key: 'audits', label: '审计' },
                { key: 'settings', label: '设置' },
              ]}
              value={tab}
              onChange={setTab}
            />

            {tab === 'overview' ? (
              <OrganizationOverviewTab org={org} />
            ) : null}
            {tab === 'members' ? (
              <OrganizationMembersTab org={org} orgId={orgId} />
            ) : null}
            {tab === 'departments' ? (
              <OrganizationDepartmentsTab org={org} orgId={orgId} />
            ) : null}
            {tab === 'roles' ? (
              <OrganizationIAMTab org={org} orgId={orgId} />
            ) : null}
            {tab === 'audits' ? (
              <OrganizationAuditsTab
                orgId={orgId}
                active={org.status === 'active'}
              />
            ) : null}
            {tab === 'settings' ? (
              <OrganizationSettingsTab org={org} orgId={orgId} />
            ) : null}
          </>
        ) : null}
      </QueryBoundary>
    </div>
  )
}

function OrganizationOverviewTab({ org }: { org: Organization }) {
  const archived = org.status === 'archived'

  return (
    <div className="space-y-4">
      {archived ? (
        <InlineAlert tone="warning" title="组织已归档">
          该组织已归档，成员与部门变更已冻结；仅平台管理员可继续处理。
        </InlineAlert>
      ) : null}

      <Card>
        <CardHeader
          title="组织概览"
          description="组织状态、角色与并发控制版本。"
          actions={<ArchiveOrganizationButton org={org} />}
        />
        <CardContent>
          <OrganizationInfoGrid
            items={[
              { label: '组织名称', value: org.name || '—' },
              { label: '组织 code', value: org.code || '—', mono: true },
              {
                label: '状态',
                value: <OrganizationStatusBadge status={org.status} />,
              },
              {
                label: '我的组织角色',
                value: <OrganizationRoleBadge role={org.role} />,
              },
              {
                label: '成员数',
                value: (
                  <span className="inline-flex items-center gap-1">
                    <Users className="h-3 w-3 text-slate-400" />
                    {formatNumber(org.member_count)}
                  </span>
                ),
              },
              { label: 'revision', value: org.revision ?? '—', mono: true },
              { label: '组织 ID', value: org.id ?? '—', mono: true },
              { label: '创建时间', value: formatDateTime(org.created_at) },
              { label: '更新时间', value: formatDateTime(org.updated_at) },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  )
}
