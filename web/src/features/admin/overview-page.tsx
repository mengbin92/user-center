import {
  Activity,
  Archive,
  ArrowRight,
  ClipboardList,
  Download,
  KeyRound,
  LogIn,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Users,
  UserX,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Badge, StatusBadge } from '../../components/badge'
import { Button } from '../../components/button'
import {
  Card,
  CardContent,
  CardHeader,
  EmptyState,
  PageHeader,
  StatCard,
} from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { api } from '../../lib/api'
import { useAuth } from '../../lib/auth'
import { formatDateTime, formatNumber } from '../../lib/format'

export function AdminOverviewPage() {
  const { can } = useAuth()

  const overviewQuery = useQuery({
    queryKey: ['admin', 'overview'],
    queryFn: () => api.admin.overview(),
    retry: false,
  })

  const auditsQuery = useQuery({
    queryKey: ['admin', 'audits', 'overview'],
    queryFn: () => api.audits.list({ page_size: 6 }),
    enabled: can('audit.read'),
    retry: false,
  })

  const overview = overviewQuery.data ?? {}

  return (
    <div className="space-y-4">
      <PageTitle title="控制台" />
      <PageHeader
        eyebrow="Admin Console"
        title="控制台"
        description="账号、会话与权限治理概览。数据按当前账号的数据范围统计。"
        actions={
          <>
            {can('identity.user.list') ? (
              <Link to="/admin/users">
                <Button size="sm" variant="primary" icon={<Users className="h-3.5 w-3.5" />}>
                  用户管理
                </Button>
              </Link>
            ) : null}
            {can('audit.read') ? (
              <Link to="/admin/audits">
                <Button size="sm" variant="secondary" icon={<ClipboardList className="h-3.5 w-3.5" />}>
                  查看审计
                </Button>
              </Link>
            ) : null}
          </>
        }
      />

      <QueryBoundary query={overviewQuery} loadingLabel="统计概览加载中…">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="用户总数"
            value={formatNumber(overview.total_users)}
            hint="包含全部状态"
            icon={Users}
          />
          <StatCard
            label="已启用"
            value={formatNumber(overview.enabled_users)}
            hint="可正常登录"
            icon={UserCheck}
            tone="emerald"
          />
          <StatCard
            label="已禁用"
            value={formatNumber(overview.disabled_users)}
            hint="登录被阻止"
            icon={UserX}
            tone="amber"
          />
          <StatCard
            label="已归档"
            value={formatNumber(overview.archived_users)}
            hint="保留历史与审计"
            icon={Archive}
            tone="slate"
          />
          <StatCard
            label="启用 MFA"
            value={formatNumber(overview.mfa_users)}
            hint="第二因素已绑定"
            icon={ShieldCheck}
            tone="violet"
          />
          <StatCard
            label="活跃会话"
            value={formatNumber(overview.active_sessions)}
            hint="未过期且未撤销"
            icon={Activity}
            tone="indigo"
          />
          <StatCard
            label="24h 登录"
            value={formatNumber(overview.logins_24h)}
            hint="成功登录事件"
            icon={LogIn}
            tone="emerald"
          />
          <StatCard
            label="24h 失败登录"
            value={formatNumber(overview.failed_logins_24h)}
            hint="需关注异常尝试"
            icon={ShieldAlert}
            tone="rose"
          />
        </div>
      </QueryBoundary>

      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <Card>
          <CardHeader
            title="最近审计事件"
            description="授权、账号与安全相关的关键变更。"
            actions={
              can('audit.read') ? (
                <Link
                  to="/admin/audits"
                  className="inline-flex items-center gap-1 text-[11px] font-medium text-indigo-700 hover:underline"
                >
                  全部审计 <ArrowRight className="h-3 w-3" />
                </Link>
              ) : (
                <Badge tone="neutral">无 audit.read 权限</Badge>
              )
            }
          />
          {!can('audit.read') ? (
            <EmptyState
              title="没有查看审计的权限"
              description="需要 audit.read 操作权限。"
              icon={ShieldAlert}
            />
          ) : (
            <QueryBoundary query={auditsQuery} loadingLabel="读取审计…" className="border-0 shadow-none">
              {auditsQuery.data?.items?.length ? (
                <ul className="divide-y divide-slate-100">
                  {auditsQuery.data.items.map((event) => (
                    <li
                      key={event.id}
                      className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 hover:bg-slate-50/70"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[11px] font-medium text-slate-800">
                            {event.action}
                          </span>
                          <StatusBadge status={event.result} />
                        </div>
                        <div className="mt-0.5 truncate text-[10px] text-slate-500">
                          actor {event.actor_user_id || 'service'} · target{' '}
                          {event.target || '—'} · {event.reason || '无原因'}
                        </div>
                      </div>
                      <span className="whitespace-nowrap text-[10px] text-slate-400">
                        {formatDateTime(event.occurred_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  title="暂无审计事件"
                  description="当前数据范围内还没有记录。"
                  icon={ClipboardList}
                />
              )}
            </QueryBoundary>
          )}
        </Card>

        <Card>
          <CardHeader title="快速入口" description="按当前权限显示可用的治理功能。" />
          <CardContent className="grid gap-2">
            {[
              {
                to: '/admin/users',
                label: '用户与账号',
                desc: '搜索、创建、禁用与归档',
                icon: Users,
                permission: 'identity.user.list',
              },
              {
                to: '/admin/iam/roles',
                label: '角色与授权',
                desc: '编辑 grants、继承与成员',
                icon: ShieldCheck,
                permission: 'iam.role.read',
              },
              {
                to: '/admin/iam/assignments',
                label: '批量分配',
                desc: '预览后为用户分配角色',
                icon: KeyRound,
                permission: 'iam.assignment.read',
              },
              {
                to: '/admin/exports',
                label: '导出任务',
                desc: '下载 CSV 产物',
                icon: Download,
                permission: 'identity.user.export',
              },
            ]
              .filter((item) => can(item.permission))
              .map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 px-3 py-2.5 transition-colors hover:border-indigo-200 hover:bg-indigo-50/40"
                >
                  <span className="flex items-center gap-2.5">
                    <span className="grid h-8 w-8 place-items-center rounded-md bg-slate-100 text-slate-600">
                      <item.icon className="h-4 w-4" />
                    </span>
                    <span>
                      <span className="block text-xs font-medium text-slate-800">
                        {item.label}
                      </span>
                      <span className="block text-[10px] text-slate-500">
                        {item.desc}
                      </span>
                    </span>
                  </span>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-400" />
                </Link>
              ))}
            {!can('identity.user.list') &&
            !can('iam.role.read') &&
            !can('iam.assignment.read') &&
            !can('identity.user.export') ? (
              <p className="py-4 text-center text-xs text-slate-500">
                没有可用的管理入口。
              </p>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
