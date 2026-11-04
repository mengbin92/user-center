import { RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'

import { PageTitle } from '../../app/guards'
import { Badge } from '../../components/badge'
import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, EmptyState } from '../../components/card'
import { QueryBoundary } from '../../components/query-state'
import { TBody, TD, TH, THead, TR, Table } from '../../components/table'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'
import { useApiMutation } from '../../lib/mutations'

export function ConsentsPage() {
  const consents = useQuery({
    queryKey: ['me', 'oidc-consents'],
    queryFn: () => api.me.oidcConsents(),
    retry: false,
  })
  const revoke = useApiMutation({
    mutationFn: (clientId: string) => api.me.revokeOIDCConsent(clientId),
    successMessage: '授权已撤销',
    successDescription: '该应用下次发起登录时会重新征询你的同意。',
    invalidate: [['me', 'oidc-consents']],
  })
  const items = consents.data?.items ?? []

  return (
    <div className="space-y-4">
      <PageTitle title="应用授权" />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            应用授权
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            此处列出你已同意授权的第三方应用。撤销不会注销会话，但下次登录会重新询问。
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => void consents.refetch()}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </Button>
      </div>

      <Card>
        <CardHeader
          title="已授权应用"
          description="授权范围按应用分别记录；应用请求新的范围时会再次征询。"
        />
        <CardContent className="p-0">
          <QueryBoundary query={consents}>
            {items.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="还没有授权记录"
                description="当第三方应用请求访问你的账号时，授权记录会显示在这里。"
              />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>应用</TH>
                    <TH>已授予范围</TH>
                    <TH>最近更新</TH>
                    <TH className="text-right">操作</TH>
                  </TR>
                </THead>
                <TBody>
                  {items.map((item) => (
                    <TR key={item.client_id}>
                      <TD>
                        <p className="font-medium text-slate-800">
                          {item.client_name || item.client_id}
                        </p>
                        <p className="text-[11px] text-slate-400">
                          {item.client_id}
                        </p>
                      </TD>
                      <TD>
                        <div className="flex flex-wrap gap-1">
                          {(item.scopes ?? []).map((scope) => (
                            <Badge key={scope} tone="info">
                              {scope}
                            </Badge>
                          ))}
                        </div>
                      </TD>
                      <TD className="text-xs text-slate-500">
                        {formatDateTime(item.updated_at)}
                      </TD>
                      <TD className="text-right">
                        <Button
                          size="xs"
                          variant="ghost"
                          loading={revoke.isPending}
                          onClick={() =>
                            void revoke.mutateAsync(item.client_id ?? '')
                          }
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          撤销
                        </Button>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </QueryBoundary>
        </CardContent>
      </Card>
    </div>
  )
}
