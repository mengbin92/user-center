import { CheckCircle2, MailCheck } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'

import { PageTitle } from '../../app/guards'
import { Button } from '../../components/button'
import { Card, CardContent, CardHeader, InlineAlert } from '../../components/card'
import { api } from '../../lib/api'

export function AcceptInvitationPage() {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')

  async function accept() {
    if (!token || busy) return
    setBusy(true)
    setError('')
    try {
      await api.orgs.acceptInvitation({ token })
      setDone(true)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '接受邀请失败，请确认已登录正确账号')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-start justify-center bg-slate-100 px-4 py-12">
      <div className="w-full max-w-lg space-y-4">
        <PageTitle title="接受组织邀请" />
        <Card>
          <CardHeader
            title="加入组织"
            description="请使用与收件邮箱一致的账号登录后再接受邀请。"
          />
          <CardContent className="space-y-4">
            {!token ? (
              <InlineAlert tone="warning">
                邀请链接缺少令牌。请从邀请邮件中复制完整链接后重试；未注册账号请先注册。
              </InlineAlert>
            ) : done ? (
              <div className="space-y-3 text-center">
                <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-600" />
                <p className="text-sm font-medium text-slate-800">已加入组织</p>
                <p className="text-xs text-slate-500">成员角色与内置授权已同步。</p>
                <Link to="/orgs">
                  <Button variant="primary">前往我的组织</Button>
                </Link>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <MailCheck className="h-4 w-4 text-indigo-600" />
                  请确认当前登录账号的邮箱与邀请邮件收件地址一致。
                </div>
                {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
                <div className="flex justify-end">
                  <Button variant="primary" loading={busy} onClick={() => void accept()}>
                    接受邀请
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
