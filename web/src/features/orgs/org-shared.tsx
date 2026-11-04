import { Archive } from 'lucide-react'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router'

import { Badge, StatusBadge } from '../../components/badge'
import type { BadgeTone } from '../../components/badge'
import { Button } from '../../components/button'
import { ReasonDialog } from '../../components/reason-dialog'
import { api } from '../../lib/api'
import { useApiMutation } from '../../lib/mutations'
import type { Organization } from '../../lib/types'
import {
  canArchiveOrganization,
  organizationIsActive,
  organizationRoleLabel,
  organizationStatusLabel,
} from './org-utils'

export function useMyOrganizations() {
  return useQuery({
    queryKey: ['orgs', 'mine'],
    queryFn: () => api.orgs.listMine(),
    retry: false,
  })
}

export function useOrganization(id: string) {
  return useQuery({
    queryKey: ['orgs', 'detail', id],
    queryFn: () => api.orgs.get(id),
    retry: false,
    enabled: Boolean(id),
  })
}

const roleTones: Record<string, BadgeTone> = {
  owner: 'violet',
  admin: 'info',
  member: 'neutral',
  platform: 'warning',
}

export function OrganizationRoleBadge({ role }: { role?: string | null }) {
  return (
    <Badge tone={roleTones[role ?? ''] ?? 'neutral'}>
      {organizationRoleLabel(role)}
    </Badge>
  )
}

export function OrganizationStatusBadge({ status }: { status?: string | null }) {
  return <StatusBadge status={status} label={organizationStatusLabel(status)} />
}

export function OrganizationInfoGrid({
  items,
  className,
}: {
  items: Array<{ label: string; value: ReactNode; mono?: boolean }>
  className?: string
}) {
  return (
    <dl
      className={
        className ??
        'grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3'
      }
    >
      {items.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-[11px] text-slate-500">{item.label}</dt>
          <dd
            className={
              item.mono
                ? 'mt-0.5 truncate font-mono text-xs text-slate-800'
                : 'mt-0.5 truncate text-xs font-medium text-slate-800'
            }
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

/**
 * Archive is an owner/platform action. Hidden for admins and members; the
 * server re-checks authorization on every call.
 */
export function ArchiveOrganizationButton({
  org,
  label = '归档组织',
  variant = 'danger',
}: {
  org: Organization
  label?: string
  variant?: 'danger' | 'secondary'
}) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const orgId = org.id ?? ''
  const archive = useApiMutation({
    mutationFn: (reason: string) =>
      api.orgs.archive(orgId, {
        id: orgId,
        expected_revision: org.revision ?? '0',
        reason,
      }),
    successMessage: '组织已归档',
    successDescription: '组织、成员与部门变更已冻结。',
    invalidate: [
      ['orgs', 'mine'],
      ['admin', 'organizations'],
    ],
    onSuccess: () => {
      setOpen(false)
      // Archived organizations are no longer readable through GET /orgs/{id};
      // return to the list instead of refetching a resource that now 404s.
      navigate('/orgs')
    },
  })

  if (!orgId || !organizationIsActive(org) || !canArchiveOrganization(org.role)) {
    return null
  }

  return (
    <>
      <Button
        size="sm"
        variant={variant}
        onClick={() => setOpen(true)}
        icon={<Archive className="h-3.5 w-3.5" />}
      >
        {label}
      </Button>
      <ReasonDialog
        open={open}
        onClose={() => setOpen(false)}
        onConfirm={(reason) => archive.mutate(reason)}
        title={`归档组织「${org.name || org.code || orgId}」`}
        description="归档后该组织不再对成员开放，成员与部门变更将被冻结。此操作会写入审计日志。"
        confirmLabel="确认归档"
        tone="danger"
        busy={archive.isPending}
        hint="归档原因会写入不可篡改的审计日志，至少 2 个字符。"
      />
    </>
  )
}
