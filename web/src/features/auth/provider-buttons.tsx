import {
  FlaskConical,
  GitBranch,
  Globe,
  KeyRound,
  type LucideIcon,
} from 'lucide-react'

import { cn } from '../../lib/cn'
import {
  providerLabel,
  providerStartPath,
  type OAuthMode,
} from '../../lib/oauth'

const PROVIDER_ICONS: Record<string, LucideIcon> = {
  github: GitBranch,
  google: Globe,
  mock: FlaskConical,
}

export function ProviderButtons({
  providers,
  mode = 'login',
  className,
}: {
  providers: string[]
  mode?: OAuthMode
  className?: string
}) {
  if (providers.length === 0) return null
  return (
    <div className={cn('grid gap-2 sm:grid-cols-2', className)}>
      {providers.map((provider) => {
        const Icon = PROVIDER_ICONS[provider] ?? KeyRound
        return (
          <a
            key={provider}
            data-testid={`provider-${provider}`}
            href={providerStartPath(provider, mode)}
            className="flex items-center justify-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-[11px] font-medium text-slate-700 transition-colors hover:border-indigo-300 hover:bg-indigo-50/50 hover:text-indigo-700"
          >
            <Icon className="h-3.5 w-3.5" />
            {mode === 'verify'
              ? `重新验证 ${providerLabel(provider)}`
              : mode === 'bind'
              ? `绑定 ${providerLabel(provider)}`
              : `使用 ${providerLabel(provider)} 登录`}
          </a>
        )
      })}
    </div>
  )
}
