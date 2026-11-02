import { LockKeyhole } from 'lucide-react'
import { Link } from 'react-router'

import { InlineAlert } from '../../components/card'

export function PasswordChangeNotice({
  required,
  showLink = false,
}: {
  required: boolean
  showLink?: boolean
}) {
  if (!required) return null
  return (
    <div role="alert" data-testid="password-change-notice">
      <InlineAlert
        tone="danger"
        icon={LockKeyhole}
        title="必须先修改初始密码"
      >
        当前账号仍在使用初始密码。完成修改前无法进入管理控制台，管理端接口会返回
        PASSWORD_CHANGE_REQUIRED。
        {showLink ? (
          <Link
            to="/account/security?password_change_required=1"
            className="ml-1 font-medium text-rose-800 underline"
          >
            前往安全中心修改
          </Link>
        ) : (
          <span className="ml-1">请在下方“修改密码”表单中完成修改。</span>
        )}
      </InlineAlert>
    </div>
  )
}
