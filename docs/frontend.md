# 前端

`web/` 是 React 19 + TypeScript + Vite + Tailwind CSS v4 的单页应用，包含用户门户与管理控制台。

## 目录

```text
web/src/
├── app/            路由、布局、启动
├── components/     UI 基础组件（Button/Input/Dialog/Table/Badge/Toast）
├── features/       auth、account、users、iam、audit、settings
├── lib/            API 客户端、查询键、权限投影、CSRF
└── lib/api-types.ts  由 openapi.yaml 生成的类型
```

## 认证与请求

- 会话只存在 HttpOnly Cookie；前端不读取、不持久化令牌。
- 启动时调用 `/api/v1/auth/context` 获取 CSRF 并读取 `uc_csrf` Cookie。
- 所有非 GET 请求带 `X-CSRF-Token` 与 `X-Request-ID`。
- 登录后并行请求 `/me` 与 `/me/authorization`；权限与菜单只来自服务端投影。
- 会话 generation 隔离在途响应，登出/角色变更清缓存；授权或安全状态查询失败时关闭管理入口。
- 401 清空 TanStack Query 缓存并跳转登录；403 显示无权限状态；409 展示冲突并刷新；429 展示重试倒计时。
- 跨标签页通过 `BroadcastChannel` 传播登出与授权失效。

## 页面

- 公开：登录（含 MFA 第二步、GitHub/Google 登录）、注册、忘记/重置密码、协议与隐私。
- 用户：资料、安全中心（密码/邮箱/MFA/恢复码/Step-up/第三方绑定）、会话、会话角色、登录记录、组织切换。
- 组织：`/orgs` 列表/创建；`/orgs/:id` 概览/成员/部门/角色与授权/审计/设置。角色与授权页签管理本组织角色（内置只读、自定义可建/改/归档）、成员授权与撤销；审计页签只读取本组织事件，并支持动作筛选。owner/platform 可写，admin 可读；前端隐藏不等于授权，服务端按 `organization:{id}` 上下文判定。
- 管理：概览、用户列表/详情（含管理员邮箱变更）、角色与继承、权限目录、授权分配（`/admin/iam/assignments` 列表/创建/撤销）、委派（`/admin/iam/delegations`）、约束、菜单、授权解释/模拟、审计、导出、认证/邮件配置、接入服务（`/admin/integrations`，客户端凭据/轮换/停用/事件投递重试）、OIDC 应用（`/admin/applications`，客户端/回调/scope/密钥轮换）、组织目录（`/admin/organizations`，平台管理员归档）。
- 强制流程：登录响应带 `password_change_required` 时跳转安全中心并阻断管理导航；`mfa_enrollment_required` 时提示先绑定 TOTP；`PASSWORD_CHANGE_REQUIRED` / `MFA_ENROLLMENT_REQUIRED` / `DELEGATION_REQUIRED` 都有明确中文提示。
- OAuth：登录/绑定按钮使用整页跳转 `/api/v1/auth/providers/{provider}/start`，回调结果由 `/auth/callback/:provider` 展示；不在前端保存 provider token。
- 纯 OAuth 账号在安全中心通过已绑定提供方重新验证（`mode=verify`），之后可设置首个本地密码和 MFA；已有 MFA 时还需当前第二因素。无本地密码时，相应表单不强制填写当前密码。

高风险操作需要填写原因；遇到 `STEP_UP_REQUIRED` 时打开近期验证对话框，完成后仅在同一会话仍有效时受控重试一次，重试仍失败则返回错误。登出请求失败会显示错误并允许重试，不伪装已完成服务端撤销。

## 开发

```bash
cd web
npm install
npm run dev       # http://localhost:5173，/api 代理到 :8080
npm run test
npm run build
```

生产构建产物由后端 `WEB_DIST`（默认 `web/dist`）托管；Docker 镜像已包含构建结果。
