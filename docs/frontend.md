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
- 401 清空 TanStack Query 缓存并跳转登录；403 显示无权限状态；409 展示冲突并刷新；429 展示重试倒计时。
- 跨标签页通过 `BroadcastChannel` 传播登出与授权失效。

## 页面

- 公开：登录（含 MFA 第二步）、注册、忘记/重置密码、协议与隐私。
- 用户：资料、安全中心（密码/邮箱/MFA/恢复码/Step-up）、会话、会话角色、登录记录。
- 管理：概览、用户列表/详情、角色与继承、权限目录、授权分配、约束、菜单、授权解释/模拟、审计、导出、认证/邮件配置。

高风险操作需要填写原因；遇到 `STEP_UP_REQUIRED` 时打开近期验证对话框，完成后仅重试一次，禁止自动重放。

## 开发

```bash
cd web
npm install
npm run dev       # http://localhost:5173，/api 代理到 :8080
npm run test
npm run build
```

生产构建产物由后端 `WEB_DIST`（默认 `web/dist`）托管；Docker 镜像已包含构建结果。
