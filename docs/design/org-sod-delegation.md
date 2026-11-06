# 组织上下文内的职责分离与委派（S12 设计）

> 状态：**设计待评审**。按 V2.5 §4 W5 的约定，评审通过前不改代码。
> 基线：`v0.7.1`（`main`）· 编写日期：2026-11-06
> 上游：[V2.5 路线图](../roadmap-v2.5.md) §4 W5；[V2.4 路线图](../roadmap-v2.4.md) §3.2（本条为 V2.4 明确欠下的设计债）

## 1. 要解决的问题

平台上下文已有角色互斥（`mutual_exclusion`）、角色数量上限（`max_roles`）与委派（`iam_delegations`）。组织上下文有独立的角色、授权与审计，但**这两套治理机制在组织域完全不存在**。

实测结论（不是推断）：

| 能力 | 平台上下文 | 组织上下文 | 证据 |
|---|---|---|---|
| 互斥角色对 / 角色数量上限 | ✅ 分配、激活、决策三处都校验 | ❌ **完全没有** | `org_iam.go:492 AssignRole` 全程未调用 `CheckConstraints` |
| 委派 | ✅ 分配/撤销四条路径都校验 | ❌ **完全没有** | 上述函数未调用 `checkDelegation` |
| 约束存储 | `iam_role_constraints`（**无 context 列**） | 无 | `constraintPO` 仅有 kind/name/role_ids/max_count |
| 委派存储 | `iam_delegations`（**无 context 列**） | 无 | `delegationPO` 仅有 manager_role_id / target_role_id |

后果按严重度排序：

1. **组织管理员可以自造"全权角色"**：给同一名成员同时授予"审批"和"付款"两个互斥职责，平台侧定义的 SoD 在租户内被绕过 —— 但平台侧并不知道这件事发生过。
2. **组织内授权没有上限**：一个成员可以被授予本组织全部自定义角色，`max_roles` 在组织域无效。
3. **成员管理没有委派边界**：组织 owner 可以把成员管理权交给任意自定义角色持有者，而平台侧"只能授予不超过自己的权限"（`checkGrantAuthority`）只作用于平台角色。

## 2. 目标与非目标

**目标**

- 组织管理员能在**不触碰平台策略**的前提下，为本组织定义互斥角色对与角色数量上限。
- 组织内的约束与委派只能在组织上下文内生效，**不能放宽**平台约束。
- 跨租户不可见、不可写。
- 分配与激活两条路径都执行校验（与平台一致，不允许只卡一条）。

**非目标（本阶段明确不做，理由随附）**

| 项 | 理由 |
|---|---|
| 组织约束影响平台角色组合 | 那会让租户能限制平台管理员，属于治理倒挂 |
| 组织管理员查看/编辑平台约束 | 同上；只读视图留给后续"策略解释"需求 |
| 约束继承（组织父子/部门级） | 组织层级目前只有部门，没有策略继承语义；引入会需要新的求值顺序定义 |
| 跨组织委派 | 与租户隔离直接冲突 |
| 约束的审批流 | 组织变更已有审计与 Outbox，审批流是独立能力 |

## 3. 作用域模型

### 3.1 唯一的一种作用域表达

角色与分配已经用 `(context_type, context_id)` 表达作用域（`platform`/`organization` + 组织 ID）。约束与委派**沿用同一对列**，不引入第二套表达：

```sql
ALTER TABLE iam_role_constraints
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_constraints_context (context_type, context_id);

ALTER TABLE iam_delegations
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_delegations_context (context_type, context_id);
```

`DEFAULT 'platform' / 0` 让存量行自动成为平台策略，**回填即为零操作**，也不需要 `UPDATE` 语句。

### 3.2 引用完整性：约束只能引用同作用域的角色

这是整个设计里最容易写错、也最容易被绕过的一条。

- `policy_role_ids` 必须**全部**属于约束自身的 `(context_type, context_id)`。
- 平台约束不能引用组织角色（否则平台策略会随某个租户删角色而失效）。
- **组织约束不能引用平台角色**（否则组织管理员可以用"把两个平台角色设为互斥"来影响平台管理员的可用角色组合 —— 这是提权）。

写入时校验，读取时不校验（读路径多一次 JOIN 的代价换不到安全性，写路径已经保证不变量）。迁移完成后加一道启动期自检：统计"跨作用域引用"的行数，非 0 则在日志告警但不阻断启动（历史数据可能因为人工改库而违规，阻断启动会让整个服务不可用）。

## 4. 合并规则：交集，不是并集

**规则一句话**：一次授权必须同时满足平台约束和组织约束；任一失败即拒绝。

```
允许 ⇔ CheckConstraints(roles, 平台约束[enabled]) = nil
      ∧ CheckConstraints(roles, 本组织约束[enabled]) = nil
```

为什么不是"组织约束覆盖平台约束"：`max_roles` 这类约束是**上限**语义，两个上限同时成立等价于取更严的那个（交集）。如果允许组织覆盖，等于允许租户放宽平台策略 —— 正是本次要堵的漏洞。

为什么不是"取并集拼接后统一求值"：`mutual_exclusion` 与 `max_roles` 的求值方式不同，且未来可能增加 `requires`（A 角色必须搭配 B）这类跨集合语义。保持"逐集合独立求值 + AND 合并"能让新增约束类型只改 `CheckConstraints` 内部，不改合并逻辑。

**组织约束不能声明"禁用平台约束"**：没有 `disabled_by` 之类的字段，也不打算加。

## 5. 冲突判定顺序

一次分配/激活的求值顺序固定如下，任何一步失败立即返回，不继续求值（避免把内部策略细节泄漏给调用方）：

| 顺序 | 检查 | 失败错误码 | 说明 |
|---|---|---|---|
| 1 | 作用域完整性（角色属于目标组织、成员属于目标组织） | `RESOURCE_NOT_FOUND` | 跨租户一律 404，不区分"不存在"与"无权" |
| 2 | 操作权限（`organization.iam.assignment.manage` 等） | `PERMISSION_DENIED` | 与现状一致 |
| 3 | 历史记录（已拥有该角色、`max_members` 容量） | `ORGANIZATION_ASSIGNMENT_EXISTS` / `ORGANIZATION_ROLE_FULL` | 与现状一致 |
| 4 | **平台约束** | `ROLE_CONSTRAINT_VIOLATION` | 新增：组织分配此前完全跳过 |
| 5 | **组织约束** | `ROLE_CONSTRAINT_VIOLATION`（metadata `scope=organization`） | 新增 |
| 6 | **委派边界** | `DELEGATION_REQUIRED` | 新增：组织分配此前完全跳过 |

要点：

- 平台约束排在组织约束之前：如果两者都未通过，报平台的那条。理由是平台策略由更高权限方定义，优先暴露它能让组织管理员知道"这不是我能改的"。
- 错误码保持 `ROLE_CONSTRAINT_VIOLATION` 不变，通过 metadata 的 `scope` 区分来源。前端据此决定提示文案："该组合违反平台策略，请联系平台管理员" vs "该组合违反本组织策略，可在组织设置中调整"。
- 平台侧不返回组织约束的具体名称给组织管理员以外的人。

## 6. 越权边界

| 场景 | 结论 | 实现要点 |
|---|---|---|
| 组织管理员读本组织约束 | ✅ 允许 | `ListConstraints(ctx, tx, authCtx)` 按 context 过滤 |
| 组织管理员读写其他组织约束 | ❌ 404 | 列表按 context 过滤；单条读取校验 context 匹配后返回 `RESOURCE_NOT_FOUND` |
| 组织管理员读平台约束 | ❌ 404 | 列表已过滤；显式 GET 也返回 404（不返回 403，避免确认"平台上有这条策略"） |
| 组织管理员创建引用平台角色的约束 | ❌ 400 | §3.2 写入校验 |
| 组织管理员删除/停用平台约束 | ❌ 404 | 单条操作按 context 匹配，不匹配即不存在 |
| 平台管理员读组织约束 | ✅ 只读 | 治理与审计需要；列表加 `context` 参数 |
| 平台管理员写组织约束 | ❌ 403 | **默认不允许**。理由：平台侧改租户策略会让"组织策略由组织自己负责"的边界失效，且审计归属会含糊（记在谁的账上）。如后续有强需求，单独立项并需要组织侧同意记录 |
| 组织约束收紧导致现有分配违规 | ⚠️ 允许保存，存量分配不追溯失效 | 见 §7 |

## 7. 存量数据与"收紧"的处理

新增一条约束（或把 `max_roles` 从 3 调到 2）会让**现有**分配变成违规。三种可选策略：

| 策略 | 后果 | 采纳 |
|---|---|---|
| A. 保存即拒绝（存在违规分配时不允许收紧） | 管理员必须先逐个撤销，操作成本高，但状态永远自洽 | ❌ |
| B. 保存成功 + 违规分配标脏，下次激活时拒绝 | 状态短暂不一致；管理员看得见问题但会话可能突然失效 | ❌ |
| C. **保存成功 + 阻止新的赋值 + 违规分配在下次登录/激活时按新规则拒绝** | 与平台约束的现有语义一致 | ✅ |

选 C 的依据：平台约束当前就是"只在写路径与激活路径校验，不对存量做清理"。组织域沿用同一语义，运维心智一致。差异写进文档而不是留给用户发现：

- 保存接口的响应里返回 `violating_assignments` 计数（>0 时前端提示"有 N 条现有授权违反新策略，将在下次会话激活时失效"）。
- 不主动撤销任何分配：撤销是有副作用的动作，必须由人确认。

## 8. 三类角色的决策矩阵

| 操作 | platform admin（`iam.constraint.write`） | 组织 owner | 组织自定义角色持 `organization.iam.role.manage` |
|---|---|---|---|
| 查看平台约束 | ✅ | ❌ 404 | ❌ 404 |
| 创建/修改/删除平台约束 | ✅ | ❌ 404 | ❌ 404 |
| 查看本组织约束 | ✅（只读） | ✅ | ✅ |
| 创建/修改/删除本组织约束 | ❌ 403（默认） | ✅ | ✅ |
| 查看其他组织约束 | ✅（只读，治理） | ❌ 404 | ❌ 404 |
| 组织内分配角色 | ✅（需 step-up） | ✅ | ✅（受委派边界约束） |
| 组织内委派 | ❌ 403 | ✅ | ✅（只能委托自己持有的角色） |
| 跨组织委派 | ❌ 404 | ❌ 404 | ❌ 404 |

一张补充边界：**组织 owner 不能给自己授权**。当前组织 `AssignRole` 没有这条限制；本设计一并补上（`targetUserID == actor.UserID` 且角色含 `organization.iam.assignment.manage` 时拒绝），否则"约束由组织自己定"+"能给自己加角色"= 约束形同虚设。这条不依赖约束机制，属于本设计的必要配套。

## 9. 委派的组织域语义

平台委派回答的是"谁能代替我把某个角色授予别人"。组织域需要同一件事，但有两条额外限制：

1. **只能在组织上下文内授予**：`manager_role_id` 与 `target_role_id` 必须同属该组织。跨上下文委派直接拒绝（写入校验，§3.2 的同一套逻辑）。
2. **只能委托自己持有的角色**：`manager_role_id` 必须在委派创建者的活跃角色集合内 —— 这条与平台的 `checkDelegation` 一致。

与平台委派的关系：

- 平台委派**不能**用于组织内分配。`checkDelegation` 增加 context 参数，平台委派只匹配 `context_type='platform'`，因此不会"顺带"覆盖组织。
- 组织委派**不能**用于平台分配。同一参数方向相反。
- 撤销组织成员资格时，该成员在本组织内的委派一并失效（已经在 `revokeOrgMemberAssignments` 里撤销分配，委派需要同样处理 —— 当前遗漏）。

## 10. 迁移

```sql
-- 013_org_sod_delegation.sql
ALTER TABLE iam_role_constraints
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_constraints_context (context_type, context_id);

ALTER TABLE iam_delegations
    ADD COLUMN context_type VARCHAR(16) NOT NULL DEFAULT 'platform',
    ADD COLUMN context_id   BIGINT      NOT NULL DEFAULT 0,
    ADD KEY idx_iam_delegations_context (context_type, context_id);
```

- 幂等性：`ADD COLUMN ... DEFAULT` 在 MySQL 8.4 上重复执行会报 1060（列已存在）。迁移框架按版本号只应用一次，重复应用由版本表保证；`TestOIDCMySQLMigrations` 的"应用两次"断言会覆盖这一点，需确认它对 013 同样生效。
- 无数据回填：`DEFAULT` 即回填。
- 回滚：删除两列即可，组织侧新增的行会随之消失，但**平台策略不受影响**（因为平台行的默认值就是原来的语义）。回滚后组织约束数据丢失，需在发版说明中写明。

## 11. 测试矩阵

| 层 | 用例 | 断言 |
|---|---|---|
| 单元 | `CheckConstraints` 在 context 过滤后只看到本作用域约束 | 平台拒绝 + 组织放行 → 仍拒绝 |
| 单元 | 跨作用域引用校验 | 组织约束引用平台角色 ID → 400 |
| 单元 | 委派 context 匹配 | 平台委派不能批准组织分配 |
| HTTP | 组织内互斥角色对 | 分配第二个互斥角色 → 409 + `scope=organization` |
| HTTP | 平台约束对组织分配生效 | 平台约束命中 → 409 + `scope=platform` |
| HTTP | 跨租户 | 组织 A 管理员读写组织 B 约束 → 全部 404 |
| HTTP | owner 自授权 | 组织 owner 给自己加管理角色 → 403 |
| HTTP | 收紧后存量违规 | 保存成功，响应含 `violating_assignments`，存量分配未被撤销 |
| HTTP | 撤销成员资格 | 该成员的组织委派同时失效 |
| 迁移 | MySQL 8.4 连续应用两次 | 幂等；存量约束 `context_type='platform'` |

## 12. 实施拆分（评审通过后）

| 阶段 | 内容 | 规模 |
|---|---|---|
| P1 | 迁移 013 + `Constraint`/`Delegation` 模型加 context + 仓储按 context 过滤 | M |
| P2 | `CheckConstraints` / `checkDelegation` 加 context 参数，组织分配两条路径接入 | M |
| P3 | 组织约束 CRUD API（proto + service + biz）+ 跨作用域引用校验 | M |
| P4 | 组织委派 CRUD API + 撤销成员时级联 | M |
| P5 | Web 组织设置页（约束列表、委派列表）+ 违规计数提示 | M |
| P6 | 文档（`docs/security.md` 的 SoD 章节、`docs/architecture.md` 的授权模型图） | S |

P1–P2 是行为修复（组织域此前跳过校验），建议单独发 PATCH；P3–P5 是新能力，随下一个 MINOR。

## 13. 待评审确认的开放问题

1. **组织约束默认开启还是默认关闭？** 建议：默认关闭（`enabled=false`），由组织管理员显式启用。理由：新机制默认生效会让存量组织在无感知的情况下改变行为。
2. **平台管理员是否永远不能写组织约束？** 建议维持"只读"。如果需要紧急处置，走组织 owner 账号或后续的"平台代管"开关（需要单独审计字段）。
3. **组织约束是否允许 `max_roles=0`（禁止任何自定义角色）？** 建议允许，语义是"本组织只用内置角色"。
4. **是否需要在组织审计里记录约束变更？** 建议需要，动作名沿用 R6 事件命名：`organization.constraint.created/updated/deleted`。
5. **撤销成员资格时是否需要保留委派记录用于追溯？** 建议软失效（`revoked_at`）而非删除，与分配一致。
