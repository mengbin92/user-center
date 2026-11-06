# 组织上下文内的职责分离与委派（S12 设计）

> 状态：**设计待评审**。按 V2.5 §4 W5 的约定，评审通过前不改代码。
> 基线：`v0.7.1`（`main`）· 编写日期：2026-11-06
> 上游：[V2.5 路线图](../roadmap-v2.5.md) §4 W5；[V2.4 路线图](../roadmap-v2.4.md) §3.2（本条为 V2.4 明确欠下的设计债）

## 0. 评审记录（2026-11-06）

评审方式：把设计里的每条断言拿代码验证一遍，而不是只读文字。8 条发现里 2 条推翻了原设计，1 条砍掉了范围，其余是补漏。

| # | 发现 | 性质 | 处理 |
|---|---|---|---|
| F1 | **平台约束在组织域是空转的**：`CheckConstraints` 比对 role id，平台约束存平台 role id，组织决策的 `ActiveRoleIDs` 是组织 role id，两个 ID 空间不相交，`n` 恒为 0 | **推翻 §4 的论证** | 结论不变（组织不能放宽平台），但理由改写：靠的是**结构性不相交**，不是"合并求值"。见 §4 修订 |
| F2 | **组织域没有"下次登录/激活"这个时机**：`orgGuard` 每次请求都按当前分配重算权限，不读会话激活角色。若存在违规分配，成员会**立即**在每次请求上被拒，而不是"下次激活时" | **推翻 §7 策略 C 的后果描述** | 改为保存时返回违规计数 + 要求显式确认，并在 UI 明示"这些成员将立即失去本组织访问"。见 §7 修订 |
| F3 | 缺 API 形状、权限码与并发控制；平台侧约束有 `expected_revision` + policy revision 两道 CAS | 补漏 | 新增 §6.1 |
| F4 | `max_roles` 在组织域的计数口径未定义：组织成员天生带 1 个内置角色（由成员角色同步） | 补漏 | 只计自定义（非内置）角色，见 §4.1 |
| F5 | 引用角色被归档后约束静默失效 | 补漏 | 保存时拒绝引用已归档角色；存量约束不追溯。见 §6.1 |
| F6 | 「平台管理员跨租户只读组织约束」会引入新的跨租户读路径与权限判断，但没有任何需求驱动 | 砍范围 | 移入非目标（§2）。审计已能覆盖治理需要 |
| F7 | 撤销成员时级联失效委派的落点没写清 | 补漏 | 明确在 `revokeOrgMemberAssignments`，见 §9 |
| F8 | 文档原写"需确认 013 是否被幂等断言覆盖" | 已确认 | `cmd/migrate` 的 `for range 2` 跑整个目录，012/013 都被覆盖，无需额外工作 |
| F9 | **`max_roles` 语义写错两次**：它是 `role_ids` 范围内最多几个，不是总共最多几个；`role_ids` 为空时约束整条被跳过；`max_count=0` 被校验拒绝 | **推翻 §4.4 与 D8** | 组织域复用 `validateConstraint`/`CheckConstraints`，不新增计数口径，删掉多余的只计自定义角色过滤 |

五个开放问题（原 §13）当场定案，降级为决策记录：

| ID | 问题 | 决定 |
|---|---|---|
| D6 | 组织约束默认开还是关 | **无全局开关**。"默认关"没有意义：约束只有被人创建时才存在，创建即生效 |
| D7 | 平台管理员能否写组织约束 | **不能，且本阶段也不做跨租户只读**（F6）。需要紧急处置时走组织 owner 账号 |
| D8 | ~~`max_roles = 0` 是否允许~~ | **作废**（F9）：`validateConstraint` 拒绝 `MaxCount <= 0`，且 `max_roles` 本就按 `role_ids` 范围计数，没有该形态 |
| D9 | 约束变更是否写组织审计 | 需要：`organization.constraint.created/updated/deleted` + Outbox 事件 |
| D10 | 撤销成员时委派是删除还是软失效 | 软失效（`revoked_at`），与分配一致，便于事后追溯 |

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
| 平台管理员跨租户只读组织约束 | 会引入新的跨租户读路径却无需求驱动；组织审计已能覆盖治理需要（评审 F6） |
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

## 4. 合并规则：结构性不相交 + 逐集合求值

本节在评审时被推翻过一次，保留修订过程，因为"为什么这样反而是安全的"不直观。

### 4.1 原设计与它的问题（评审 F1）

原设计写的是"一次授权必须同时满足平台约束和组织约束（交集）"。听上去更严格，但**它在代码上不成立**：

`CheckConstraints(roleIDs, constraints)` 比对的是 role id，而平台约束里存的是平台角色 ID，组织上下文里的 `ActiveRoleIDs` 是组织角色 ID。两个表的自增 ID 空间不相交，`slices.Contains(c.RoleIDs, id)` 恒为 false，`n` 恒为 0 —— 平台约束在组织域**每次都通过**，是空转的。

所以"交集合并"不是需要实现的东西，而是**已经存在的结构性事实**：

```
平台约束  ⟂  组织角色        （ID 空间不相交，永不匹配）
组织约束  ⟂  其他组织的角色   （同上）
```

### 4.2 修订后的规则

1. **求值按上下文分别进行**：平台决策只加载平台约束，组织决策只加载该组织的约束。不做跨集合拼接。
2. **"组织不能放宽平台策略"由结构保证，而非由合并逻辑保证**：组织根本没有能影响平台角色组合的入口。
3. **维护这条结构性保证的前提，是 §3.2 的引用限制**：一旦允许组织约束引用平台角色（或反之），两个 ID 空间就打通了，上面第 2 条立刻失效。所以"组织约束只能引用本组织角色"是**安全边界**，不是数据卫生。

### 4.3 如果将来真的需要跨上下文 SoD

"同一人不能既审批又付款，不论在哪个租户"这类要求，用"角色组合"表达不了 —— 必须把约束对象从 role id 换成 operation/permission 集合，那是另一个模型（约束表结构、求值位置、审计都要变）。本阶段明确不做，也不预留半成品字段。

### 4.4 `max_roles` 的真实语义（评审 F4 + F9，两次修正）

第一版写"组织域 `max_roles` 只计自定义角色"，第二版又写"`max_roles=0` 表示只用内置角色"。**两条都是错的**，实现时读代码才发现：

`CheckConstraints` 对 `max_roles` 的判定是 `role_ids` **范围内**的命中数不超过 `max_count`，并且：

- `len(c.RoleIDs) == 0` 时**整个约束被跳过**（`if !c.Enabled || len(c.RoleIDs) == 0 { continue }`）——列不出角色的约束等于不存在。
- `max_count <= 0` 被读作 `1`，但 `validateConstraint` 直接拒绝 `MaxCount <= 0`，所以这个默认值永远不会生效。

所以 `max_roles` 不是"某人最多能有多少个角色"，而是"某人最多能同时持有**下列角色中的几个**"。它天然与内置角色无关：内置角色不在 `role_ids` 里就不计数，写不写"只计自定义"的代码都一样。

**结论：组织域直接复用 `validateConstraint` 与 `CheckConstraints`，不引入任何新的计数口径。** D8 随之作废（不存在 `max_roles=0` 这个形态）。`checkOrgConstraints` 里那段先解析内置角色再过滤的代码因此是多余的，已删除。

`mutual_exclusion` 同理：它是"下列角色中最多同时持有 1 个"，与内置角色无关。

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

### 5.1 判定过程中用到的权限码

组织约束与委派需要两个新权限码，随迁移以 `builtin=false` 的组织权限落库（与现有 `organization.iam.role.manage` 并列：

| 权限码 | 归属上下文 | 用途 | 默认授予 |
|---|---|---|---|
| `organization.iam.constraint.read` | organization | 读本组织约束 | owner、admin |
| `organization.iam.constraint.manage` | organization | 创建/修改/删除本组织约束 | 仅 owner |

原则：**约束属于治理动作，只给 owner**。`admin` 能给成员分配角色，但能改约束就等于能改变"哪些角色组合合法"的规则本身；两者分开才有意义。自定义组织角色可通过 `PutRoleGrants` 显式获得该权限，但受 §8 的"不能给自己授权"约束。

## 6. 越权边界

| 场景 | 结论 | 实现要点 |
|---|---|---|
| 组织管理员读本组织约束 | ✅ 允许 | `ListConstraints(ctx, tx, authCtx)` 按 context 过滤 |
| 组织管理员读写其他组织约束 | ❌ 404 | 列表按 context 过滤；单条读取校验 context 匹配后返回 `RESOURCE_NOT_FOUND` |
| 组织管理员读平台约束 | ❌ 404 | 列表已过滤；显式 GET 也返回 404（不返回 403，避免确认"平台上有这条策略"） |
| 组织管理员创建引用平台角色的约束 | ❌ 400 | §3.2 写入校验 |
| 组织管理员删除/停用平台约束 | ❌ 404 | 单条操作按 context 匹配，不匹配即不存在 |
| 平台管理员读写组织约束 | ❌ 404 | 评审 F6/D7：跨租户读会引入新的租户穿透路径却无需求驱动，组织审计已能覆盖治理。紧急处置走组织 owner 账号 |
| 组织约束收紧导致现有分配违规 | ⚠️ 需显式确认后保存 | 见 §7 修订：违规会**立即**生效 |

### 6.1 API 形状与并发控制（评审 F3/F5）

组织侧沿用平台约束的四操作形状，只是把 `{id}` 换成 `{org_id}`、把上下文固定为路径里的组织：

```
GET    /api/v1/orgs/{org_id}/iam/constraints
POST   /api/v1/orgs/{org_id}/iam/constraints
PATCH  /api/v1/orgs/{org_id}/iam/constraints/{id}
DELETE /api/v1/orgs/{org_id}/iam/constraints/{id}
```

并发控制与平台侧对齐，两道 CAS 都要有：

| 字段 | 作用 | 缺失后果 |
|---|---|---|
| `expected_revision` | 防止两个管理员同时改同一条约束 | 后写覆盖前写，且审计里看不出覆盖 |
| `expected_policy_revision` | 防止在策略已变更（角色被归档/授权被改）的旧快照上写约束 | 引用一个刚被归档的角色，约束静默失效 |
| `reason` | 审计理由，服务层强制非空 | 治理动作无法复盘 |

写入校验顺序（在事务内，先拿锁再校验）：

1. `orgGuard(PermOrgConstraintManage)` + step-up
2. `policyGuard(expected_policy_revision)` —— 与平台一致
3. 角色归属：`role_ids` 全部属于该组织，且状态为 `active`（**F5**：拒绝引用已归档角色，否则约束静默空转）
4. `validateConstraint` —— 与平台共用同一个函数，避免两处规则漂移
5. 计算违规分配，按 §7 决定是否需要 `acknowledge_violations`
6. 写约束 + bump policy revision + 组织审计 + Outbox 事件（`organization.constraint.created/updated/deleted`）

**关于"引用角色后来被归档"**：保存时校验挡不住未来。求值侧的处理是——`CheckConstraints` 对已归档角色的 ID 仍会匹配到（因为约束存的是 ID），所以行为是"约束仍在，但那个角色不能再被分配"。这是可接受的（不会放宽），无需额外处理。

## 7. 存量数据与"收紧"的处理

新增一条约束（或把 `max_roles` 从 3 调到 2）会让**现有**分配变成违规。三种可选策略：

| 策略 | 后果 | 采纳 |
|---|---|---|
| A. 保存即拒绝（存在违规分配时不允许收紧） | 管理员必须先逐个撤销，操作成本高，但状态永远自洽 | ❌ |
| B. 保存成功 + 违规分配标脏，下次激活时拒绝 | 状态短暂不一致；管理员看得见问题但会话可能突然失效 | ❌ |
| C. **保存成功 + 阻止新的赋值 + 已有违规分配立即生效（每次请求都拒）** | 组织域没有"激活时机"，冲突在请求期就被判 deny | ✅（评审后修订） |

选 C 的依据：不主动撤销任何分配 —— 撤销有副作用，必须由人确认。但**后果比原设计写的更重，必须说清楚**：

组织域的权限在每次请求时按当前分配重算（`orgGuard` 不读会话激活角色），所以一条违规分配不会"等到下次登录"，而是**当场让该成员在本组织的每一次请求都被拒**。这相当于把成员静默踢出组织，而管理员以为自己只是"收紧了一条策略"。

因此保存路径加一道确认：

- 响应返回 `violating_assignments` 计数与受影响成员 ID 列表。
- 计数 > 0 时，请求必须带 `acknowledge_violations=true` 才生效，否则返回 `ORGANIZATION_POLICY_VIOLATIONS_PENDING` 并附计数。管理员先看到"这会让 3 名成员立即失去本组织访问"，再决定。
- 不自动撤销、不自动跳过：两种"贴心"处理都会让策略与实际权限悄悄分叉。

## 8. 三类角色的决策矩阵

| 操作 | platform admin（`iam.constraint.write`） | 组织 owner | 组织自定义角色持 `organization.iam.role.manage` |
|---|---|---|---|
| 查看平台约束 | ✅ | ❌ 404 | ❌ 404 |
| 创建/修改/删除平台约束 | ✅ | ❌ 404 | ❌ 404 |
| 查看本组织约束 | ❌ 404 | ✅ | ✅ |
| 创建/修改/删除本组织约束 | ❌ 404 | ✅ | ✅ |
| 查看其他组织约束 | ❌ 404 | ❌ 404 | ❌ 404 |
| 组织内分配角色 | ✅（需 step-up） | ✅ | ✅（受委派边界约束） |
| 组织内委派 | ❌ 403 | ✅ | ✅（只能委托自己持有的角色） |
| 跨组织委派 | ❌ 404 | ❌ 404 | ❌ 404 |

两条补充边界：

1. **组织成员不能给自己授权**（不只是 owner）。当前组织 `AssignRole` 没有这条限制；本设计一并补上——目标用户是自己且角色含 `organization.iam.assignment.manage` 时拒绝，否则"约束由组织自己定"+"能给自己加角色"= 约束形同虚设。这条不依赖约束机制，是必要配套。
2. **平台管理员在本设计里完全没有组织约束入口**（D7）。`isPlatformAdmin` 在 `orgGuard` 里是直接放行的旁路，如果也给约束开口，等于留下一条绕过组织治理的通道。

## 9. 委派的组织域语义

平台委派回答的是"谁能代替我把某个角色授予别人"。组织域需要同一件事，但有两条额外限制：

1. **只能在组织上下文内授予**：`manager_role_id` 与 `target_role_id` 必须同属该组织。跨上下文委派直接拒绝（写入校验，§3.2 的同一套逻辑）。
2. **只能委托自己持有的角色**：`manager_role_id` 必须在委派创建者的活跃角色集合内 —— 这条与平台的 `checkDelegation` 一致。

### 9.1 与平台委派的关系

- 平台委派**不能**用于组织内分配。`checkDelegation` 增加 context 参数，平台委派只匹配 `context_type='platform'`，因此不会"顺带"覆盖组织。
- 组织委派**不能**用于平台分配。同一参数方向相反。
- 两者的存储、求值、审计完全隔离：`iam_delegations` 加 `(context_type, context_id)` 后，平台的 `ListDelegations` 默认过滤 `platform`，组织查询强制带 context。

### 9.2 撤销成员资格的级联（评审 F7）

当前 `revokeOrgMemberAssignments` 只调 `RevokeMemberAssignments` 撤销分配，**没有撤销委派**。落点如下：

```go
func revokeOrgMemberAssignments(ctx context.Context, s *Services, tx Tx, orgID, userID, by int64) error {
    // 已有：撤销该成员在本组织的全部角色分配
    if _, err := s.OrgIAM.RevokeMemberAssignments(ctx, tx, authorization.Organization(orgID), userID, nil, by); err != nil {
        return err
    }
    // 新增：软失效所有以该成员为 manager 的委派（D10）
    return s.OrgIAM.RevokeDelegationsForUser(ctx, tx, authorization.Organization(orgID), userID, by)
}
```

配套语义：

- **软失效而非删除**（D10）：写 `revoked_at`，保留记录供审计追溯。
- **同时撤销"以他为 manager"和"以他为 target"的委派**：前者是他不能再代授，后者是别人不能再授给他。只处理一半会让撤销成员后仍有一条授权通道。
- 委派失效**不**触发级联撤销已授出的分配：那是他的继任者要复核的事情，自动回滚会让历史权限无解释地消失。
- 成员重新加入组织时**不自动恢复**委派：失效是永久的，重新建立需要重新授予。

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

评审时删掉了两条原用例，因为它们在修订后的模型里**不可能发生**（写出来只会制造"已覆盖"的假象）：

- ~~"平台约束对组织分配生效 → 409 + `scope=platform`"~~：平台约束引用平台角色 ID，永不匹配组织角色（F1）。真正要断言的相反结论见下表第一行。
- ~~"`CheckConstraints` 平台拒绝 + 组织放行 → 仍拒绝"~~：两个集合不相交，不存在"同时命中"的输入。

| 层 | 用例 | 断言 |
|---|---|---|
| 单元 | **平台约束不影响组织决策**（F1 的回归锁） | 平台建一条互斥约束（引用平台角色 A/B）后，组织内授予两个组织角色 → 仍然成功 |
| 单元 | 约束求值按 context 过滤 | 组织 A 的约束不出现在组织 B 的 `GetAuthzFactsIn` 结果里 |
| 单元 | 跨作用域引用校验 | 组织约束引用平台角色 ID → 400；平台约束引用组织角色 ID → 400 |
| 单元 | `max_roles` 只计自定义角色（F4） | 成员持有 1 个内置 + `max_roles=1` 时，可再授 1 个自定义角色 |
| 单元 | 委派 context 匹配 | 平台委派不能批准组织分配；组织委派不能批准平台分配 |
| HTTP | 组织内互斥角色对 | 分配第二个互斥角色 → 409 + `scope=organization` |
| HTTP | 跨租户 | 组织 A 管理员读写组织 B 约束 → 全部 404（含列表为空而非 403） |
| HTTP | 平台管理员访问组织约束 | → 404（D7） |
| HTTP | 自授权 | 组织成员给自己加管理角色 → 403 |
| HTTP | 引用归档角色 | 约束引用已归档角色 → 400（F5） |
| HTTP | 收紧后存量违规未确认 | → `ORGANIZATION_POLICY_VIOLATIONS_PENDING` + 计数；约束**未**落库 |
| HTTP | 收紧后存量违规已确认 | → 200 + `violating_assignments`；受影响成员的**下一次**组织请求即 403（F2，不是"下次登录"） |
| HTTP | 撤销成员资格 | 该成员的组织分配与委派（两个方向）同时软失效（F7） |
| 迁移 | MySQL 8.4 连续应用两次 | 幂等（`cmd/migrate` 的 `for range 2` 覆盖整个目录）；存量约束/委派 `context_type='platform'` |
| 迁移 | 存量行语义不变 | 升级后平台约束的判定结果与升级前逐条一致 |

## 12. 实施拆分（评审通过后）

| 阶段 | 内容 | 规模 |
|---|---|---|
| P1 | 迁移 013 + `Constraint`/`Delegation` 模型加 context + 仓储按 context 过滤 | M |
| P2 | `CheckConstraints` / `checkDelegation` 加 context 参数；组织分配两条路径接入；**自授权拦截**（§8） | M |
| P3 | 组织约束 CRUD API（proto + service + biz）+ 跨作用域引用校验 + 违规确认（§7） | M |
| P4 | 组织委派 CRUD API + 撤销成员时双向级联软失效（§9.2） | M |
| P5 | Web 组织设置页（约束列表、委派列表、违规确认对话框） | M |
| P6 | 文档（`docs/security.md` 的 SoD 章节、`docs/architecture.md` 的授权模型图） | S |

拆分原则与发版：

- **P1–P2 是缺口修复**（组织域此前完全跳过约束与委派校验，等于平台 SoD 可被绕过），行为上只会**变严**，不会放宽任何现有权限。单独发 PATCH 即可。
- **P3–P5 是新能力**，随下一个 MINOR。
- P2 的自授权拦截也放进 PATCH：它不依赖约束机制，且没有它，P3 的能力等于给了一个可以自我扩权的开关。

每阶段的验收都必须包含"存量行为不变"：P1–P2 只应让**非法**的组合被拒，合法组合的判定结果必须与升级前逐条一致（见 §11 最后一行）。

## 13. 评审结论

五条原开放问题已在 §0 的 D6–D10 定案（其中 D6 被重新表述：不存在"组织约束默认开/关"这个开关，约束只有被人创建时才存在）。评审同时推翻了 §4 的论证与 §7 的后果描述，并把"平台管理员跨租户只读"移出范围。

**结论：设计通过，可进入实现。** 但有两条前置必须先做，否则 P3 之后的实现会建在错误的前提上：

1. **先补 P1–P2 的回归测试再改代码**：F1 的结论（平台约束对组织决策无影响）目前没有任何断言保护。如果有人在 P1 里顺手"修正"了 `CheckConstraints` 让它跨 ID 空间匹配，会静默改变平台行为而无人察觉。§11 第一行那条用例必须先红后绿。
2. **P1 迁移必须先于 P2 代码上线**：`Constraint`/`Delegation` 的 context 过滤依赖新列，代码先上会读到 `context_type=''` 的行。按 compose 的 `migrate` 一次性服务部署即可满足，但手工部署要写明顺序。

评审未解决的遗留（不阻塞实现，写入已知限制）：

- 跨上下文 SoD（"同一人不能既审批又付款，跨租户"）需要换模型，见 §4.3。
- 组织约束的命名空间与平台共用 `iam_role_constraints` 表，`name` 唯一性只在 context 内保证；跨 context 重名会让审计里的名称有歧义，靠 `scope` 字段区分。

## 14. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-11-06 | 初稿 |
| 2026-11-07 | 实现期修正（F9）：`max_roles` 语义两次写错，改为完全复用平台校验，删除 `checkOrgConstraints` 中的自定义角色过滤 |
| 2026-11-06 | 评审：8 条发现（F1–F8），推翻 §4 论证与 §7 后果描述，砍掉平台管理员跨租户只读，补 §5.1/§6.1/§9.2，D6–D10 定案，删除两条不可能发生的测试用例，结论为"通过，可进入实现" |
