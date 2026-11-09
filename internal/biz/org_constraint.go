package biz

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Organization-scoped segregation of duties.
//
// The platform has had mutual-exclusion and max-role constraints since V2.2,
// but the organization domain skipped them entirely: an org admin could grant
// one member two mutually exclusive duties and stack unlimited custom roles,
// while every platform-side SoD rule looked satisfied. This file closes that
// gap without giving tenants any lever over platform policy.
//
// Two properties carry the isolation, and both are load-bearing:
//
//  1. Constraints are read by context (ListConstraints(ctx, tx, authCtx)).
//     A platform constraint must never be evaluated against an organization's
//     roles, and one tenant's rules must never reach another.
//  2. A constraint may only reference roles from its own context. Without this,
//     an org admin could write a constraint over platform role ids and start
//     reshaping platform decisions -- privilege escalation through policy.

// OrgConstraintInput is the writable surface of an organization constraint.
type OrgConstraintInput struct {
	Kind     string
	Name     string
	RoleIDs  []int64
	MaxCount int64
	Enabled  bool
	// AcknowledgeViolations must be true when the constraint would immediately
	// invalidate existing assignments. Organization permissions are recomputed
	// on every request, so "violating" means those members lose access now, not
	// at their next login.
	AcknowledgeViolations bool
}

// OrgConstraintChange is the result of a write, including how many existing
// assignments the stored constraint rejects.
type OrgConstraintChange struct {
	Constraint *Constraint
	Violations int64
}

// orgConstraintGuard is the tenant boundary for the segregation-of-duties
// endpoints, and it is deliberately NOT orgGuard.
//
// D7 decided that platform administrators have no entry point into a tenant's
// constraints -- not even read-only -- because every such path is a new
// cross-tenant channel with no requirement behind it (organization audit
// already covers governance). orgGuard returns early for isPlatformAdmin, so
// reusing it here silently re-opens exactly that channel: a platform account can
// enumerate every tenant's rules and write a policy that immediately locks the
// tenant's own members out.
//
// A non-member is answered with "not found", the same answer a cross-tenant id
// gets: 403 would confirm the organization exists and that the caller is
// outside it.
func (uc *OrgIAMUsecase) orgConstraintGuard(ctx context.Context, actor ActorContext, orgID int64, operation string) (authorization.Context, error) {
	authCtx := authorization.Organization(orgID)
	if orgID <= 0 {
		return authCtx, ErrResourceNotFound
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil || org.Status != OrgStatusActive {
		return authCtx, ErrResourceNotFound
	}
	member, err := uc.Organizations.GetMember(ctx, nil, orgID, actor.User.ID)
	if err != nil || member.Status != OrgMemberActive {
		return authCtx, ErrResourceNotFound
	}
	// Materialize built-in roles for a legacy organization: an empty role list
	// would make every constraint look like it references nothing.
	if err := uc.ensureOrganizationIAM(ctx, orgID); err != nil {
		return authCtx, err
	}
	if _, err := uc.AuthorizeIn(ctx, actor, authCtx, operation, 0, true); err != nil {
		return authCtx, err
	}
	return authCtx, nil
}

func (uc *OrgIAMUsecase) Constraints(ctx context.Context, actor ActorContext, orgID int64) ([]*Constraint, error) {
	authCtx, err := uc.orgConstraintGuard(ctx, actor, orgID, PermOrgConstraintRead)
	if err != nil {
		return nil, err
	}
	items, err := uc.IAM.ListConstraints(ctx, nil, authCtx)
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *OrgIAMUsecase) CreateConstraint(ctx context.Context, actor ActorContext, orgID int64, in OrgConstraintInput, reason string, expectedPolicy uint64) (*OrgConstraintChange, error) {
	authCtx, err := uc.orgConstraintGuard(ctx, actor, orgID, PermOrgConstraintManage)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	candidate := &Constraint{
		Kind: in.Kind, Name: in.Name, RoleIDs: in.RoleIDs,
		MaxCount: in.MaxCount, Enabled: in.Enabled, Context: authCtx,
	}
	if err := validateConstraint(candidate); err != nil {
		return nil, err
	}
	var change *OrgConstraintChange
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.validateConstraintRoles(ctx, tx, authCtx, candidate.RoleIDs); err != nil {
			return err
		}
		violations, err := uc.countViolations(ctx, tx, authCtx, candidate)
		if err != nil {
			return err
		}
		if violations > 0 && !in.AcknowledgeViolations {
			return ConflictCode("ORGANIZATION_POLICY_VIOLATIONS_PENDING",
				"该约束会使现有授权失效，请确认后再保存")
		}
		saved, err := uc.IAM.CreateConstraint(ctx, tx, candidate)
		if err != nil {
			return ErrDependency
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.constraint.created", itoa(saved.ID), reason); err != nil {
			return err
		}
		if err := orgEvent(ctx, uc.Services, tx, orgID, saved.Revision, "organization.constraint.created", map[string]any{
			"organization_id": orgID, "constraint_id": saved.ID, "kind": saved.Kind, "revision": saved.Revision,
		}); err != nil {
			return err
		}
		change = &OrgConstraintChange{Constraint: saved, Violations: violations}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return change, nil
}

func (uc *OrgIAMUsecase) UpdateConstraint(ctx context.Context, actor ActorContext, orgID, id int64, in OrgConstraintInput, expected uint64, reason string, expectedPolicy uint64) (*OrgConstraintChange, error) {
	authCtx, err := uc.orgConstraintGuard(ctx, actor, orgID, PermOrgConstraintManage)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	var change *OrgConstraintChange
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		existing, err := uc.IAM.GetConstraint(ctx, tx, authCtx, id)
		if err != nil {
			// A constraint from another tenant is "not found", never "forbidden":
			// 403 would confirm the id exists somewhere else.
			return ErrResourceNotFound
		}
		candidate := &Constraint{
			ID: existing.ID, Kind: existing.Kind, Name: in.Name, RoleIDs: in.RoleIDs,
			MaxCount: in.MaxCount, Enabled: in.Enabled, Context: authCtx,
			Revision: existing.Revision,
		}
		if err := validateConstraint(candidate); err != nil {
			return err
		}
		if err := uc.validateConstraintRoles(ctx, tx, authCtx, candidate.RoleIDs); err != nil {
			return err
		}
		violations, err := uc.countViolations(ctx, tx, authCtx, candidate)
		if err != nil {
			return err
		}
		if violations > 0 && !in.AcknowledgeViolations {
			return ConflictCode("ORGANIZATION_POLICY_VIOLATIONS_PENDING",
				"该约束会使现有授权失效，请确认后再保存")
		}
		saved, err := uc.IAM.UpdateConstraint(ctx, tx, candidate, expected)
		if err != nil {
			return err
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.constraint.updated", itoa(saved.ID), reason); err != nil {
			return err
		}
		if err := orgEvent(ctx, uc.Services, tx, orgID, saved.Revision, "organization.constraint.updated", map[string]any{
			"organization_id": orgID, "constraint_id": saved.ID, "kind": saved.Kind, "revision": saved.Revision,
		}); err != nil {
			return err
		}
		change = &OrgConstraintChange{Constraint: saved, Violations: violations}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return change, nil
}

func (uc *OrgIAMUsecase) DeleteConstraint(ctx context.Context, actor ActorContext, orgID, id int64, expected uint64, reason string, expectedPolicy uint64) error {
	authCtx, err := uc.orgConstraintGuard(ctx, actor, orgID, PermOrgConstraintManage)
	if err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		existing, err := uc.IAM.GetConstraint(ctx, tx, authCtx, id)
		if err != nil {
			return ErrResourceNotFound
		}
		if expected == 0 || existing.Revision != expected {
			return ConflictRevision(existing.Revision)
		}
		if err := uc.IAM.DeleteConstraint(ctx, tx, id); err != nil {
			return ErrDependency
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.constraint.deleted", itoa(id), reason); err != nil {
			return err
		}
		return orgEvent(ctx, uc.Services, tx, orgID, 0, "organization.constraint.deleted", map[string]any{
			"organization_id": orgID, "constraint_id": id,
		})
	})
}

// validateConstraintRoles enforces that every referenced role belongs to the
// same context and is still assignable. Both halves matter: a cross-context
// reference would let a tenant write rules over platform roles, and an archived
// role would leave the constraint permanently inert.
func (uc *OrgIAMUsecase) validateConstraintRoles(ctx context.Context, tx Tx, authCtx authorization.Context, roleIDs []int64) error {
	if len(roleIDs) == 0 {
		return nil
	}
	roles, err := uc.OrgIAM.ListRoles(ctx, tx, authCtx)
	if err != nil {
		return ErrDependency
	}
	byID := make(map[int64]*Role, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
	}
	for _, id := range roleIDs {
		role, ok := byID[id]
		if !ok {
			// Either it does not exist or it belongs to another context; both are
			// reported the same way so the caller cannot probe for platform ids.
			return Validation("角色不属于本组织")
		}
		if role.Status != RoleStatusActive {
			return Validation("不能引用已归档的角色")
		}
	}
	return nil
}

// countViolations reports how many existing assignees the constraint would
// reject. It is computed before the write so the caller can be asked to
// acknowledge the consequence rather than discover it from user complaints.
//
// Each member is evaluated against the candidate constraint alone: the question
// is how many people THIS rule rejects, not the combined verdict of every rule
// already in place. Counting the combined verdict would over-report whenever a
// member is already in violation of something else.
func (uc *OrgIAMUsecase) countViolations(ctx context.Context, tx Tx, authCtx authorization.Context, c *Constraint) (int64, error) {
	if !c.Enabled {
		return 0, nil
	}
	// tx, not nil: the caller already holds this transaction's connection, and
	// the dev profile runs max_open_conns=1. Borrowing a second connection here
	// waits for the pool to release the one the same goroutine is holding, so
	// every constraint write timed out under load.
	members, err := uc.Organizations.ListMembers(ctx, tx, orgIDOf(authCtx))
	if err != nil {
		return 0, ErrDependency
	}
	roles, err := uc.OrgIAM.ListRoles(ctx, tx, authCtx)
	if err != nil {
		return 0, ErrDependency
	}
	byID := make(map[int64]*Role, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
	}
	now := uc.Clock.Now()
	var violations int64
	for _, m := range members {
		if m.Status != OrgMemberActive {
			continue
		}
		items, err := uc.OrgIAM.ListAssignments(ctx, tx, authCtx, m.UserID)
		if err != nil {
			return 0, ErrDependency
		}
		held := make([]int64, 0, len(items))
		for _, item := range items {
			// Only assignments that actually confer the role count. Counting
			// revoked or expired history would report violations for members who
			// hold nothing, and the acknowledgement prompt would be a lie.
			if !assignmentHolds(item.Assignment, byID, now) {
				continue
			}
			held = append(held, item.Assignment.RoleID)
		}
		if CheckConstraints(held, []*Constraint{c}) != nil {
			violations++
		}
	}
	return violations, nil
}

func orgIDOf(c authorization.Context) int64 {
	c = c.Normalize()
	if c.IsOrganization() {
		return c.OrganizationID
	}
	return 0
}

// assignmentHolds reports whether an assignment actually confers its role at
// `now`: not revoked, already started, not yet expired, and pointing at a role
// that is still active within the same context.
//
// Every segregation-of-duties path must use this same predicate. The previous
// three copies each stopped at `Revoked`, so an assignment that had naturally
// expired still counted as held: granting the other half of a mutually
// exclusive pair was refused forever, and a member whose only "conflict" was
// years-old history was locked out of the whole organization.
func assignmentHolds(a *Assignment, roles map[int64]*Role, now time.Time) bool {
	if a == nil || !a.Active(now) {
		return false
	}
	if role, ok := roles[a.RoleID]; ok && role != nil && role.Status != RoleStatusActive {
		return false
	}
	return true
}

// orgPolicyGuard mirrors IAMUsecase.policyGuard. It is duplicated rather than
// shared because the two usecases do not embed each other; the behaviour must
// stay identical, and the test below pins both.
func (uc *OrgIAMUsecase) orgPolicyGuard(ctx context.Context, tx Tx, expected uint64) (uint64, error) {
	current, err := uc.Policy.PolicyRevision(ctx, tx)
	if err != nil {
		return 0, ErrDependency
	}
	if expected == 0 {
		return current, Validation("expected_policy_revision 必须为正整数")
	}
	if expected != current {
		return current, ConflictPolicy(current)
	}
	return current, nil
}

// orgBumpPolicy advances the policy revision and emits the same
// authorization.changed event the platform path does, so consumers that
// invalidate cached decisions see tenant policy changes too.
func (uc *OrgIAMUsecase) orgBumpPolicy(ctx context.Context, tx Tx) error {
	revision, err := uc.Policy.BumpPolicyRevision(ctx, tx)
	if err != nil {
		return err
	}
	return uc.emit(ctx, tx, "policy", 1, revision, "authorization.changed",
		string(mustJSON(map[string]string{"policy_revision": fmt.Sprint(revision)})))
}
