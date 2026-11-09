package biz

import (
	"context"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
)

// Organization-scoped delegation writes.
//
// V2.5 shipped the delegation *evaluator* (checkOrgDelegation) and the
// context-aware storage, but no product entry point could ever create a row
// with context_type='organization'. Tests had to inject one straight through
// the platform usecase. In production Branch 2 of checkOrgDelegation was
// therefore always empty, and an org manager could only grant capabilities he
// already held. This file supplies the missing CRUD without widening that
// evaluator by a single rule.
//
// Three invariants are load-bearing and are enforced on every write:
//
//  1. The path organization is the only tenant selector. The wire message has
//     no context field, so a caller cannot address the platform or another
//     tenant by putting an id in the body.
//  2. Both roles belong to this organization and are active (design §3.2).
//     Design §9 additionally asked for the manager role to be in the issuer's
//     own active role set, but that check belongs to the evaluator and is
//     already there (checkOrgDelegation Branch 2). Repeating it on the write
//     side would make the feature unusable: an owner cannot self-assign a
//     custom role, so the only manager role available to him would be the
//     built-in org_owner -- which already holds every organization capability
//     and therefore always satisfies Branch 1. See design §14, F10.
//  3. The grant ceiling is bounded by the caller's own capabilities inside
//     this tenant. Otherwise a delegation would be a way to write a ceiling
//     containing platform operations or authority the caller never had.
//
// Reads and writes reuse the constraint governance permissions (design §5.1):
// read is owner + admin, every write is owner-only. orgConstraintGuard also
// gives platform administrators no entry point at all (D7).

// OrgDelegationInput is the mutable part of a delegation. Manager/target roles
// are immutable after creation: changing them would turn an existing
// delegation into a different authorization without a re-review.
type OrgDelegationInput struct {
	Actions         []string
	TargetUserScope authorization.Scope
	GrantCeiling    []DelegationCeiling
	StartsAt        time.Time
	ExpiresAt       *time.Time
}

// OrgDelegations lists delegations in exactly one tenant. A foreign id or a
// platform delegation is invisible, not "forbidden".
func (uc *OrgIAMUsecase) OrgDelegations(ctx context.Context, actor ActorContext, orgID int64, status string) ([]*Delegation, error) {
	authCtx, err := uc.orgConstraintGuard(ctx, actor, orgID, PermOrgConstraintRead)
	if err != nil {
		return nil, err
	}
	items, err := uc.IAM.ListDelegations(ctx, nil, DelegationFilter{Status: status, Context: authCtx})
	if err != nil {
		return nil, ErrDependency
	}
	return items, nil
}

func (uc *OrgIAMUsecase) CreateOrgDelegation(
	ctx context.Context, actor ActorContext, orgID, managerRoleID, targetRoleID int64,
	in OrgDelegationInput, reason string, expectedPolicy uint64,
) (*Delegation, error) {
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
	candidate := &Delegation{
		ManagerRoleID: managerRoleID, TargetRoleID: targetRoleID,
		Actions: in.Actions, TargetUserScope: in.TargetUserScope,
		GrantCeiling: in.GrantCeiling, StartsAt: in.StartsAt, ExpiresAt: in.ExpiresAt,
		CreatedBy: actor.User.ID, Context: authCtx,
	}
	if err := validateDelegation(candidate); err != nil {
		return nil, err
	}
	var created *Delegation
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		if err := uc.validateOrgDelegationAuthority(ctx, tx, authCtx, actor, candidate); err != nil {
			return err
		}
		c, err := uc.IAM.CreateDelegation(ctx, tx, candidate)
		if err != nil {
			return ErrDependency
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.delegation.created", itoa(c.ID), reason); err != nil {
			return err
		}
		if err := orgEvent(ctx, uc.Services, tx, orgID, c.Revision, "organization.delegation.created", map[string]any{
			"organization_id": orgID, "delegation_id": c.ID,
			"manager_role_id": c.ManagerRoleID, "target_role_id": c.TargetRoleID,
			"revision": c.Revision,
		}); err != nil {
			return err
		}
		created = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (uc *OrgIAMUsecase) UpdateOrgDelegation(
	ctx context.Context, actor ActorContext, orgID, id int64,
	in OrgDelegationInput, expected uint64, reason string, expectedPolicy uint64,
) (*Delegation, error) {
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
	var updated *Delegation
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		existing, err := uc.orgDelegationInTx(ctx, tx, authCtx, id)
		if err != nil {
			return err
		}
		if expected == 0 || existing.Revision != expected {
			return ConflictRevision(existing.Revision)
		}
		candidate := *existing
		candidate.Actions = in.Actions
		candidate.TargetUserScope = in.TargetUserScope
		candidate.GrantCeiling = in.GrantCeiling
		if !in.StartsAt.IsZero() {
			candidate.StartsAt = in.StartsAt
		}
		candidate.ExpiresAt = in.ExpiresAt
		candidate.CanRedelegate = false
		if err := validateDelegation(&candidate); err != nil {
			return err
		}
		if err := uc.validateOrgDelegationAuthority(ctx, tx, authCtx, actor, &candidate); err != nil {
			return err
		}
		u, err := uc.IAM.UpdateDelegation(ctx, tx, &candidate, expected)
		if err != nil {
			return err
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.delegation.updated", itoa(id), reason); err != nil {
			return err
		}
		if err := orgEvent(ctx, uc.Services, tx, orgID, u.Revision, "organization.delegation.updated", map[string]any{
			"organization_id": orgID, "delegation_id": id, "revision": u.Revision,
		}); err != nil {
			return err
		}
		updated = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (uc *OrgIAMUsecase) RevokeOrgDelegation(
	ctx context.Context, actor ActorContext, orgID, id int64,
	expected uint64, reason string, expectedPolicy uint64,
) (*Delegation, error) {
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
	var revoked *Delegation
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.orgPolicyGuard(ctx, tx, expectedPolicy); err != nil {
			return err
		}
		existing, err := uc.orgDelegationInTx(ctx, tx, authCtx, id)
		if err != nil {
			return err
		}
		if expected == 0 || existing.Revision != expected {
			return ConflictRevision(existing.Revision)
		}
		if existing.RevokedAt != nil {
			return Validation("委派已撤销")
		}
		if err := uc.IAM.RevokeDelegation(ctx, tx, id, expected, actor.User.ID, authCtx); err != nil {
			return err
		}
		if err := uc.orgBumpPolicy(ctx, tx); err != nil {
			return err
		}
		if err := uc.auditOrg(ctx, tx, actor, orgID, "organization.delegation.revoked", itoa(id), reason); err != nil {
			return err
		}
		if err := orgEvent(ctx, uc.Services, tx, orgID, expected+1, "organization.delegation.revoked", map[string]any{
			"organization_id": orgID, "delegation_id": id, "revision": expected + 1,
		}); err != nil {
			return err
		}
		revoked = existing
		revoked.RevokedAt = ptrTime(uc.Clock.Now().UTC())
		revoked.Revision = expected + 1
		return nil
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

// orgDelegationInTx loads a delegation through the context-scoped query.
// IAMRepo.GetDelegation is intentionally context-free (the platform read path
// uses it), so calling it here would let a guessed id from another tenant be
// edited. A foreign id resolves to "not found", never "forbidden".
func (uc *OrgIAMUsecase) orgDelegationInTx(ctx context.Context, tx Tx, authCtx authorization.Context, id int64) (*Delegation, error) {
	items, err := uc.IAM.ListDelegations(ctx, tx, DelegationFilter{Context: authCtx})
	if err != nil {
		return nil, ErrDependency
	}
	for _, d := range items {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, ErrResourceNotFound
}

// validateOrgDelegationAuthority is the write-side counterpart of
// checkOrgDelegation's Branch 2. It runs in the same transaction as the write,
// against the same snapshot, so a role revoked concurrently cannot be used to
// mint a delegation.
func (uc *OrgIAMUsecase) validateOrgDelegationAuthority(
	ctx context.Context, tx Tx, authCtx authorization.Context, actor ActorContext, d *Delegation,
) error {
	if err := uc.validateConstraintRoles(ctx, tx, authCtx, []int64{d.ManagerRoleID, d.TargetRoleID}); err != nil {
		return err
	}
	roles, err := uc.OrgIAM.ListRoles(ctx, tx, authCtx)
	if err != nil {
		return ErrDependency
	}
	byID := make(map[int64]*Role, len(roles))
	edges := make(map[int64][]int64, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
		edges[r.ID] = r.Inherits
	}
	assignments, err := uc.OrgIAM.ListAssignments(ctx, tx, authCtx, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	now := uc.Clock.Now()
	actorRoleIDs := make([]int64, 0, len(assignments))
	for _, item := range assignments {
		if assignmentHolds(item.Assignment, byID, now) {
			actorRoleIDs = append(actorRoleIDs, item.Assignment.RoleID)
		}
	}
	// The manager role is NOT required to be one of actorRoleIDs here. Whoever
	// later uses the delegation must actually hold it -- checkOrgDelegation
	// checks that on every assignment write -- but the issuer (an owner) is
	// granting a capability to a role, not claiming to hold that role himself.
	held := orgRoleOperations(actorRoleIDs, byID, edges, authCtx)
	ceiling := make(map[string]authorization.Scope, len(d.GrantCeiling))
	for _, c := range d.GrantCeiling {
		if prev, ok := ceiling[c.Operation]; ok {
			ceiling[c.Operation] = widestScope(prev, c.Scope)
			continue
		}
		ceiling[c.Operation] = c.Scope
	}
	if !coversOperations(held, ceiling) {
		return Validation("委派上限不能超出你在本组织持有的权限")
	}
	return nil
}
