package service

import (
	"context"
	"time"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

// Organization-scoped delegation CRUD. The mapping layer stays thin: every
// tenant boundary, every authority check and every concurrency decision lives
// in biz, exactly as it does for organization constraints.

func orgDelegationProto(d *biz.Delegation) *usercv1.OrgDelegation {
	if d == nil {
		return nil
	}
	out := &usercv1.OrgDelegation{
		Id: id(d.ID), ManagerRoleId: id(d.ManagerRoleID), TargetRoleId: id(d.TargetRoleID),
		TargetKind: d.TargetKind, Actions: d.Actions, TargetUserScope: scopeProto(d.TargetUserScope),
		StartsAt: ts(d.StartsAt), ExpiresAt: tptr(d.ExpiresAt), Revision: rev(d.Revision),
		CreatedBy: id(d.CreatedBy), Revoked: d.RevokedAt != nil, RevokedAt: tptr(d.RevokedAt),
	}
	for _, c := range d.GrantCeiling {
		out.GrantCeiling = append(out.GrantCeiling, &usercv1.DelegationCeiling{
			Operation: c.Operation, Scope: scopeProto(c.Scope),
		})
	}
	return out
}

// orgDelegationInput parses the fields shared by create and update. It mirrors
// the platform delegation mapping so an operator sees the same validation
// messages on both surfaces.
func orgDelegationInput(
	actions []string, scope *usercv1.Scope, ceiling []*usercv1.DelegationCeiling,
	startsAt, expiresAt string,
) (biz.OrgDelegationInput, error) {
	targetScope, err := scopeBiz(scope)
	if err != nil {
		return biz.OrgDelegationInput{}, err
	}
	starts, err := biz.ParseTime(startsAt, "starts_at")
	if err != nil {
		return biz.OrgDelegationInput{}, err
	}
	expires, err := biz.ParseTime(expiresAt, "expires_at")
	if err != nil {
		return biz.OrgDelegationInput{}, err
	}
	var expPtr *time.Time
	if !expires.IsZero() {
		expPtr = &expires
	}
	out := biz.OrgDelegationInput{
		Actions: actions, TargetUserScope: targetScope, StartsAt: starts, ExpiresAt: expPtr,
	}
	for _, c := range ceiling {
		cs, err := scopeBiz(c.GetScope())
		if err != nil {
			return biz.OrgDelegationInput{}, err
		}
		out.GrantCeiling = append(out.GrantCeiling, biz.DelegationCeiling{
			Operation: c.GetOperation(), Scope: cs,
		})
	}
	return out, nil
}

func (s *OrganizationService) ListOrgDelegations(ctx context.Context, req *usercv1.ListOrgDelegationsRequest) (*usercv1.OrgDelegationsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.OrgDelegations(ctx, actor, orgID, req.GetStatus())
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgDelegationsReply{}
	for _, d := range items {
		out.Items = append(out.Items, orgDelegationProto(d))
	}
	return out, nil
}

func (s *OrganizationService) CreateOrgDelegation(ctx context.Context, req *usercv1.CreateOrgDelegationRequest) (*usercv1.OrgDelegation, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	managerID, err := parseIDField(req.GetManagerRoleId(), "manager_role_id")
	if err != nil {
		return nil, err
	}
	targetID, err := parseIDField(req.GetTargetRoleId(), "target_role_id")
	if err != nil {
		return nil, err
	}
	policy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	in, err := orgDelegationInput(req.GetActions(), req.GetTargetUserScope(), req.GetGrantCeiling(),
		req.GetStartsAt(), req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	d, err := s.iam.CreateOrgDelegation(ctx, actor, orgID, managerID, targetID, in, reason, policy)
	if err != nil {
		return nil, err
	}
	return orgDelegationProto(d), nil
}

func (s *OrganizationService) UpdateOrgDelegation(ctx context.Context, req *usercv1.UpdateOrgDelegationRequest) (*usercv1.OrgDelegation, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	delegationID, err := parseIDField(req.GetDelegationId(), "delegation_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	policy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	in, err := orgDelegationInput(req.GetActions(), req.GetTargetUserScope(), req.GetGrantCeiling(),
		req.GetStartsAt(), req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	d, err := s.iam.UpdateOrgDelegation(ctx, actor, orgID, delegationID, in, expected, reason, policy)
	if err != nil {
		return nil, err
	}
	return orgDelegationProto(d), nil
}

func (s *OrganizationService) RevokeOrgDelegation(ctx context.Context, req *usercv1.RevokeOrgDelegationRequest) (*usercv1.OrgDelegation, error) {
	reason, err := requireReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	delegationID, err := parseIDField(req.GetDelegationId(), "delegation_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	policy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	d, err := s.iam.RevokeOrgDelegation(ctx, actor, orgID, delegationID, expected, reason, policy)
	if err != nil {
		return nil, err
	}
	return orgDelegationProto(d), nil
}
