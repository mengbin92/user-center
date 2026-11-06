package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
)

// Organization-scoped segregation of duties. The mapping layer stays thin on
// purpose: all decisions (context isolation, violation counting, self-grant
// refusal) live in biz, so an HTTP caller and a future gRPC caller cannot
// disagree about what a constraint means.

func orgConstraintProto(c *biz.Constraint, violations int64) *usercv1.OrgConstraint {
	if c == nil {
		return nil
	}
	out := &usercv1.OrgConstraint{
		Id: id(c.ID), Kind: c.Kind, Name: c.Name, MaxCount: c.MaxCount,
		Enabled: c.Enabled, Revision: rev(c.Revision), ViolatingAssignments: violations,
	}
	for _, roleID := range c.RoleIDs {
		out.RoleIds = append(out.RoleIds, id(roleID))
	}
	return out
}

func (s *OrganizationService) ListOrgConstraints(ctx context.Context, req *usercv1.GetOrganizationRequest) (*usercv1.OrgConstraintsReply, error) {
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	items, err := s.iam.Constraints(ctx, actor, orgID)
	if err != nil {
		return nil, err
	}
	out := &usercv1.OrgConstraintsReply{}
	for _, c := range items {
		out.Items = append(out.Items, orgConstraintProto(c, 0))
	}
	return out, nil
}

func (s *OrganizationService) CreateOrgConstraint(ctx context.Context, req *usercv1.CreateOrgConstraintRequest) (*usercv1.OrgConstraint, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	roleIDs, err := parseIDs(req.GetRoleIds(), "role_id")
	if err != nil {
		return nil, err
	}
	expectedPolicy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	change, err := s.iam.CreateConstraint(ctx, actor, orgID, biz.OrgConstraintInput{
		Kind: req.GetKind(), Name: req.GetName(), RoleIDs: roleIDs,
		MaxCount: req.GetMaxCount(), Enabled: req.GetEnabled(),
		AcknowledgeViolations: req.GetAcknowledgeViolations(),
	}, auditReason, expectedPolicy)
	if err != nil {
		return nil, err
	}
	return orgConstraintProto(change.Constraint, change.Violations), nil
}

func (s *OrganizationService) UpdateOrgConstraint(ctx context.Context, req *usercv1.UpdateOrgConstraintRequest) (*usercv1.OrgConstraint, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	constraintID, err := parseIDField(req.GetConstraintId(), "constraint_id")
	if err != nil {
		return nil, err
	}
	roleIDs, err := parseIDs(req.GetRoleIds(), "role_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	expectedPolicy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	change, err := s.iam.UpdateConstraint(ctx, actor, orgID, constraintID, biz.OrgConstraintInput{
		Name: req.GetName(), RoleIDs: roleIDs, MaxCount: req.GetMaxCount(),
		Enabled: req.GetEnabled(), AcknowledgeViolations: req.GetAcknowledgeViolations(),
	}, expected, auditReason, expectedPolicy)
	if err != nil {
		return nil, err
	}
	return orgConstraintProto(change.Constraint, change.Violations), nil
}

func (s *OrganizationService) DeleteOrgConstraint(ctx context.Context, req *usercv1.DeleteOrgConstraintRequest) (*emptypb.Empty, error) {
	auditReason, reasonErr := requireReason(req.GetReason())
	if reasonErr != nil {
		return nil, reasonErr
	}
	actor, err := requireActorMeta(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := parseIDField(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	constraintID, err := parseIDField(req.GetConstraintId(), "constraint_id")
	if err != nil {
		return nil, err
	}
	expected, err := parseRevisionField(req.GetExpectedRevision(), "expected_revision")
	if err != nil {
		return nil, err
	}
	expectedPolicy, err := parseRevisionField(req.GetExpectedPolicyRevision(), "expected_policy_revision")
	if err != nil {
		return nil, err
	}
	if err := s.iam.DeleteConstraint(ctx, actor, orgID, constraintID, expected, auditReason, expectedPolicy); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
