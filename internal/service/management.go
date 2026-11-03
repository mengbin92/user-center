package service

import (
	"context"
	"strings"

	"github.com/mengbin92/user-center/internal/biz"
)

func managementMeta(ctx context.Context, req interface{ GetReason() string }) (biz.ActorContext, error) {
	actor := requestMeta(ctx)
	if strings.TrimSpace(req.GetReason()) == "" {
		return actor, biz.Validation("reason 不能为空")
	}
	if versioned, ok := req.(interface{ GetExpectedRevision() string }); ok {
		revision, err := biz.ParseRevision(versioned.GetExpectedRevision(), "expected_revision")
		if err != nil {
			return actor, err
		}
		actor.ExpectedTargetRevision = revision
	}
	if versioned, ok := req.(interface{ GetExpectedPolicyRevision() string }); ok {
		revision, err := biz.ParseRevision(versioned.GetExpectedPolicyRevision(), "expected_policy_revision")
		if err != nil {
			return actor, err
		}
		actor.ExpectedPolicyRevision = revision
	}
	return actor, nil
}
