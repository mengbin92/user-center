package biz

import (
	"context"
	"errors"
)

// A primary proof is deliberately separate from a full step-up proof: an
// external identity recheck must not silently satisfy an enabled MFA factor.
func primaryProofKey(session *Session) string { return "primary:" + StepUpKey(session) }

func (s *Services) requirePrimaryProof(ctx context.Context, actor ActorContext) error {
	if actor.Session == nil {
		return ErrUnauthenticated
	}
	until, err := s.StepUp.Get(ctx, primaryProofKey(actor.Session))
	if err != nil {
		return ErrDependency
	}
	if until.IsZero() || !s.Clock.Now().Before(until) {
		return ErrStepUpRequired
	}
	return nil
}

func (s *Services) confirmPrimaryAuthentication(ctx context.Context, actor ActorContext, password string) error {
	credential, err := s.Credentials.Get(ctx, nil, actor.User.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return ErrDependency
	}
	if credential == nil || credential.PasswordHash == "" {
		return s.requirePrimaryProof(ctx, actor)
	}
	if !VerifyPassword(credential.PasswordHash, password) {
		return Validation("当前密码不正确")
	}
	return nil
}
