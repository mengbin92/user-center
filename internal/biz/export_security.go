package biz

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

type exportAuthority struct {
	PolicyRevision  uint64    `json:"policy_revision"`
	SessionRevision uint64    `json:"session_revision"`
	ValidUntil      time.Time `json:"valid_until"`
}

func (s *Services) exportSnapshot(ctx context.Context, actor ActorContext) (string, error) {
	policy, err := s.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return "", ErrDependency
	}
	until := actor.Session.ExpiresAt
	assignments, err := s.IAM.ListAssignmentsForUser(ctx, nil, actor.User.ID)
	if err != nil {
		return "", ErrDependency
	}
	now := s.Clock.Now()
	for _, assignment := range assignments {
		if assignment.Revoked {
			continue
		}
		if assignment.StartsAt.After(now) && assignment.StartsAt.Before(until) {
			until = assignment.StartsAt
		}
		if assignment.ExpiresAt != nil && assignment.ExpiresAt.After(now) && assignment.ExpiresAt.Before(until) {
			until = *assignment.ExpiresAt
		}
	}
	data, err := jsonx.Marshal(exportAuthority{PolicyRevision: policy, SessionRevision: actor.Session.Revision, ValidUntil: until})
	if err != nil {
		return "", ErrDependency
	}
	return string(data), nil
}

func (uc *UserUsecase) authorizeExport(ctx context.Context, actor ActorContext, job *ExportJob) error {
	if !uc.Clock.Now().Before(job.ExpiresAt) {
		return ErrResourceNotFound
	}
	var authority exportAuthority
	if jsonx.Unmarshal([]byte(job.ScopeSnapshot), &authority) != nil || authority.PolicyRevision == 0 {
		return ErrPermissionDenied
	}
	policy, err := uc.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return ErrDependency
	}
	if policy != authority.PolicyRevision || actor.Session.Revision != authority.SessionRevision || !uc.Clock.Now().Before(authority.ValidUntil) {
		return ErrPermissionDenied
	}
	switch job.Kind {
	case "users":
		if _, err := uc.ListScope(ctx, actor, "identity.user.export"); err != nil {
			return err
		}
		// Contact scope is covered by the unchanged policy and session snapshot;
		// still require a current contact grant when sensitive fields are present.
		if slices.Contains(job.RequestedFields, "email") || slices.Contains(job.RequestedFields, "email_verified") {
			if _, err := uc.ListScope(ctx, actor, "identity.user.contact.read"); err != nil {
				return err
			}
		}
	case "audits":
		if _, err := uc.Authorize(ctx, actor, "audit.export", 0, true); err != nil {
			return err
		}
	default:
		return ErrResourceNotFound
	}
	return nil
}

func csvSafeRow(row []string) []string {
	for i, value := range row {
		// Quoting CSV cells does not prevent spreadsheet formula execution.
		trimmed := strings.TrimLeft(value, " \t\r\n")
		if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") || (len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
			row[i] = "'" + value
		}
	}
	return row
}
