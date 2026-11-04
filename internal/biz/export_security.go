package biz

import (
	"context"
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
