// Package tenant carries the resolved organization id through a request so the
// data layer can pick the physical schema without any layer above it knowing
// about connection pools. It is a pure transport type: no storage, no GORM.
package tenant

import (
	"context"
	"strconv"
	"strings"
)

type contextKey struct{}

// With binds a request to one organization. A zero id means "platform scope",
// which always uses the platform schema.
func With(ctx context.Context, organizationID int64) context.Context {
	return context.WithValue(ctx, contextKey{}, organizationID)
}

func From(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	if v, ok := ctx.Value(contextKey{}).(int64); ok {
		return v
	}
	return 0
}

// FromPath extracts the organization id from an /api/v1/orgs/{id}/... path.
// It is deliberately strict: a malformed or negative id resolves to platform
// scope, and the authorization layer still has to reject the request.
func FromPath(path string) int64 {
	rest, ok := strings.CutPrefix(path, "/api/v1/orgs/")
	if !ok {
		return 0
	}
	raw, _, _ := strings.Cut(rest, "/")
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
