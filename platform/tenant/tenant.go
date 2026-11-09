// Package tenant carries the resolved organization id through a request so the
// data layer can pick the physical schema without any layer above it knowing
// about connection pools. It is a pure transport type: no storage, no GORM.
package tenant

import "context"

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
	const marker = "/api/v1/orgs/"
	start := -1
	for i := 0; i+len(marker) <= len(path); i++ {
		if path[i:i+len(marker)] == marker {
			start = i + len(marker)
			break
		}
	}
	if start < 0 {
		return 0
	}
	rest := path[start:]
	end := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' {
			end = i
			break
		}
	}
	var id int64
	for _, c := range rest[:end] {
		if c < '0' || c > '9' {
			return 0
		}
		id = id*10 + int64(c-'0')
		if id > 1<<62 {
			return 0
		}
	}
	return id
}
