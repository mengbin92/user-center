package biz

import "context"

type integrationClientKey struct{}

// WithIntegrationClient is populated only after machine authentication.
func WithIntegrationClient(ctx context.Context, client *IntegrationClient) context.Context {
	return context.WithValue(ctx, integrationClientKey{}, client)
}

func integrationClientFromContext(ctx context.Context) (*IntegrationClient, error) {
	client, ok := ctx.Value(integrationClientKey{}).(*IntegrationClient)
	if !ok || client == nil {
		return nil, ErrUnauthenticated
	}
	return client, nil
}
