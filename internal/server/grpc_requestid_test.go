package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/mengbin92/user-center/internal/biz"
)

func TestRequestIDInterceptorReusesIncomingHeader(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-request-id", "grpc-req-1"))

	var seen string
	_, err := requestIDInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(ctx context.Context, _ any) (any, error) {
			seen = biz.RequestID(ctx)
			return nil, nil
		})
	require.NoError(t, err)
	require.Equal(t, "grpc-req-1", seen, "the audit row must carry the caller's id")
}

func TestRequestIDInterceptorGeneratesWhenMissingOrOversized(t *testing.T) {
	cases := map[string]string{
		"missing": "",
		"empty":   "   ",
		"huge":    "0123456789012345678901234567890123456789012345678901234567890123456789",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if header != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-request-id", header))
			}
			var seen string
			_, err := requestIDInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"},
				func(ctx context.Context, _ any) (any, error) {
					seen = biz.RequestID(ctx)
					return nil, nil
				})
			require.NoError(t, err)
			require.NotEmpty(t, seen)
			require.LessOrEqual(t, len(seen), 64)
			require.NotEqual(t, header, seen)
		})
	}
}
