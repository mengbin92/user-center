package server

import (
	"context"
	"strings"
	"time"

	kgrpc "github.com/go-kratos/kratos/v3/transport/grpc"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	usercv1 "github.com/mengbin92/user-center/api/usercenter/v1"
	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/service"
)

type GRPCServer struct {
	*kgrpc.Server
}

func NewGRPCServer(cfg *conf.Server, log *zap.Logger, integration *service.IntegrationService) *GRPCServer {
	addr := ":9090"
	timeout := 30
	if cfg != nil && cfg.Grpc != nil {
		if cfg.Grpc.Addr != "" {
			addr = cfg.Grpc.Addr
		}
		if cfg.Grpc.TimeoutSeconds > 0 {
			timeout = int(cfg.Grpc.TimeoutSeconds)
		}
	}
	srv := kgrpc.NewServer(
		kgrpc.Address(addr),
		kgrpc.Timeout(time.Duration(timeout)*time.Second),
		kgrpc.Options(grpc.ChainUnaryInterceptor(requestIDInterceptor(), integrationAuth(integration.Usecase()))),
	)
	usercv1.RegisterIntegrationServiceServer(srv, integration)
	return &GRPCServer{Server: srv}
}

// requestIDInterceptor makes the request id reachable from gRPC handlers and
// the audit rows they write, and echoes it back so the caller can correlate.
// The rules match the HTTP middleware: reuse a sane incoming value, otherwise
// generate one.
func requestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if values := md.Get("x-request-id"); len(values) > 0 {
				id = strings.TrimSpace(values[0])
			}
		}
		if id == "" || len(id) > 64 {
			id = uuid.NewString()
		}
		ctx = biz.WithRequestID(ctx, id)
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", id))
		return handler(ctx, req)
	}
}

func integrationAuth(uc *biz.IntegrationUsecase) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Default deny: only the integration service is exposed here, and a
		// future registration must opt in explicitly instead of inheriting
		// anonymous access.
		if !strings.HasPrefix(info.FullMethod, "/api.usercenter.v1.IntegrationService/") {
			return nil, biz.ErrUnauthenticated
		}
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, biz.ErrUnauthenticated
		}
		raw := strings.TrimSpace(values[0])
		if !strings.HasPrefix(raw, "Bearer ") {
			return nil, biz.ErrUnauthenticated
		}
		raw = strings.TrimPrefix(raw, "Bearer ")
		client, err := uc.AuthenticateClient(ctx, raw)
		if err != nil {
			return nil, biz.ErrUnauthenticated
		}
		if !uc.AllowedMethod(client, info.FullMethod) {
			return nil, biz.ErrPermissionDenied
		}
		reply, err := handler(biz.WithIntegrationClient(ctx, client), req)
		if err != nil {
			return nil, publicError(err)
		}
		return reply, nil
	}
}
