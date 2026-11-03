package server

import (
	"context"
	"strings"
	"time"

	kgrpc "github.com/go-kratos/kratos/v3/transport/grpc"
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
		kgrpc.Options(grpc.ChainUnaryInterceptor(integrationAuth(integration.Usecase()))),
	)
	usercv1.RegisterIntegrationServiceServer(srv, integration)
	return &GRPCServer{Server: srv}
}

func integrationAuth(uc *biz.IntegrationUsecase) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasPrefix(info.FullMethod, "/api.usercenter.v1.IntegrationService/") {
			return handler(ctx, req)
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
