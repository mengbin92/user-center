package server

import (
	"context"
	"os"
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

// IntegrationToken is a named Wire provider for the internal gRPC credential.
type IntegrationToken string

func NewIntegrationToken() IntegrationToken {
	return IntegrationToken(os.Getenv("USER_CENTER_INTEGRATION_TOKEN"))
}

func NewGRPCServer(cfg *conf.Server, integrationToken IntegrationToken, log *zap.Logger, integration *service.IntegrationService) *GRPCServer {
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
		kgrpc.Options(grpc.ChainUnaryInterceptor(integrationAuth(string(integrationToken), integration.Usecase()))),
	)
	usercv1.RegisterIntegrationServiceServer(srv, integration)
	return &GRPCServer{Server: srv}
}

func integrationAuth(staticToken string, uc *biz.IntegrationUsecase) grpc.UnaryServerInterceptor {
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
		raw = strings.TrimPrefix(raw, "Bearer ")
		if staticToken != "" && raw == staticToken {
			return handler(ctx, req)
		}
		client, err := uc.AuthenticateClient(ctx, raw)
		if err != nil {
			return nil, biz.ErrUnauthenticated
		}
		if !uc.AllowedMethod(client, info.FullMethod) {
			return nil, biz.ErrPermissionDenied
		}
		return handler(ctx, req)
	}
}
