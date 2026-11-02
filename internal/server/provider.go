package server

import "github.com/google/wire"

var ProviderSet = wire.NewSet(
	NewMiddleware,
	NewHTTPServer,
	NewGRPCServer,
	NewArtifactDir,
	NewIntegrationToken,
)
