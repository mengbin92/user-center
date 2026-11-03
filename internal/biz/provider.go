package biz

import "github.com/google/wire"

// ProviderSet wires the shared service graph and every usecase.
var ProviderSet = wire.NewSet(
	NewServices,
	NewAuthUsecase,
	NewUserUsecase,
	NewSecurityUsecase,
	NewSessionUsecase,
	NewIAMUsecase,
	NewAuditUsecase,
	NewSettingsUsecase,
	NewIntegrationUsecase,
	NewIntegrationAdminUsecase,
	NewOIDCUsecase,
)
