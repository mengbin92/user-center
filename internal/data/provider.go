package data

import (
	"github.com/google/wire"

	"github.com/mengbin92/user-center/internal/biz"
)

// ProviderSet wires every repository against the shared Data clients.
var ProviderSet = wire.NewSet(
	NewData,
	wire.Struct(new(Clock)),
	wire.Struct(new(IDs)),
	NewSecretBox,
	wire.Bind(new(biz.Clock), new(*Clock)),
	wire.Bind(new(biz.IDGenerator), new(*IDs)),
	wire.Bind(new(biz.TxManager), new(*Data)),
	wire.Bind(new(biz.SecretBox), new(*SecretBox)),
	NewChallengeStore,
	NewRateLimiter,
	NewStepUpStore,
	NewMailSender,
	NewUserRepo,
	NewCredentialRepo,
	NewExternalIdentityRepo,
	NewMFARepo,
	NewSessionRepo,
	NewSecurityEventRepo,
	NewFlowCompletionRepo,
	NewAuditRepo,
	NewPolicyRepo,
	NewIAMRepo,
	NewOutboxRepo,
	NewSettingsRepo,
	NewExportRepo,
	NewIntegrationClientRepo,
	NewOIDCClientRepo,
	NewOIDCCodeRepo,
	NewOIDCSigner,
	NewOAuthRegistry,
)
