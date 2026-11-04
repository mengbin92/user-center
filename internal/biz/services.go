package biz

import (
	"time"
)

// Services is the shared dependency set for the user-center usecases. It is
// assembled once by Wire; no usecase opens its own storage client.
type Services struct {
	Users              UserRepo
	Credentials        CredentialRepo
	Identities         ExternalIdentityRepo
	MFA                MFARepo
	Sessions           SessionRepo
	Events             SecurityEventRepo
	Flows              FlowCompletionRepo
	Challenges         ChallengeStore
	Limiter            RateLimiter
	StepUp             StepUpStore
	Mail               MailSender
	Audit              AuditRepo
	Policy             PolicyRepo
	IAM                IAMRepo
	Outbox             OutboxRepo
	IntegrationClients IntegrationClientRepo
	OIDCClients        OIDCClientRepo
	OIDCCodes          OIDCCodeRepo
	OIDCConsents       OIDCConsentRepo
	OIDCSigner         OIDCSigner
	OIDCIssuer         string
	OIDCAccessTTL      time.Duration
	OIDCRefreshTTL     time.Duration
	Organizations      OrganizationRepo
	OrgIAM             OrgIAMRepo
	Settings           SettingsRepo
	Exports            ExportRepo
	Tx                 TxManager
	Clock              Clock
	IDs                IDGenerator
	Secrets            SecretBox
	OAuth              map[string]OAuthProvider

	SessionTTL       time.Duration
	IdleTimeout      time.Duration
	StepUpTTL        time.Duration
	ChallengeTTL     time.Duration
	ResetTTL         time.Duration
	ActivationTTL    time.Duration
	ArtifactDir      string
	PublicBaseURL    string
	CodeSecret       string
	MaxLoginAttempts int
	// OrgInvitationTTL is how long an invitation token stays valid.
	OrgInvitationTTL time.Duration
}

type AuthUsecase struct{ *Services }
type UserUsecase struct{ *Services }
type SecurityUsecase struct{ *Services }
type SessionUsecase struct{ *Services }
type IAMUsecase struct{ *Services }
type AuditUsecase struct{ *Services }
type SettingsUsecase struct{ *Services }
type IntegrationUsecase struct{ *Services }
type IntegrationAdminUsecase struct{ *Services }
type OrganizationUsecase struct{ *Services }
type OrgIAMUsecase struct{ *Services }

func NewAuthUsecase(s *Services) *AuthUsecase               { return &AuthUsecase{Services: s} }
func NewUserUsecase(s *Services) *UserUsecase               { return &UserUsecase{Services: s} }
func NewSecurityUsecase(s *Services) *SecurityUsecase       { return &SecurityUsecase{Services: s} }
func NewSessionUsecase(s *Services) *SessionUsecase         { return &SessionUsecase{Services: s} }
func NewIAMUsecase(s *Services) *IAMUsecase                 { return &IAMUsecase{Services: s} }
func NewAuditUsecase(s *Services) *AuditUsecase             { return &AuditUsecase{Services: s} }
func NewSettingsUsecase(s *Services) *SettingsUsecase       { return &SettingsUsecase{Services: s} }
func NewIntegrationUsecase(s *Services) *IntegrationUsecase { return &IntegrationUsecase{Services: s} }
func NewIntegrationAdminUsecase(s *Services) *IntegrationAdminUsecase {
	return &IntegrationAdminUsecase{Services: s}
}

func NewOrganizationUsecase(s *Services) *OrganizationUsecase {
	return &OrganizationUsecase{Services: s}
}

func NewOrgIAMUsecase(s *Services) *OrgIAMUsecase { return &OrgIAMUsecase{Services: s} }

type RuntimeConfig struct {
	OIDCIssuer       string
	OIDCAccessTTL    time.Duration
	OIDCRefreshTTL   time.Duration
	SessionTTL       time.Duration
	IdleTimeout      time.Duration
	StepUpTTL        time.Duration
	ChallengeTTL     time.Duration
	ResetTTL         time.Duration
	ActivationTTL    time.Duration
	ArtifactDir      string
	PublicBaseURL    string
	CodeSecret       string
	MaxLoginAttempts int
	// OrgInvitationTTL is how long an invitation token stays valid.
	OrgInvitationTTL time.Duration
}

// NewServices assembles the shared usecase dependency graph.

func NewServices(
	users UserRepo, credentials CredentialRepo, identities ExternalIdentityRepo,
	mfa MFARepo, sessions SessionRepo, events SecurityEventRepo, flows FlowCompletionRepo,
	challenges ChallengeStore, limiter RateLimiter, stepUp StepUpStore, mail MailSender,
	audit AuditRepo, policy PolicyRepo, iam IAMRepo, outbox OutboxRepo,
	settings SettingsRepo, exports ExportRepo, integrationClients IntegrationClientRepo,
	oidcClients OIDCClientRepo, oidcCodes OIDCCodeRepo, oidcConsents OIDCConsentRepo, oidcSigner OIDCSigner,
	organizations OrganizationRepo, orgIAM OrgIAMRepo, tx TxManager, clock Clock, ids IDGenerator, secrets SecretBox,
	oauth map[string]OAuthProvider, cfg *RuntimeConfig,
) *Services {
	s := &Services{
		Users: users, Credentials: credentials, Identities: identities, MFA: mfa,
		Sessions: sessions, Events: events, Flows: flows, Challenges: challenges,
		Limiter: limiter, StepUp: stepUp, Mail: mail, Audit: audit, Policy: policy,
		IAM: iam, Outbox: outbox, Settings: settings, Exports: exports,
		IntegrationClients: integrationClients, OIDCClients: oidcClients,
		OIDCCodes: oidcCodes, OIDCConsents: oidcConsents, OIDCSigner: oidcSigner, Organizations: organizations,
		OrgIAM: orgIAM, Tx: tx,
		Clock: clock, IDs: ids, Secrets: secrets, OAuth: oauth,
		SessionTTL: 12 * time.Hour, IdleTimeout: time.Hour, StepUpTTL: 5 * time.Minute,
		ChallengeTTL: 10 * time.Minute, ResetTTL: 30 * time.Minute,
		ActivationTTL: 24 * time.Hour, MaxLoginAttempts: 10, OrgInvitationTTL: 72 * time.Hour,
		ArtifactDir: "artifacts", PublicBaseURL: "http://localhost:5173",
	}
	if cfg != nil {
		if cfg.SessionTTL > 0 {
			s.SessionTTL = cfg.SessionTTL
		}
		if cfg.IdleTimeout > 0 {
			s.IdleTimeout = cfg.IdleTimeout
		}
		if cfg.StepUpTTL > 0 {
			s.StepUpTTL = cfg.StepUpTTL
		}
		if cfg.ChallengeTTL > 0 {
			s.ChallengeTTL = cfg.ChallengeTTL
		}
		if cfg.ResetTTL > 0 {
			s.ResetTTL = cfg.ResetTTL
		}
		if cfg.ActivationTTL > 0 {
			s.ActivationTTL = cfg.ActivationTTL
		}
		if cfg.ArtifactDir != "" {
			s.ArtifactDir = cfg.ArtifactDir
		}
		if cfg.PublicBaseURL != "" {
			s.PublicBaseURL = cfg.PublicBaseURL
		}
		if cfg.CodeSecret != "" {
			s.CodeSecret = cfg.CodeSecret
		}
		if cfg.MaxLoginAttempts > 0 {
			s.MaxLoginAttempts = cfg.MaxLoginAttempts
		}
		if cfg.OrgInvitationTTL > 0 {
			s.OrgInvitationTTL = cfg.OrgInvitationTTL
		}
		s.OIDCIssuer = cfg.OIDCIssuer
		if cfg.OIDCAccessTTL > 0 {
			s.OIDCAccessTTL = cfg.OIDCAccessTTL
		}
		if cfg.OIDCRefreshTTL > 0 {
			s.OIDCRefreshTTL = cfg.OIDCRefreshTTL
		}
	}
	return s
}
