package repository

import (
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

type Repository interface {
	APIKey() ApiKeyRepository
	Audit() AuditRepository
	EmailTemplate() EmailTemplateRepository
	IdentityProvider() IdentityProviderRepository
	Membership() MembershipRepository
	MFA() MFARepository
	OAuth() OAuthRepository
	Organization() OrganizationRepository
	OrganizationFeature() OrganizationFeatureRepository
	PassKey() PasskeyRepository
	Role() RoleRepository
	User() UserRepository
	Session() SessionRepository
	SMSTemplate() SMSTemplateRepository
	SSOState() SSOStateRepository
	Verification() VerificationRepository
	Webhook() WebhookRepository
	WebhookEvent() WebhookEventRepository
	Permission() PermissionRepository
	ProviderCatalog() ProviderCatalogRepository
	OrganizationProvider() OrganizationProviderRepository
	Activity() ActivityRepository
}

type repository struct {
	client *data.Clients

	apiKey               ApiKeyRepository
	activity             ActivityRepository
	audit                AuditRepository
	email                EmailTemplateRepository
	identityProvider     IdentityProviderRepository
	membership           MembershipRepository
	mfa                  MFARepository
	oauth                OAuthRepository
	organization         OrganizationRepository
	organizationFeature  OrganizationFeatureRepository
	passKey              PasskeyRepository
	role                 RoleRepository
	user                 UserRepository
	session              SessionRepository
	smstemplate          SMSTemplateRepository
	webhook              WebhookRepository
	webhookEvent         WebhookEventRepository
	verification         VerificationRepository
	ssoState             SSOStateRepository
	permission           PermissionRepository
	providerCatalog      ProviderCatalogRepository
	organizationProvider OrganizationProviderRepository
}

func (r *repository) Activity() ActivityRepository {
	return r.activity
}

func (r *repository) ProviderCatalog() ProviderCatalogRepository {
	return r.providerCatalog
}

func (r *repository) OrganizationProvider() OrganizationProviderRepository {
	return r.organizationProvider
}

func (r *repository) Permission() PermissionRepository {
	return r.permission
}

func (r *repository) APIKey() ApiKeyRepository {
	return r.apiKey
}

func (r *repository) Audit() AuditRepository {
	return r.audit
}

func (r *repository) EmailTemplate() EmailTemplateRepository {
	return r.email
}

func (r *repository) IdentityProvider() IdentityProviderRepository {
	return r.identityProvider
}

func (r *repository) Membership() MembershipRepository {
	return r.membership
}

func (r *repository) MFA() MFARepository {
	return r.mfa
}

func (r *repository) OAuth() OAuthRepository {
	return r.oauth
}

func (r *repository) Organization() OrganizationRepository {
	return r.organization
}

func (r *repository) OrganizationFeature() OrganizationFeatureRepository {
	return r.organizationFeature
}

func (r *repository) PassKey() PasskeyRepository {
	return r.passKey
}

func (r *repository) Role() RoleRepository {
	return r.role
}

func (r *repository) User() UserRepository {
	return r.user
}

func (r *repository) Session() SessionRepository {
	return r.session
}

func (r *repository) SSOState() SSOStateRepository {
	return r.ssoState
}

func (r *repository) Verification() VerificationRepository {
	return r.verification
}

func (r *repository) Webhook() WebhookRepository {
	return r.webhook
}

func (r *repository) WebhookEvent() WebhookEventRepository {
	return r.webhookEvent
}

func (r *repository) SMSTemplate() SMSTemplateRepository {
	return r.smstemplate
}

func New(client *data.Clients, logger logging.Logger) Repository {
	return &repository{
		client:               client,
		activity:             NewActivityRepository(client, logger),
		apiKey:               NewApiKeyRepository(client.DB),
		audit:                NewAuditRepository(client.DB),
		email:                NewEmailTemplateRepository(client.DB),
		identityProvider:     NewIdentityProviderRepository(client.DB),
		membership:           NewMembershipRepository(client.DB, logger),
		mfa:                  NewMFARepository(client.DB),
		oauth:                NewOAuthRepository(client.DB, logger),
		organization:         NewOrganizationRepository(client.DB, logger),
		organizationFeature:  NewOrganizationFeatureRepository(client.DB),
		passKey:              NewPasskeyRepository(client.DB, logger),
		role:                 NewRoleRepository(client.DB, logger),
		user:                 NewUserRepository(client.DB, logger),
		session:              NewSessionRepository(client.DB, logger),
		smstemplate:          NewSMSTemplateRepository(client.DB),
		webhook:              NewWebhookRepository(client.DB),
		webhookEvent:         NewWebhookEventRepository(client.DB),
		verification:         NewVerificationRepository(client.DB),
		ssoState:             NewSSOStateRepository(client.DB),
		permission:           NewPermissionRepository(client.DB, logger),
		providerCatalog:      NewProviderCatalogRepository(client.DB, logger),
		organizationProvider: NewOrganizationProviderRepository(client.DB, logger),
	}
}
