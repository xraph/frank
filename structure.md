Here's the full, detailed folder structure for the auth server project:

```
github.com/juicycleff/frank/
├── cmd/
│   └── server/
│       └── main.go
├── config/
│   ├── config.go
│   ├── defaults.go
│   └── environment.go
├── ent/
│   ├── schema/
│   │   ├── user.go
│   │   ├── organization.go
│   │   ├── session.go
│   │   ├── apikey.go
│   │   ├── mfa.go
│   │   ├── passkey.go
│   │   ├── oauth_client.go
│   │   ├── oauth_scope.go
│   │   ├── oauth_token.go
│   │   ├── oauth_authorization.go
│   │   ├── webhook.go
│   │   ├── webhook_event.go
│   │   ├── identity_provider.go
│   │   ├── permission.go
│   │   ├── role.go
│   │   ├── email_template.go
│   │   ├── verification.go
│   │   ├── feature_flag.go
│   │   └── organization_feature.go
├── internal/
│   ├── auth/
│   │   ├── oauth2/
│   │   │   ├── provider.go
│   │   │   ├── server.go
│   │   │   ├── client.go
│   │   │   ├── token.go
│   │   │   ├── handlers.go
│   │   │   └── storage.go
│   │   ├── passwordless/
│   │   │   ├── email.go
│   │   │   ├── sms.go
│   │   │   ├── magic_link.go
│   │   │   └── service.go
│   │   ├── mfa/
│   │   │   ├── totp.go
│   │   │   ├── backup_codes.go
│   │   │   ├── sms.go
│   │   │   ├── email.go
│   │   │   └── service.go
│   │   ├── passkeys/
│   │   │   ├── webauthn.go
│   │   │   ├── authenticator.go
│   │   │   └── service.go
│   │   ├── sso/
│   │   │   ├── provider.go
│   │   │   ├── saml.go
│   │   │   ├── oidc.go
│   │   │   └── service.go
│   │   └── session/
│   │       ├── manager.go
│   │       ├── store.go
│   │       └── cookie.go
│   ├── middleware/
│   │   ├── auth.go
│   │   ├── logging.go
│   │   ├── cors.go
│   │   ├── rate_limiter.go
│   │   ├── recovery.go
│   │   └── organization.go
│   ├── handlers/
│   │   ├── auth.go
│   │   ├── users.go
│   │   ├── organizations.go
│   │   ├── oauth.go
│   │   ├── webhooks.go
│   │   ├── apikeys.go
│   │   ├── mfa.go
│   │   ├── passkeys.go
│   │   ├── sso.go
│   │   └── passwordless.go
│   ├── organization/
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── features.go
│   │   └── membership.go
│   ├── user/
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── password.go
│   │   └── verification.go
│   ├── apikeys/
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── validator.go
│   ├── webhook/
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── event.go
│   │   └── delivery.go
│   ├── email/
│   │   ├── service.go
│   │   ├── templates.go
│   │   └── sender.go
│   ├── sms/
│   │   ├── service.go
│   │   └── sender.go
│   ├── server/
│   │   ├── http.go
│   │   ├── router.go
│   │   └── health.go
│   └── rbac/
│       ├── service.go
│       ├── repository.go
│       └── enforcer.go
├── pkg/
│   ├── errors/
│   │   ├── errors.go
│   │   └── codes.go
│   ├── logging/
│   │   ├── logger.go
│   │   └── middleware.go
│   ├── crypto/
│   │   ├── jwt.go
│   │   ├── hash.go
│   │   └── random.go
│   ├── validator/
│   │   └── validator.go
│   └── utils/
│       ├── http.go
│       ├── strings.go
│       └── time.go
├── migrations/
│   ├── 20250101000000_initial_schema.up.sql
│   └── 20250101000000_initial_schema.down.sql
├── scripts/
│   ├── setup.sh
│   ├── generate.sh
│   └── migrate.sh
├── api/
│   ├── proto/
│   │   ├── auth.proto
│   │   ├── user.proto
│   │   └── organization.proto
│   └── swagger/
│       └── openapi.yaml
├── web/
│   ├── templates/
│   │   ├── email/
│   │   │   ├── verification.html
│   │   │   ├── magic_link.html
│   │   │   └── password_reset.html
│   │   └── auth/
│   │       ├── login.html
│   │       ├── register.html
│   │       └── mfa.html
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── images/
│   └── views/
│       ├── components/
│       └── layouts/
├── tests/
│   ├── integration/
│   │   ├── auth_test.go
│   │   ├── organization_test.go
│   │   └── oauth_test.go
│   ├── unit/
│   │   ├── auth_test.go
│   │   ├── crypto_test.go
│   │   └── validation_test.go
│   └── mocks/
│       ├── repositories.go
│       └── services.go
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── oauth2.md
│   └── development.md
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── .gitignore
├── .golangci.yml
├── .env.example
└── README.md
```

This comprehensive structure includes everything needed for your auth server with all the requested features:

1. **EntGO schema files** for all required entities (users, organizations, OAuth2, MFA, passkeys, etc.)

2. **Auth features** fully separated into modules:
    - OAuth2 (both as client and provider)
    - Passwordless authentication
    - Multi-factor authentication
    - Passkeys (WebAuthn)
    - SSO and Enterprise SSO

3. **Organization support** with feature customization:
    - Organization models and services
    - Feature flags that can be toggled per organization

4. **API management**:
    - API key generation and validation for machine-to-machine auth
    - OAuth2 provider implementation

5. **Webhooks**:
    - Event generation and delivery
    - Subscription management

6. **Supporting infrastructure**:
    - Session management
    - Email and SMS delivery
    - RBAC (Role-Based Access Control)
    - Templates for notifications

Let me know which specific files you'd like me to implement first, and I'll get started.