# 🏗️ Frank Auth SaaS - Complete Project Structure

```
frank/
├── cmd/
│   ├── server/                          # Main server application
│   │   ├── main.go
│   │   └── wire.go                      # Dependency injection
│   ├── migrate/                         # Database migration tool
│   │   └── main.go
│   └── cli/                            # CLI tools
│       └── main.go
│
├── internal/                           # Private application code
│   ├── server/                         # HTTP server setup
│   │   ├── server.go
│   │   └── router.go
│   │
│   ├── config/                         # Configuration management
│   │   ├── config.go                   # ✅ Already implemented
│   │   └── validation.go
│   │
│   ├── di/                            # Dependency injection container
│   │   ├── container.go
│   │   └── wire.go
│   │
│   ├── middleware/                     # HTTP middleware
│   │   ├── auth.go
│   │   ├── cors.go
│   │   ├── logging.go
│   │   ├── rate_limit.go
│   │   └── tenant.go
│   │
│   ├── routes/                        # API route definitions
│   │   ├── routes.go                  # ✅ Main router
│   │   ├── routes_rbac.go             # ✅ RBAC endpoints
│   │   ├── routes_auth.go             # Authentication endpoints
│   │   ├── routes_users.go            # User management
│   │   ├── routes_organizations.go    # Organization management
│   │   ├── routes_memberships.go      # Membership management
│   │   ├── routes_oauth.go            # OAuth2 endpoints
│   │   ├── routes_passkeys.go         # Passkey authentication
│   │   ├── routes_mfa.go             # MFA endpoints
│   │   ├── routes_sso.go             # SSO endpoints
│   │   └── routes_webhooks.go        # ✅ Webhook endpoints
│   │
│   ├── services/                      # Business logic layer
│   │   ├── auth/                      # Authentication services
│   │   │   ├── auth.go
│   │   │   ├── password.go
│   │   │   ├── token.go
│   │   │   └── session.go
│   │   ├── user/                      # User management services
│   │   │   ├── user.go
│   │   │   ├── profile.go
│   │   │   └── preferences.go
│   │   ├── organization/              # Organization services
│   │   │   ├── organization.go
│   │   │   ├── membership.go
│   │   │   ├── invitation.go
│   │   │   └── billing.go
│   │   ├── rbac/                      # RBAC services
│   │   │   ├── rbac.go
│   │   │   ├── permission.go
│   │   │   └── role.go
│   │   ├── oauth/                     # OAuth2 services
│   │   │   ├── oauth.go
│   │   │   ├── client.go
│   │   │   └── token.go
│   │   ├── passkey/                   # Passkey services
│   │   │   ├── passkey.go
│   │   │   └── webauthn.go
│   │   ├── mfa/                       # MFA services
│   │   │   ├── mfa.go
│   │   │   ├── totp.go
│   │   │   └── sms.go
│   │   ├── sso/                       # SSO services
│   │   │   ├── sso.go
│   │   │   ├── saml.go
│   │   │   └── oidc.go
│   │   ├── audit/                     # Audit logging
│   │   │   ├── audit.go
│   │   │   └── compliance.go
│   │   ├── notification/              # Notification services
│   │   │   ├── email.go
│   │   │   └── sms.go
│   │   └── webhook/                   # Webhook services
│   │       ├── webhook.go
│   │       └── delivery.go
│   │
│   ├── repository/                    # Data access layer
│   │   ├── user.go
│   │   ├── organization.go
│   │   ├── membership.go
│   │   ├── role.go
│   │   ├── permission.go
│   │   ├── session.go
│   │   ├── oauth.go
│   │   ├── passkey.go
│   │   ├── mfa.go
│   │   ├── audit.go
│   │   └── webhook.go
│   │
│   ├── authz/                         # Authorization middleware
│   │   ├── checker.go
│   │   ├── middleware.go
│   │   └── permissions.go
│   │
│   ├── model/                         # API models and DTOs
│   │   ├── auth.go
│   │   ├── user.go
│   │   ├── organization.go
│   │   ├── membership.go
│   │   ├── rbac.go
│   │   ├── oauth.go
│   │   ├── passkey.go
│   │   ├── mfa.go
│   │   ├── sso.go
│   │   ├── audit.go
│   │   ├── webhook.go
│   │   ├── pagination.go             # ✅ Already implemented
│   │   └── response.go
│   │
│   └── database/                      # Database setup and migrations
│       ├── database.go
│       ├── migrate.go
│       └── seed.go
│
├── ent/                              # Ent ORM generated code
│   ├── schema/                       # ✅ Complete schema definitions
│   │   ├── user.go
│   │   ├── organization.go
│   │   ├── membership.go
│   │   ├── role.go
│   │   ├── permission.go
│   │   ├── session.go
│   │   ├── oauth_*.go
│   │   ├── passkey.go
│   │   ├── mfa.go
│   │   ├── webhook.go
│   │   └── ...
│   └── [generated files]
│
├── pkg/                              # Public packages
│   ├── errors/                       # ✅ Error handling
│   │   ├── errors.go
│   │   └── codes.go
│   ├── logging/                      # ✅ Logging utilities
│   │   └── logger.go
│   ├── crypto/                       # Cryptographic utilities
│   │   ├── hash.go
│   │   ├── jwt.go
│   │   └── random.go
│   ├── validation/                   # Input validation
│   │   └── validator.go
│   ├── email/                        # Email utilities
│   │   └── sender.go
│   ├── sms/                         # SMS utilities
│   │   └── sender.go
│   └── entity/                      # Entity utilities
│       └── json.go
│
├── migrations/                       # Database migrations
│   ├── 001_initial.up.sql
│   ├── 002_rbac.up.sql
│   ├── 003_oauth.up.sql
│   └── ...
│
├── templates/                        # Email/notification templates
│   ├── email/
│   │   ├── verification.html
│   │   ├── password_reset.html
│   │   └── invitation.html
│   └── sms/
│       └── verification.txt
│
├── docs/                            # Documentation
│   ├── api/                         # API documentation
│   ├── deployment/                  # Deployment guides
│   └── compliance/                  # SOC 2 documentation
│
├── scripts/                         # Build and deployment scripts
│   ├── build.sh
│   ├── deploy.sh
│   └── migrate.sh
│
├── tests/                           # Test files
│   ├── integration/
│   ├── unit/
│   └── fixtures/
│
├── configs/                         # Configuration files
│   ├── config.yaml
│   ├── config.prod.yaml
│   └── config.test.yaml
│
├── docker/                          # Docker files
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.prod.yml
│
├── .github/                         # GitHub workflows
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── compliance.yml
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── LICENSE
```

## 🎯 Key Architecture Principles

### 1. **Three-Tier User System**
- **Internal Users**: Platform staff who manage the SaaS
- **External Users**: Customer organization members
- **End Users**: Users of customers' applications

### 2. **Multi-Tenant Architecture**
- Organization-scoped resources and permissions
- Context-aware RBAC system
- Tenant isolation at database level

### 3. **Microservice-Ready**
- Clear separation of concerns
- Dependency injection for testability
- Repository pattern for data access

### 4. **Security-First Design**
- SOC 2 compliance built-in
- Comprehensive audit logging
- Zero-trust authorization model

### 5. **Clerk.js Feature Parity**
- ✅ Multi-factor authentication (TOTP, SMS, Email)
- ✅ Passkey/WebAuthn support
- ✅ OAuth2/OIDC providers
- ✅ SAML SSO integration
- ✅ Passwordless authentication
- ✅ Session management
- ✅ User management
- ✅ Organization management
- ✅ Role-based access control
- ✅ Audit logging
- ✅ Webhook system
- ✅ Email/SMS notifications

## 🔄 Next Implementation Steps

1. **Organization-User Relationships** (Priority 1)
2. **Authentication Services** (Priority 2)
3. **RBAC Implementation** (Priority 3)
4. **Audit & Compliance** (Priority 4)
5. **Advanced Features** (Priority 5)