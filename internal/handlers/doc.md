1. Authentication
    - Traditional username/password login
    - OAuth2 authentication (as both client and provider)
    - Passwordless authentication (email and SMS)
    - Magic links
    - Passkeys (WebAuthn)

2. Multi-factor authentication (MFA)
    - TOTP (Time-based One-Time Password)
    - SMS codes
    - Email codes
    - Backup codes

3. Single Sign-On (SSO)
    - OAuth2 providers
    - OIDC providers
    - SAML (structure in place, implementation to be completed)

4. Organizations
    - Multi-tenant support
    - Organization member management
    - Feature management per organization

5. API Keys
    - Machine-to-machine authentication
    - Scoped permissions
    - Expirable keys

6. Webhooks
    - Event-driven architecture
    - Custom payloads
    - Signature verification

The implementation follows a clean architecture with separation of concerns:

1. Handlers: Handle HTTP requests and responses
2. Middleware: Provide cross-cutting concerns like authentication, logging, and rate limiting
3. Services: Implement business logic

This auth server can be used as both an authentication provider for your applications and as an OAuth2 provider for third-party applications. Organizations can customize which features are enabled, making it flexible for different use cases.

The code structure follows the folder organization you specified, with clear separation between different components. Each handler implements its own routes and operations, while middleware components handle cross-cutting concerns.