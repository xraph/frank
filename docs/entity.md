1. **User Schema**: Defines user attributes including email, phone number, name, and authentication details.

2. **Organization Schema**: Handles multi-tenancy with organization name, domain, plan, and related settings.

3. **Session Schema**: Manages user sessions with tokens, IP addresses, and expiration times.

4. **ApiKey Schema**: Supports machine-to-machine authentication with nameable, revocable API keys.

5. **MFA Schema**: Implements multi-factor authentication methods (TOTP, SMS, email, backup codes).

6. **Passkey Schema**: Supports WebAuthn for passwordless authentication using security keys.

7. **OAuth Client/Token/Authorization/Scope**: Complete OAuth2 provider implementation with:
    - Client registration
    - Authorization code flow
    - Token management
    - Scopes for permission control

8. **Webhook and WebhookEvent**: Enables event notifications to third-party services with:
    - Webhook registration
    - Event delivery and tracking
    - Retry capabilities

9. **IdentityProvider**: Implements SSO integrations (SAML, OIDC) for enterprise authentication.

10. **Permission and Role**: Role-based access control (RBAC) for granular permissions.

11. **EmailTemplate**: Customizable email templates for different communications.

12. **Verification**: Handles email/phone verification, password resets, and magic links.

13. **FeatureFlag and OrganizationFeature**: Allows organizations to customize which features are enabled for their users.

These schemas establish the foundation for your auth server, enabling all the requested features: OAuth2, passwordless auth, MFA, passkeys, SSO, enterprise SSO, webhooks, organizations, and API Keys for machine-to-machine authentication.

Would you like me to implement any specific part of the business logic next, or would you prefer to focus on another aspect of the system?