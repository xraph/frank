# Frank Auth Server

Frank is a robust, feature-rich authentication server built with Go and EntGO that provides a comprehensive identity management solution. It combines all the best features of modern authentication providers like ClerkJS into a self-hosted solution.

## Features

- **Multiple Authentication Methods**
   - Traditional email/password
   - Passwordless (Email and SMS)
   - Multi-factor authentication (TOTP, SMS, Email)
   - Passkeys (WebAuthn)
   - OAuth2/OIDC (Social login)
   - Enterprise SSO (SAML)

- **Organization Support**
   - Multi-tenancy
   - Custom features per organization
   - Member management and roles

- **API Keys Management**
   - For machine-to-machine authentication
   - Scoped permissions
   - Expiration management

- **OAuth2 Provider**
   - Use Frank as an identity provider for your applications
   - Full OAuth2 and OpenID Connect support

- **Webhook System**
   - Real-time notifications for auth events
   - Custom payload formats
   - Retry logic

- **Security Features**
   - CSRF protection
   - Rate limiting
   - Session management
   - CORS configuration

## Technology Stack

- **Go** - Fast and efficient programming language
- **EntGO** - Entity framework for Go
- **PostgreSQL** - Secure and reliable database
- **Redis** - For session and cache management

## Getting Started

### Prerequisites

- Go 1.18+
- PostgreSQL 13+
- Redis 6+
- Docker and Docker Compose (optional)

### Local Development Setup

1. Clone the repository:
   ```
   git clone https://github.com/juicycleff/frank.git
   cd frank
   ```

2. Copy the example environment file:
   ```
   cp .env.example .env
   ```

3. Edit the `.env` file to configure your environment.

4. Initialize the development environment:
   ```
   make dev-init
   ```

5. Start the development server:
   ```
   make dev
   ```

### Docker Setup

To run Frank using Docker Compose:

```
docker-compose up -d
```

This will start the Frank Auth server along with PostgreSQL, Redis, and MailHog for email testing.

## Configuration

Frank is highly configurable. See the `.env.example` file for available configuration options.

## API Documentation

Once running, API documentation is available at:

```
http://localhost:8080/api/docs
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Clerk](https://clerk.dev/) - For the inspiration
- [EntGO](https://entgo.io/) - For the amazing entity framework
- [Go-Swagger](https://github.com/go-swagger/go-swagger) - For API documentation