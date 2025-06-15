# 🔐 Frank Auth SaaS

**Production-ready, multi-tenant authentication platform with Clerk.js compatibility**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://choosealicense.com/licenses/mit/)
[![SOC 2](https://img.shields.io/badge/SOC%202-Compliant-blue?style=for-the-badge)](docs/compliance/)
[![API Status](https://img.shields.io/badge/API-Production%20Ready-success?style=for-the-badge)](https://api.frankauth.com/docs)

Frank Auth SaaS is a comprehensive, enterprise-ready authentication platform designed to provide seamless user management, multi-factor authentication, and advanced security features for modern applications. Built with a three-tier user system and multi-tenant architecture, it offers complete compatibility with Clerk.js while providing enhanced security and compliance features.

## 🚀 Quick Start

### Prerequisites

- **Go 1.21+** - [Install Go](https://golang.org/doc/install)
- **PostgreSQL 14+** - [Install PostgreSQL](https://www.postgresql.org/download/)
- **Redis 6+** - [Install Redis](https://redis.io/download)

### Installation

```bash
# Clone the repository
git clone https://github.com/juicycleff/frank.git
cd frank

# Install dependencies
go mod download

# Copy configuration template
cp configs/config.yaml.example configs/config.yaml

# Setup database
make migrate-up

# Seed initial data (optional)
make seed

# Start the server
make run
```

### Docker Setup

```bash
# Start all services
docker-compose up -d

# Initialize database
docker-compose exec app make migrate-up

# View logs
docker-compose logs -f app
```

## 🏗️ Architecture Overview

Frank Auth SaaS implements a sophisticated three-tier user system designed for maximum flexibility and security:

### Three-Tier User System

#### **Tier 1: Internal Users (Platform Staff)**
- Your company employees managing the SaaS platform
- `users` table with `user_type = "internal"`
- Full platform management permissions
- Access to analytics, billing, and system administration

#### **Tier 2: External Users (Customer Organization Members)**
- Customer developers/admins managing their authentication service
- `users` table with `user_type = "external"`
- Organization-scoped permissions
- Manage their organization's end users and settings

#### **Tier 3: End Users (Auth Service Users)**
- Actual users of customer applications
- Separate `end_users` table (isolated per organization)
- Self-access permissions only
- The users that your customers' applications authenticate

### Multi-Tenant Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frank Auth Platform                      │
├─────────────────────────────────────────────────────────────┤
│  Internal Users (Platform Staff)                           │
│  • Platform Management    • Analytics    • Billing         │
└─────────────────────────────────────────────────────────────┘
           │
           ├── Organization A ──────────────────────────────────┐
           │   │                                               │
           │   ├── External Users (Customer Staff)             │
           │   │   • Manage End Users  • Configure Auth        │
           │   │                                               │
           │   └── End Users (Application Users)               │
           │       • Login to Apps     • Self-Management       │
           │                                                   │
           └── Organization B ──────────────────────────────────┤
               │                                               │
               ├── External Users (Customer Staff)             │
               │   • Manage End Users  • Configure Auth        │
               │                                               │
               └── End Users (Application Users)               │
                   • Login to Apps     • Self-Management       │
```

## ✨ Features

### 🔐 **Authentication Methods**
- **Traditional**: Email/password with robust security
- **Passwordless**: Magic links and OTP via email/SMS
- **Social OAuth**: Google, GitHub, Microsoft, Apple, and 20+ providers
- **Enterprise SSO**: SAML 2.0 and OpenID Connect
- **Passkeys**: WebAuthn/FIDO2 for modern authentication
- **API Keys**: Secure programmatic access

### 🛡️ **Security & Compliance**
- **Multi-Factor Authentication**: TOTP, SMS, Email, and backup codes
- **Session Management**: Secure, scalable session handling
- **Rate Limiting**: Intelligent throttling and DDoS protection
- **Audit Logging**: Comprehensive security event tracking
- **SOC 2 Compliance**: Built-in compliance features
- **Zero-Trust Architecture**: Verify everything, trust nothing

### 🏢 **Organization Management**
- **Multi-Tenant Architecture**: Complete organization isolation
- **Role-Based Access Control**: Granular permissions system
- **Member Management**: Invitations, roles, and billing seats
- **Team Collaboration**: Organization-scoped resources
- **Billing Integration**: Usage-based pricing support

### 🔗 **Integration & APIs**
- **RESTful API**: Comprehensive REST API with OpenAPI docs
- **WebSocket Support**: Real-time authentication events
- **Webhooks**: Event-driven integrations
- **SDK Support**: Official SDKs for popular languages
- **Clerk.js Compatibility**: Drop-in replacement for existing apps

### 📊 **Analytics & Monitoring**
- **User Analytics**: Login patterns, device tracking, geolocation
- **Security Monitoring**: Failed attempts, suspicious activity
- **Performance Metrics**: Response times, throughput, errors
- **Compliance Reports**: Automated audit trail generation

## 🛠️ Configuration

### Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/frank_auth
REDIS_URL=redis://localhost:6379

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0
ENVIRONMENT=development

# Authentication
JWT_SECRET=your-super-secure-jwt-secret
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=7d

# External Services
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Security
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Configuration File

```yaml
# configs/config.yaml
server:
  port: 8080
  host: "0.0.0.0"
  timeout: 30s

database:
  host: "localhost"
  port: 5432
  name: "frank_auth"
  user: "postgres"
  password: "password"
  ssl_mode: "disable"
  max_connections: 100

auth:
  jwt_secret: "your-jwt-secret"
  jwt_expiry: "24h"
  password_policy:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_digit: true
    require_special: false

mfa:
  totp_issuer: "Frank Auth"
  totp_digits: 6
  totp_period: 30
  backup_codes_count: 10

security:
  rate_limit_enabled: true
  rate_limit_per_second: 10
  rate_limit_burst: 50
  cors_enabled: true
  security_headers_enabled: true
```

## 🔌 API Usage

### Authentication

```bash
# Register a new user
curl -X POST https://api.frankauth.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'

# Login
curl -X POST https://api.frankauth.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'

# Get current user
curl -X GET https://api.frankauth.com/v1/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Organization Management

```bash
# Create organization
curl -X POST https://api.frankauth.com/v1/organizations \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme-corp"
  }'

# Invite user to organization
curl -X POST https://api.frankauth.com/v1/organizations/acme-corp/invitations \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "role": "member"
  }'
```

## 📚 Documentation

- **[API Documentation](https://api.frankauth.com/docs)** - Complete OpenAPI/Swagger docs
- **[Integration Guide](docs/integration.md)** - Step-by-step integration instructions
- **[Migration Guide](docs/migration.md)** - Migrating from other auth providers
- **[Security Guide](docs/security.md)** - Security best practices
- **[Compliance Documentation](docs/compliance/)** - SOC 2 and other compliance info
- **[Deployment Guide](docs/deployment/)** - Production deployment instructions

## 🔧 Development

### Project Structure

```
frank/
├── cmd/                     # Application entrypoints
├── internal/                # Private application code
│   ├── routes/             # API route handlers
│   ├── services/           # Business logic
│   ├── repository/         # Data access layer
│   ├── middleware/         # HTTP middleware
│   └── config/             # Configuration
├── ent/                    # Database schema & ORM
├── pkg/                    # Public packages
├── migrations/             # Database migrations
├── docs/                   # Documentation
└── tests/                  # Test files
```

### Development Commands

```bash
# Install development dependencies
make dev-deps

# Generate code (Ent ORM, Wire DI)
make generate

# Run tests
make test

# Run tests with coverage
make test-coverage

# Lint code
make lint

# Format code
make fmt

# Start development server with hot reload
make dev

# Build for production
make build

# Run database migrations
make migrate-up

# Rollback migrations
make migrate-down
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests
go test -tags=integration ./tests/integration/...

# Run specific test
go test -run TestUserRegistration ./internal/services/auth/
```

## 🚀 Deployment

### Production Deployment

Frank Auth SaaS is designed for production deployment with Docker and Kubernetes support.

#### Docker Deployment

```bash
# Build production image
docker build -t frank-auth:latest .

# Run with docker-compose
docker-compose -f docker-compose.prod.yml up -d
```

#### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=frank-auth
```

#### Environment-Specific Configurations

- **Development**: `configs/config.yaml`
- **Staging**: `configs/config.staging.yaml`
- **Production**: `configs/config.prod.yaml`

## 🔒 Security

Frank Auth SaaS takes security seriously and implements multiple layers of protection:

### Security Features

- **Encryption**: All data encrypted at rest and in transit
- **Password Security**: Argon2id hashing with salt
- **Rate Limiting**: Intelligent request throttling
- **Session Security**: Secure session management with rotation
- **CSRF Protection**: Built-in CSRF token validation
- **XSS Prevention**: Content Security Policy headers
- **SQL Injection**: Parameterized queries and ORM protection

### Compliance

- **SOC 2 Type II**: Comprehensive security controls
- **GDPR**: Data privacy and user rights compliance
- **CCPA**: California Consumer Privacy Act compliance
- **HIPAA**: Healthcare data protection (optional module)

## 🤝 Contributing

We welcome contributions to Frank Auth SaaS! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Implement your feature or fix
4. **Add tests**: Ensure your changes are tested
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to the branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**: Submit your changes for review

### Development Guidelines

- Follow Go best practices and conventions
- Write comprehensive tests for new features
- Update documentation for user-facing changes
- Use conventional commit messages
- Ensure all CI checks pass

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Community Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/juicycleff/frank/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/juicycleff/frank/discussions)
- **Discord**: [Join our community](https://discord.gg/frankauth)

### Enterprise Support

For enterprise customers, we offer:

- **Priority Support**: 24/7 technical support
- **Custom Integrations**: Tailored solutions for your needs
- **Professional Services**: Implementation and consulting
- **SLA Guarantees**: Uptime and response time guarantees

Contact us at [enterprise@xraph.com](mailto:enterprise@xraph.com) for more information.

## 🙏 Acknowledgments

Frank Auth SaaS is built on the shoulders of giants. We'd like to thank:

- **[Huma](https://github.com/danielgtaylor/huma)** - Modern HTTP API framework
- **[Ent](https://entgo.io/)** - Entity framework for Go
- **[Chi](https://github.com/go-chi/chi)** - Lightweight HTTP router
- **[Viper](https://github.com/spf13/viper)** - Configuration management
- **[Zap](https://github.com/uber-go/zap)** - Structured logging

## 📊 Status

- **Version**: 1.0.0
- **Status**: Production Ready
- **Go Version**: 1.21+
- **Database**: PostgreSQL 14+
- **Cache**: Redis 6+
- **License**: MIT

---

**Built with ❤️ by the XRaph team**

For more information, visit [xraph.com](https://frank.xraph.com) or check out our [documentation](https://frank.xraph.com/docs).