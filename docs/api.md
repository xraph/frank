# Frank Authentication Server API Documentation

## Overview

This document outlines the API endpoints provided by the Frank Authentication Server. The API follows RESTful principles and uses JSON for request and response bodies.

## Base URL

All API endpoints are prefixed with: `/api/v1`

## Authentication

API requests can be authenticated using:

1. **Bearer Token**: Include an `Authorization` header with a valid JWT token
   ```
   Authorization: Bearer {token}
   ```

2. **API Key**: Include an `X-API-Key` header with a valid API key
   ```
   X-API-Key: {api_key}
   ```

3. **Session Cookie**: For browser-based requests, a session cookie is used

## Common Response Format

All API responses follow a standard format:

```json
{
  "success": true|false,
  "data": { ... },  // Present on successful requests
  "error": {        // Present on failed requests
    "code": "error_code",
    "message": "Human-readable error message"
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `unauthorized` | Authentication is required |
| `forbidden` | Authenticated but not authorized |
| `not_found` | Requested resource not found |
| `invalid_input` | Invalid input parameters |
| `conflict` | Resource already exists |
| `internal_server_error` | Server-side error |
| `rate_limited` | Too many requests |

## API Endpoints

### Authentication

#### Traditional Authentication

##### Register a User

```
POST /auth/register
```

Request:
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "first_name": "John",
  "last_name": "Doe",
  "metadata": {
    "custom_field": "value"
  }
}
```

Response:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "created_at": "2023-01-01T00:00:00Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

##### Login

```
POST /auth/login
```

Request:
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "organization_id": "org_123",
  "remember_me": true
}
```

Response:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": 1672531200
  }
}
```

##### Logout

```
POST /auth/logout
```

Response:
```json
{
  "success": true,
  "data": {
    "message": "Successfully logged out"
  }
}
```

##### Refresh Token

```
POST /auth/refresh
```

Request:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Response:
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": 1672531200
  }
}
```

#### Passwordless Authentication

##### Email Login

```
POST /auth/passwordless/email
```

Request:
```json
{
  "email": "user@example.com",
  "redirect_url": "https://myapp.com/verify"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "message": "Passwordless login email sent",
    "verification_id": "ver_123"
  }
}
```

##### SMS Login

```
POST /auth/passwordless/sms
```

Request:
```json
{
  "phone_number": "+12025550123",
  "redirect_url": "https://myapp.com/verify"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "message": "Passwordless login SMS sent",
    "verification_id": "ver_123"
  }
}
```

##### Verify Passwordless

```
POST /auth/passwordless/verify
```

Request:
```json
{
  "token": "abc123", // For email verification
  "phone_number": "+12025550123", // For SMS verification
  "code": "123456", // For SMS verification
  "auth_type": "email|sms"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "user_id": "user_123",
    "email": "user@example.com"
  }
}
```

#### Multi-Factor Authentication (MFA)

##### Enroll in MFA

```
POST /auth/mfa/enroll
```

Request:
```json
{
  "method": "totp|sms|email|backup_codes",
  "phone_number": "+12025550123", // For SMS
  "email": "user@example.com" // For email
}
```

Response for TOTP:
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "uri": "otpauth://totp/Frank:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Frank",
    "qr_code_data": "base64_encoded_qr_code"
  }
}
```

Response for backup codes:
```json
{
  "success": true,
  "data": {
    "backup_codes": [
      "12345-67890",
      "abcde-fghij"
    ]
  }
}
```

##### Verify MFA

```
POST /auth/mfa/verify
```

Request:
```json
{
  "method": "totp|sms|email|backup_codes",
  "code": "123456",
  "phone_number": "+12025550123" // For SMS
}
```

Response:
```json
{
  "success": true,
  "data": {
    "verified": true
  }
}
```

##### Get MFA Methods

```
GET /auth/mfa/methods
```

Response:
```json
{
  "success": true,
  "data": {
    "methods": ["totp", "backup_codes"]
  }
}
```

#### Passkeys (WebAuthn)

##### Begin Registration

```
POST /auth/passkeys/register/begin
```

Request:
```json
{
  "device_name": "My iPhone",
  "device_type": "mobile"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "options": { ... },
    "session_id": "sess_123"
  }
}
```

##### Complete Registration

```
POST /auth/passkeys/register/complete
```

Request:
```json
{
  "session_id": "sess_123",
  "response": { ... },
  "device_name": "My iPhone",
  "device_type": "mobile"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "passkey_123",
    "name": "My iPhone",
    "device_type": "mobile",
    "registered_at": "2023-01-01T00:00:00Z"
  }
}
```

##### Begin Login

```
POST /auth/passkeys/login/begin
```

Response:
```json
{
  "success": true,
  "data": {
    "options": { ... },
    "session_id": "sess_123"
  }
}
```

##### Complete Login

```
POST /auth/passkeys/login/complete
```

Request:
```json
{
  "session_id": "sess_123",
  "response": { ... }
}
```

Response:
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "user_id": "user_123"
  }
}
```

#### OAuth2 & SSO

##### List OAuth Providers

```
GET /auth/oauth/providers
```

Response:
```json
{
  "success": true,
  "data": {
    "providers": [
      {
        "id": "google",
        "name": "Google",
        "type": "oauth2"
      },
      {
        "id": "github",
        "name": "GitHub",
        "type": "oauth2"
      }
    ]
  }
}
```

##### Initiate OAuth Login

```
GET /auth/oauth/providers/{provider}?redirect_uri=https://myapp.com/callback
```

Response: Redirects to provider's authorization page

##### OAuth Callback

```
GET /auth/oauth/callback/{provider}?code=abc123&state=xyz789
```

Response: Completes authentication and redirects to the original redirect URI or returns:

```json
{
  "success": true,
  "data": {
    "message": "OAuth authentication successful",
    "user": {
      "id": "user_123",
      "email": "user@example.com"
    }
  }
}
```

##### List SSO Providers

```
GET /auth/sso/providers
```

Response:
```json
{
  "success": true,
  "data": {
    "providers": [
      {
        "id": "okta",
        "name": "Okta",
        "type": "saml"
      },
      {
        "id": "azure_ad",
        "name": "Azure AD",
        "type": "oidc"
      }
    ]
  }
}
```

### User Management

#### Get Current User

```
GET /users/me
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "created_at": "2023-01-01T00:00:00Z"
  }
}
```

#### Update Current User

```
PATCH /users/me
```

Request:
```json
{
  "first_name": "John",
  "last_name": "Smith",
  "profile_image_url": "https://example.com/avatar.jpg"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Smith",
    "profile_image_url": "https://example.com/avatar.jpg"
  }
}
```

#### List Users

```
GET /users?offset=0&limit=10&search=john
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "user_123",
      "email": "john@example.com",
      "first_name": "John",
      "last_name": "Doe"
    }
  ],
  "total": 1,
  "pagination": {
    "offset": 0,
    "limit": 10,
    "total": 1
  }
}
```

### Organization Management

#### List Organizations

```
GET /organizations?offset=0&limit=10&search=acme
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "org_123",
      "name": "Acme Inc",
      "domain": "acme.com",
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1,
  "pagination": {
    "offset": 0,
    "limit": 10,
    "total": 1
  }
}
```

#### Create Organization

```
POST /organizations
```

Request:
```json
{
  "name": "Acme Inc",
  "domain": "acme.com",
  "logo_url": "https://acme.com/logo.png",
  "features": ["mfa", "passkeys", "sso"]
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "org_123",
    "name": "Acme Inc",
    "domain": "acme.com",
    "logo_url": "https://acme.com/logo.png",
    "created_at": "2023-01-01T00:00:00Z"
  }
}
```

#### Manage Organization Features

```
GET /organizations/{id}/features
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "key": "mfa",
      "enabled": true,
      "settings": {
        "required": false
      }
    },
    {
      "key": "passkeys",
      "enabled": true,
      "settings": {}
    }
  ]
}
```

```
POST /organizations/{id}/features
```

Request:
```json
{
  "feature_key": "sso",
  "settings": {
    "domains": ["acme.com"]
  }
}
```

Response:
```json
{
  "success": true,
  "data": {
    "message": "Feature enabled successfully"
  }
}
```

### API Keys

#### List API Keys

```
GET /api-keys?offset=0&limit=10&type=server
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "key_123",
      "name": "Server Key",
      "type": "server",
      "created_at": "2023-01-01T00:00:00Z",
      "last_used": "2023-01-02T00:00:00Z"
    }
  ],
  "total": 1,
  "pagination": {
    "offset": 0,
    "limit": 10,
    "total": 1
  }
}
```

#### Create API Key

```
POST /api-keys
```

Request:
```json
{
  "name": "Server Key",
  "type": "server",
  "permissions": ["read:users", "write:users"],
  "expires_in": 31536000
}
```

Response:
```json
{
  "success": true,
  "data": {
    "api_key": {
      "id": "key_123",
      "name": "Server Key",
      "type": "server",
      "created_at": "2023-01-01T00:00:00Z"
    },
    "key": "key_XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
  }
}
```

### Webhooks

#### List Webhooks

```
GET /webhooks?offset=0&limit=10
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "hook_123",
      "name": "User Created Hook",
      "url": "https://example.com/webhook",
      "event_types": ["user.created", "user.updated"],
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1,
  "pagination": {
    "offset": 0,
    "limit": 10,
    "total": 1
  }
}
```

#### Create Webhook

```
POST /webhooks
```

Request:
```json
{
  "name": "User Created Hook",
  "url": "https://example.com/webhook",
  "event_types": ["user.created", "user.updated"],
  "retry_count": 3
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "hook_123",
    "name": "User Created Hook",
    "url": "https://example.com/webhook",
    "event_types": ["user.created", "user.updated"],
    "retry_count": 3,
    "secret": "whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "created_at": "2023-01-01T00:00:00Z"
  }
}
```

## Rate Limiting

All API endpoints are subject to rate limiting. When a rate limit is exceeded, the server will respond with a 429 Too Many Requests status code and the following headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1672531200
Retry-After: 60
```

## Pagination

List endpoints support pagination with the following query parameters:

- `offset`: The number of items to skip (default: 0)
- `limit`: The maximum number of items to return (default: 20, max: 100)

## Searching and Filtering

List endpoints support searching and filtering with the following query parameters:

- `search`: Search term to filter results
- Additional filter parameters specific to each endpoint

## Webhook Events

Frank sends webhook notifications for the following events:

1. User events:
    - `user.created`
    - `user.updated`
    - `user.deleted`
    - `user.login`
    - `user.logout`

2. Organization events:
    - `organization.created`
    - `organization.updated`
    - `organization.deleted`
    - `organization.member_added`
    - `organization.member_removed`

3. Authentication events:
    - `auth.password_reset_requested`
    - `auth.password_reset_completed`
    - `auth.mfa_enrolled`
    - `auth.mfa_removed`
    - `auth.passkey_registered`
    - `auth.passkey_removed`

Webhook payloads include:

```json
{
  "event_type": "user.created",
  "timestamp": "2023-01-01T00:00:00Z",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com"
    }
  }
}
```

A signature is included in the `X-Signature` header for verification.