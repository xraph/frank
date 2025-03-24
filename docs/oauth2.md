# Frank OAuth2 Provider Documentation

## Overview

Frank functions as both an OAuth2 client (connecting to external providers like Google, GitHub, etc.) and as an OAuth2 provider (allowing third-party applications to authenticate with Frank).

This document focuses on Frank's capabilities as an OAuth2 provider, covering implementation details, supported flows, and integration guidelines.

## Supported OAuth2 Flows

Frank supports the following OAuth2 authorization flows:

1. **Authorization Code Flow** - The standard OAuth2 flow for server-side applications
2. **Authorization Code Flow with PKCE** - For mobile and single-page applications
3. **Client Credentials Flow** - For machine-to-machine (M2M) authentication
4. **Refresh Token Flow** - For obtaining new access tokens without re-authentication

## OpenID Connect Features

Frank implements the OpenID Connect (OIDC) protocol on top of OAuth2, providing:

- Standard OIDC scopes (`openid`, `profile`, `email`)
- ID token issuance
- UserInfo endpoint
- Discovery endpoint (`.well-known/openid-configuration`)
- JWKS endpoint for key rotation

## Endpoints

### Authorization Endpoint

```
GET /oauth/authorize
```

Parameters:
- `client_id` (required): The client identifier
- `redirect_uri` (required): The URI to redirect to after authorization
- `response_type` (required): Must be `code` for authorization code flow
- `scope` (optional): Space-separated list of scopes
- `state` (recommended): Random string for CSRF protection
- `code_challenge` (required for PKCE): The code challenge
- `code_challenge_method` (required for PKCE): Method used to derive the challenge, either `plain` or `S256`

Example:
```
GET /oauth/authorize?
  client_id=client123&
  redirect_uri=https://client.example.com/callback&
  response_type=code&
  scope=openid profile email&
  state=af0ifjsldkj&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### Token Endpoint

```
POST /oauth/token
```

Parameters (authorization code grant):
- `grant_type` (required): Must be `authorization_code`
- `code` (required): The authorization code
- `redirect_uri` (required): Must match the original redirect URI
- `client_id` (required): The client identifier
- `client_secret` (required for confidential clients): The client secret
- `code_verifier` (required for PKCE): The code verifier

Parameters (refresh token grant):
- `grant_type` (required): Must be `refresh_token`
- `refresh_token` (required): The refresh token
- `client_id` (required): The client identifier
- `client_secret` (required for confidential clients): The client secret

Parameters (client credentials grant):
- `grant_type` (required): Must be `client_credentials`
- `scope` (optional): Space-separated list of scopes
- `client_id` (required): The client identifier
- `client_secret` (required): The client secret

Example response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### UserInfo Endpoint

```
GET /oauth/userinfo
```

Header:
- `Authorization: Bearer {access_token}`

Example response:
```json
{
  "sub": "user_123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/profile.jpg"
}
```

### Token Introspection Endpoint

```
POST /oauth/introspect
```

Parameters:
- `token` (required): The token to introspect
- `token_type_hint` (optional): Either `access_token` or `refresh_token`
- `client_id` (required): The client identifier
- `client_secret` (required for confidential clients): The client secret

Example response:
```json
{
  "active": true,
  "client_id": "client123",
  "scope": "openid profile email",
  "sub": "user_123",
  "exp": 1672531200,
  "iat": 1672527600,
  "token_type": "Bearer"
}
```

### Token Revocation Endpoint

```
POST /oauth/revoke
```

Parameters:
- `token` (required): The token to revoke
- `token_type_hint` (optional): Either `access_token` or `refresh_token`
- `client_id` (required): The client identifier
- `client_secret` (required for confidential clients): The client secret

### OpenID Connect Discovery Endpoint

```
GET /.well-known/openid-configuration
```

Example response:
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "