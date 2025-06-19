# Frank Auth TypeScript Client

Official TypeScript client for the Frank Authentication API. Uses native fetch API for HTTP requests.

## Installation

```bash
npm install @frank-auth/client
```

## Usage

```typescript
import { Configuration, AuthApi, UsersApi } from '@frank-auth/client';

// Configure the client
const config = new Configuration({
  basePath: 'https://api.frankauth.com/v1',
  apiKey: 'your-api-key',
  // or use Bearer token
  // accessToken: 'your-access-token',
});

// Create API instances
const authApi = new AuthApi(config);
const usersApi = new UsersApi(config);

// Example: Login
try {
  const response = await authApi.login({
    loginRequest: {
      email: 'user@example.com',
      password: 'password123'
    }
  });
  console.log('Login successful:', response);
} catch (error) {
  console.error('Login failed:', error);
}

// Example: Get user profile
try {
  const profile = await usersApi.getCurrentUser();
  console.log('User profile:', profile);
} catch (error) {
  console.error('Failed to get user profile:', error);
}
```

## Advanced Configuration

```typescript
import { Configuration, AuthApi } from '@frank-auth/client';

const config = new Configuration({
  basePath: 'https://api.frankauth.com/v1',
  apiKey: 'your-api-key',
  fetchApi: fetch, // Use custom fetch implementation if needed
  middleware: [
    {
      pre: async (context) => {
        // Custom request middleware
        console.log('Making request to:', context.url);
        return Promise.resolve(context);
      },
      post: async (context) => {
        // Custom response middleware
        console.log('Response status:', context.response.status);
        return Promise.resolve(context.response);
      }
    }
  ]
});

const authApi = new AuthApi(config);
```

## API Reference

This client provides full access to the Frank Authentication API. See the [API documentation](https://docs.frankauth.com) for detailed information about available endpoints and operations.

## Error Handling

The client uses the native fetch API for HTTP requests. All API methods return promises that resolve to the response data or reject with an error.

```typescript
try {
  const result = await authApi.login({
    loginRequest: {
      email: 'user@example.com',
      password: 'password123'
    }
  });
  // Handle success
  console.log('Login successful:', result);
} catch (error) {
  if (error instanceof Response) {
    // HTTP error response
    console.error('HTTP Error:', error.status, error.statusText);
    const errorBody = await error.text();
    console.error('Error body:', errorBody);
  } else {
    // Network error or other issue
    console.error('Network/Other error:', error.message);
  }
}
```

## Configuration Options

- `basePath`: API base URL (default: 'https://api.frankauth.com/v1')
- `apiKey`: API key for authentication
- `accessToken`: Bearer token for authentication
- `username`: Username for basic auth
- `password`: Password for basic auth
- `fetchApi`: Custom fetch implementation (defaults to global fetch)
- `middleware`: Array of middleware for request/response processing

## Browser Compatibility

This client uses the native fetch API, which is supported in:
- Chrome 42+
- Firefox 39+
- Safari 10.1+
- Edge 14+

For older browsers, you may need to include a fetch polyfill:

```bash
npm install whatwg-fetch
```

```typescript
import 'whatwg-fetch';
import { Configuration, AuthApi } from '@frank-auth/client';
```

## Development

```bash
# Install dependencies
npm install

# Build the client
npm run build

# Run tests
npm test

# Lint code
npm run lint
```

## Project Structure

```
typescript/
├── src/           # Generated TypeScript source files
│   ├── apis/      # API endpoint classes
│   ├── models/    # Type definitions and models
│   └── runtime.ts # Runtime utilities
├── dist/          # Compiled JavaScript output
├── package.json
├── tsconfig.json
└── README.md
```

## TypeScript Support

This client is written in TypeScript and provides full type safety:

```typescript
import { User, Organization, LoginRequest } from '@frank-auth/client';

// All types are automatically inferred
const loginRequest: LoginRequest = {
  email: 'user@example.com',
  password: 'password123'
};

// Response types are strongly typed
const user: User = await usersApi.getCurrentUser();
const org: Organization = await orgApi.getOrganization({ orgId: user.organizationId });
```
