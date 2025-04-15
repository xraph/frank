# @frank-auth/react

React SDK for Frank Authentication. Simplifies authentication and organization management in React applications.

## Features

- Easy authentication with React hooks
- Next.js middleware integration
- Organization context management
- Token management and auto-refresh
- TypeScript support

## Installation

```bash
npm install @frank-auth/react
# or
yarn add @frank-auth/react
```

## Quick Start

### 1. Initialize the SDK

```tsx
import { AuthProvider, setConfig } from '@frank-auth/react';

// Initialize SDK configuration
setConfig({
  baseUrl: 'https://auth.yourapi.com',
  // Optional configuration
  storagePrefix: 'your_app_',
  tokenStorageType: 'localStorage', // 'localStorage', 'sessionStorage', 'cookie', or 'memory'
});

// Wrap your app with the provider
const App = () => {
  return (
    <AuthProvider>
      <YourApp />
    </AuthProvider>
  );
};
```

### 2. Use Authentication Hooks

```tsx
import { useLogin, useAuth, useLogout } from '@frank-auth/react';

const LoginForm = () => {
  const { login, isLoading, error } = useLogin();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login({ email, password });
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Your form fields */}
      {isLoading && <p>Loading...</p>}
      {error && <p>Error: {error.message}</p>}
    </form>
  );
};

const UserProfile = () => {
  const { user, isAuthenticated } = useAuth();
  const { logout } = useLogout();

  if (!isAuthenticated) {
    return <p>Please log in</p>;
  }

  return (
    <div>
      <h1>Welcome, {user.email}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
};
```

### 3. Use Organization Context

```tsx
import { OrganizationProvider, useOrganization } from '@frank-auth/react';

const App = () => {
  return (
    <AuthProvider>
      <OrganizationProvider>
        <YourApp />
      </OrganizationProvider>
    </AuthProvider>
  );
};

const OrganizationSelector = () => {
  const { 
    listOrganizations, 
    switchOrganization, 
    currentOrganization 
  } = useOrganization();
  const [organizations, setOrganizations] = useState([]);

  useEffect(() => {
    listOrganizations().then(setOrganizations);
  }, []);

  return (
    <div>
      <h2>Select Organization</h2>
      <ul>
        {organizations.map(org => (
          <li key={org.id}>
            <button onClick={() => switchOrganization(org.id)}>
              {org.name}
            </button>
          </li>
        ))}
      </ul>
      {currentOrganization && (
        <p>Current: {currentOrganization.name}</p>
      )}
    </div>
  );
};
```

### 4. Next.js Integration

```tsx
// middleware.ts
import { createNextAuthMiddleware } from '@frank-auth/react/next';

export const middleware = createNextAuthMiddleware({
  protectedPages: ['/dashboard', '/settings', '/profile'],
  publicPages: ['/', '/about', '/contact'],
  authPages: ['/login', '/register'],
  loginPage: '/login',
  orgRequired: true
});

export const config = {
  matcher: ['/((?!api|_next/static|favicon.ico).*)']
};
```

```tsx
// _app.tsx or layout.tsx
import { AuthProvider, OrganizationProvider, getNextAuthConfig } from '@frank-auth/react';
import { setConfig } from '@frank-auth/react';

function MyApp({ Component, pageProps }) {
  // Initialize config from server-side data
  const authConfig = getNextAuthConfig();
  setConfig(authConfig);

  return (
    <AuthProvider>
      <OrganizationProvider>
        <Component {...pageProps} />
      </OrganizationProvider>
    </AuthProvider>
  );
}

export default MyApp;
```

## API Reference

### Hooks

- `useAuth()` - Access authentication context
- `useLogin()` - Login functionality
- `useLogout()` - Logout functionality
- `useRegister()` - User registration
- `useUser()` - Current user information
- `useOrganization()` - Organization context

### Providers

- `<AuthProvider>` - Authentication provider
- `<OrganizationProvider>` - Organization context provider

### Configuration

- `setConfig(config)` - Set SDK configuration
- `getConfig()` - Get current configuration

### Utilities

- Token management: `getToken()`, `setTokenData()`, etc.
- Storage: `getItem()`, `setItem()`, etc.
- API clients: `createApiClient()`, `getAuthClient()`

## Organization Context

The SDK provides built-in support for multi-tenant applications through the organization context:

```tsx
// Switch the current organization context
const { switchOrganization } = useOrganization();
await switchOrganization('org-123');

// Or initialize with a specific organization
<AuthProvider organizationId="org-123">
  <YourApp />
</AuthProvider>
```

When an organization is selected, all API requests will include the organization ID in the headers.

## Advanced Usage

### Custom Storage

You can customize where authentication tokens are stored:

```tsx
setConfig({
  baseUrl: 'https://auth.yourapi.com',
  tokenStorageType: 'cookie', // 'localStorage', 'sessionStorage', 'cookie', or 'memory'
  storagePrefix: 'your_app_'
});
```

### Token Refresh

The SDK automatically handles token refresh when tokens expire:

```tsx
// Get an authenticated client that will refresh tokens if needed
import { getAuthClient } from '@frank-auth/react';

const fetchUserData = async () => {
  const client = await getAuthClient();
  const { data } = await client.get({ url: '/v1/user/profile' });
  return data;
};
```

### Custom Auth Logic

You can build custom authentication flows:

```tsx
import { setTokenData, clearTokenData } from '@frank-auth/react';

// Custom SSO integration
const handleSsoCallback = (tokenResponse) => {
  setTokenData({
    token: tokenResponse.access_token,
    refreshToken: tokenResponse.refresh_token,
    expiresAt: Date.now() + tokenResponse.expires_in * 1000
  });
  
  // Redirect to dashboard
  navigate('/dashboard');
};

// Handle logout on token invalidation
const handleApiError = (error) => {
  if (error.status === 401) {
    clearTokenData();
    navigate('/login');
  }
};
```

## TypeScript Support

The SDK is built with TypeScript and provides comprehensive type definitions:

```tsx
import { User, OrganizationResponse, TokenData } from '@frank-auth/react';

// Type-safe authentication functions
const handleLogin = async (credentials: LoginRequest): Promise<User | null> => {
  // ...
};

// Type-safe organization functions
const handleSwitchOrg = async (orgId: string): Promise<OrganizationResponse | null> => {
  // ...
};
```

## License

MIT