### Initialize the SDK
```typescript jsx
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

### Use Authentication Hooks
```typescript jsx
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

### Use Organization Context
```typescript jsx
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

### Next.js Integration
```typescript jsx
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

```typescript jsx
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