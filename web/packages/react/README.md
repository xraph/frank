# @frank-auth/react

> A comprehensive, highly configurable React authentication UI library for the Frank Auth multi-tenant SaaS platform.

[![npm version](https://badge.fury.io/js/%40frank-auth%2Freact.svg)](https://badge.fury.io/js/%40frank-auth%2Freact)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg)](http://www.typescriptlang.org/)

## 🌟 Features

- **🎨 Highly Customizable**: Server-driven configuration with complete theme control
- **🏢 Multi-Tenant**: Built-in organization management and switching
- **👥 Three-Tier Users**: Support for Internal, External, and End Users
- **🔐 Advanced Security**: MFA, Passkeys, OAuth, Magic Links
- **🌍 Internationalization**: 10+ languages with RTL support
- **♿ Accessibility**: WCAG 2.1 AA compliant
- **📱 Responsive**: Mobile-first design
- **⚡ Performance**: Tree-shaking, lazy loading, optimized bundles
- **🎯 TypeScript**: Full type safety and IntelliSense
- **🔧 Framework Agnostic**: Works with Next.js, Remix, Vite, and more

## 🚀 Quick Start

### Installation

```bash
npm install @frank-auth/react
# or
yarn add @frank-auth/react
# or
pnpm add @frank-auth/react
```

### Basic Setup

```tsx
import { FrankAuthProvider, SignIn, UserButton } from '@frank-auth/react';

function App() {
  return (
    <FrankAuthProvider publishableKey="pk_test_...">
      <div className="app">
        <nav>
          <UserButton />
        </nav>
        <main>
          <SignIn />
        </main>
      </div>
    </FrankAuthProvider>
  );
}
```

### Advanced Setup with Configuration

```tsx
import { 
  FrankAuthProvider, 
  SignIn, 
  UserButton,
  createFrankAuthConfig 
} from '@frank-auth/react';

const config = createFrankAuthConfig({
  appearance: {
    theme: 'auto',
    colors: {
      primary: '#6366f1',
      background: '#ffffff',
      foreground: '#0f172a',
    },
    elements: {
      formButtonPrimary: 'bg-indigo-600 hover:bg-indigo-700',
      card: 'shadow-xl border-2 border-indigo-100',
    },
  },
  authentication: {
    methods: ['email', 'oauth', 'passkey'],
    mfa: {
      enabled: true,
      methods: ['totp', 'sms'],
    },
    oauth: {
      providers: [
        { provider: 'google', enabled: true },
        { provider: 'github', enabled: true },
      ],
    },
  },
  organization: {
    enabled: true,
    allowInvitations: true,
    maxMembers: 50,
  },
});

function App() {
  return (
    <FrankAuthProvider 
      publishableKey="pk_test_..."
      config={config}
      onAuthEvent={(event) => {
        console.log('Auth event:', event);
      }}
    >
      <SignIn mode="modal" />
      <UserButton showProfile showOrganization />
    </FrankAuthProvider>
  );
}
```

## 🎯 Component Examples

### Authentication Components

#### SignIn Component

```tsx
import { SignIn } from '@frank-auth/react';

// Basic usage
<SignIn />

// Modal mode
<SignIn mode="modal" />

// Custom appearance
<SignIn 
  appearance={{
    elements: {
      formButtonPrimary: 'bg-blue-600 hover:bg-blue-700',
      card: 'rounded-2xl shadow-2xl',
    }
  }}
/>

// With custom handlers
<SignIn 
  onSignInSuccess={(user) => {
    console.log('Welcome back!', user);
    // Custom redirect or action
  }}
  onSignInError={(error) => {
    console.error('Sign in failed:', error);
    // Custom error handling
  }}
/>

// Limited authentication methods
<SignIn 
  allowedMethods={['email', 'oauth']}
  redirectAfterSignIn="/dashboard"
/>
```

#### SignUp Component

```tsx
import { SignUp } from '@frank-auth/react';

// Basic usage
<SignUp />

// With custom fields
<SignUp 
  customFields={[
    {
      id: 'company',
      name: 'Company Name',
      type: 'text',
      required: true,
    },
    {
      id: 'role',
      name: 'Role',
      type: 'select',
      options: [
        { value: 'developer', label: 'Developer' },
        { value: 'designer', label: 'Designer' },
        { value: 'manager', label: 'Manager' },
      ],
    },
  ]}
/>
```

#### UserButton Component

```tsx
import { UserButton } from '@frank-auth/react';

// Basic usage
<UserButton />

// With custom actions
<UserButton 
  customActions={[
    {
      label: 'Settings',
      action: () => navigate('/settings'),
      icon: <SettingsIcon />,
    },
    {
      label: 'Billing',
      action: () => navigate('/billing'),
      icon: <CreditCardIcon />,
    },
  ]}
/>

// Show specific sections
<UserButton 
  showProfile={true}
  showOrganization={true}
  showSessions={true}
/>
```

### Organization Components

#### Organization Switcher

```tsx
import { OrganizationSwitcher } from '@frank-auth/react';

// Basic usage
<OrganizationSwitcher />

// With creation and switching
<OrganizationSwitcher 
  allowCreation={true}
  allowSwitching={true}
  showMembers={true}
/>

// Custom appearance
<OrganizationSwitcher 
  appearance={{
    elements: {
      organizationSwitcher: 'rounded-lg border-2',
    }
  }}
/>
```

#### Organization Profile

```tsx
import { OrganizationProfile } from '@frank-auth/react';

// Full organization management
<OrganizationProfile 
  showMembers={true}
  showSettings={true}
  showBilling={true}
/>
```

## 🎨 Customization

### Theme Configuration

```tsx
const customTheme = {
  name: 'custom-theme',
  colors: {
    primary: '#8b5cf6',
    secondary: '#06b6d4',
    background: '#fafafa',
    foreground: '#18181b',
    muted: '#f4f4f5',
    accent: '#f59e0b',
    destructive: '#ef4444',
    border: '#e4e4e7',
    input: '#ffffff',
    ring: '#8b5cf6',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
  },
  typography: {
    fontFamily: 'Inter, -apple-system, sans-serif',
    fontSize: {
      xs: '0.75rem',
      sm: '0.875rem',
      base: '1rem',
      lg: '1.125rem',
      xl: '1.25rem',
      '2xl': '1.5rem',
      '3xl': '1.875rem',
    },
  },
  layout: {
    borderRadius: '0.75rem',
    spacing: {
      xs: '0.25rem',
      sm: '0.5rem',
      md: '1rem',
      lg: '1.5rem',
      xl: '3rem',
    },
  },
};

<FrankAuthProvider 
  publishableKey="pk_test_..."
  config={{
    appearance: {
      theme: customTheme,
    }
  }}
>
  {/* Your app */}
</FrankAuthProvider>
```

### Component Overrides

```tsx
import { FrankAuthProvider } from '@frank-auth/react';
import { CustomSignIn, CustomUserButton } from './custom-components';

<FrankAuthProvider 
  publishableKey="pk_test_..."
  config={{
    components: {
      SignIn: CustomSignIn,
      UserButton: CustomUserButton,
    }
  }}
>
  {/* Your app */}
</FrankAuthProvider>
```

### CSS-in-JS Customization

```tsx
const config = {
  appearance: {
    elements: {
      // Form elements
      formButtonPrimary: 'bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white font-semibold py-2 px-4 rounded-lg shadow-lg transform transition hover:scale-105',
      formFieldInput: 'border-2 border-gray-200 focus:border-purple-500 rounded-lg px-3 py-2 transition-colors',
      formFieldLabel: 'text-sm font-medium text-gray-700 mb-1',
      
      // Cards
      card: 'bg-white/80 backdrop-blur-sm border border-gray-200 rounded-2xl shadow-xl',
      cardHeader: 'border-b border-gray-100 p-6',
      cardBody: 'p-6',
      
      // Modal
      modalOverlay: 'fixed inset-0 bg-black/50 backdrop-blur-sm',
      modalContent: 'bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4',
      
      // User interface
      userButton: 'flex items-center space-x-2 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors',
      organizationSwitcher: 'border border-gray-200 rounded-lg p-2 hover:bg-gray-50',
    },
    variables: {
      '--frank-auth-primary': '#8b5cf6',
      '--frank-auth-radius': '0.75rem',
      '--frank-auth-shadow': '0 10px 25px -5px rgba(0, 0, 0, 0.1)',
    },
  },
};
```

## 🔧 Hooks Usage

### useAuth Hook

```tsx
import { useAuth } from '@frank-auth/react';

function MyComponent() {
  const { 
    isLoaded, 
    isSignedIn, 
    user, 
    signOut,
    organization,
    switchOrganization 
  } = useAuth();

  if (!isLoaded) {
    return <div>Loading...</div>;
  }

  if (!isSignedIn) {
    return <div>Please sign in</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.firstName}!</h1>
      <p>Organization: {organization?.name}</p>
      <button onClick={() => signOut()}>
        Sign Out
      </button>
    </div>
  );
}
```

### useOrganization Hook

```tsx
import { useOrganization } from '@frank-auth/react';

function OrganizationDashboard() {
  const { 
    organization, 
    members, 
    invitations,
    isAdmin,
    inviteMember,
    removeMember 
  } = useOrganization();

  const handleInvite = async (email: string, role: string) => {
    try {
      await inviteMember({ email, role });
      toast.success('Invitation sent!');
    } catch (error) {
      toast.error('Failed to send invitation');
    }
  };

  return (
    <div>
      <h1>{organization.name}</h1>
      <p>{members.length} members</p>
      
      {isAdmin && (
        <button onClick={() => handleInvite('user@example.com', 'member')}>
          Invite Member
        </button>
      )}
    </div>
  );
}
```

### usePermissions Hook

```tsx
import { usePermissions } from '@frank-auth/react';

function AdminPanel() {
  const { hasPermission, hasRole, checkPermission } = usePermissions();

  const canManageUsers = hasPermission('users:write');
  const isAdmin = hasRole('admin');
  const canDeletePosts = checkPermission('posts:delete', { resourceId: 'post-123' });

  return (
    <div>
      {canManageUsers && (
        <button>Manage Users</button>
      )}
      
      {isAdmin && (
        <button>Admin Settings</button>
      )}
      
      {canDeletePosts && (
        <button>Delete Post</button>
      )}
    </div>
  );
}
```

## 🌐 Multi-Tenant Examples

### Organization-Specific Branding

```tsx
// This configuration is automatically loaded from your Frank Auth backend
// based on the current organization context

function App() {
  return (
    <FrankAuthProvider 
      publishableKey="pk_test_..."
      organizationId="org_acme_corp"
      onConfigLoad={(serverConfig) => {
        // Server config includes organization-specific branding
        console.log('Organization theme:', serverConfig.theme);
        console.log('Organization logo:', serverConfig.branding.logo);
      }}
    >
      <SignIn />
    </FrankAuthProvider>
  );
}
```

### Dynamic User Type Handling

```tsx
import { useAuth, configureForUserType } from '@frank-auth/react';

function AppWrapper() {
  const { user } = useAuth();
  
  // Configure based on user type
  const config = configureForUserType(user?.type || 'end-users', {
    appearance: {
      theme: user?.type === 'internal' ? 'dark' : 'light',
    },
  });

  return (
    <FrankAuthProvider 
      publishableKey="pk_test_..."
      config={config}
    >
      <App />
    </FrankAuthProvider>
  );
}
```

## 🔐 Advanced Security Features

### Multi-Factor Authentication

```tsx
import { useMfa } from '@frank-auth/react';

function SecuritySettings() {
  const { 
    mfaEnabled, 
    availableMethods, 
    enableMfa, 
    disableMfa,
    generateBackupCodes 
  } = useMfa();

  const handleEnableMfa = async (method: 'totp' | 'sms') => {
    try {
      const qrCode = await enableMfa(method);
      // Show QR code to user for TOTP setup
    } catch (error) {
      console.error('Failed to enable MFA:', error);
    }
  };

  return (
    <div>
      <h2>Two-Factor Authentication</h2>
      <p>Status: {mfaEnabled ? 'Enabled' : 'Disabled'}</p>
      
      {!mfaEnabled && (
        <div>
          <button onClick={() => handleEnableMfa('totp')}>
            Enable Authenticator App
          </button>
          <button onClick={() => handleEnableMfa('sms')}>
            Enable SMS
          </button>
        </div>
      )}
      
      {mfaEnabled && (
        <div>
          <button onClick={generateBackupCodes}>
            Generate Backup Codes
          </button>
          <button onClick={disableMfa}>
            Disable MFA
          </button>
        </div>
      )}
    </div>
  );
}
```

### Passkey Integration

```tsx
import { usePasskeys } from '@frank-auth/react';

function PasskeySettings() {
  const { 
    passkeys, 
    registerPasskey, 
    removePasskey,
    isSupported 
  } = usePasskeys();

  if (!isSupported) {
    return <div>Passkeys are not supported in this browser</div>;
  }

  const handleRegister = async () => {
    try {
      await registerPasskey({ name: 'My Device' });
      toast.success('Passkey registered successfully!');
    } catch (error) {
      toast.error('Failed to register passkey');
    }
  };

  return (
    <div>
      <h2>Passkeys</h2>
      <button onClick={handleRegister}>
        Add Passkey
      </button>
      
      <div className="mt-4">
        {passkeys.map((passkey) => (
          <div key={passkey.id} className="flex items-center justify-between p-3 border rounded">
            <div>
              <p className="font-medium">{passkey.name}</p>
              <p className="text-sm text-gray-500">
                Added {new Date(passkey.createdAt).toLocaleDateString()}
              </p>
            </div>
            <button 
              onClick={() => removePasskey(passkey.id)}
              className="text-red-600 hover:text-red-800"
            >
              Remove
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
```

## 🚀 Framework Integration

### Next.js Integration

```tsx
// pages/_app.tsx
import { FrankAuthProvider } from '@frank-auth/react';
import type { AppProps } from 'next/app';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <FrankAuthProvider publishableKey={process.env.NEXT_PUBLIC_FRANK_AUTH_PUBLISHABLE_KEY!}>
      <Component {...pageProps} />
    </FrankAuthProvider>
  );
}

// pages/dashboard.tsx
import { RequireAuth } from '@frank-auth/react';

export default function Dashboard() {
  return (
    <RequireAuth>
      <div>
        <h1>Dashboard</h1>
        {/* Protected content */}
      </div>
    </RequireAuth>
  );
}
```

### Remix Integration

```tsx
// app/root.tsx
import { FrankAuthProvider } from '@frank-auth/react';

export default function App() {
  return (
    <html>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
      </head>
      <body>
        <FrankAuthProvider publishableKey={ENV.FRANK_AUTH_PUBLISHABLE_KEY}>
          <Outlet />
        </FrankAuthProvider>
      </body>
    </html>
  );
}
```

## 📱 Mobile and Responsive Design

All components are mobile-first and responsive by default:

```tsx
// Components automatically adapt to screen size
<SignIn mode="card" /> // Becomes full-screen on mobile

// Custom responsive behavior
<UserButton 
  className="hidden md:block" // Hide on mobile
/>

<UserButton 
  className="md:hidden" // Show only on mobile
  showProfile={false} // Simplified mobile view
/>
```

## 🌍 Internationalization

```tsx
import { FrankAuthProvider } from '@frank-auth/react';

const config = {
  localization: {
    defaultLocale: 'en',
    supportedLocales: ['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh'],
    customTranslations: {
      'es': {
        'sign_in': 'Iniciar Sesión',
        'sign_up': 'Registrarse',
        'welcome_back': 'Bienvenido de vuelta',
      },
    },
  },
};

<FrankAuthProvider 
  publishableKey="pk_test_..."
  config={config}
>
  {/* Components will use Spanish translations */}
</FrankAuthProvider>
```

## 🔧 Development and Debugging

### Debug Mode

```tsx
<FrankAuthProvider 
  publishableKey="pk_test_..."
  config={{
    advanced: {
      debug: true, // Enable debug logging
      telemetry: false, // Disable telemetry in development
    }
  }}
>
  <App />
</FrankAuthProvider>
```

### Dev Tools

```tsx
import { AuthDevTools } from '@frank-auth/react';

function App() {
  return (
    <div>
      {/* Your app */}
      {process.env.NODE_ENV === 'development' && <AuthDevTools />}
    </div>
  );
}
```

## 📚 API Reference

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `publishableKey` | `string` | Your Frank Auth publishable key |
| `organizationId` | `string` | Current organization ID |
| `appearance` | `AppearanceConfig` | Theme and styling configuration |
| `authentication` | `AuthenticationConfig` | Authentication methods and settings |
| `organization` | `OrganizationConfig` | Organization features and settings |
| `localization` | `LocalizationConfig` | Language and locale settings |
| `components` | `ComponentOverrides` | Custom component overrides |
| `advanced` | `AdvancedConfig` | Advanced options and debugging |

### Component Props

All components accept these common props:

| Prop | Type | Description |
|------|------|-------------|
| `className` | `string` | Additional CSS classes |
| `appearance` | `Partial<AppearanceConfig>` | Component-specific appearance |
| `onSuccess` | `(result: any) => void` | Success callback |
| `onError` | `(error: Error) => void` | Error callback |

## 🤝 Migration from ClerkJS

Frank Auth React is designed to be API-compatible with ClerkJS for easy migration:

```tsx
// Before (ClerkJS)
import { ClerkProvider, SignIn, UserButton } from '@clerk/nextjs';

<ClerkProvider publishableKey="pk_test_...">
  <SignIn />
  <UserButton />
</ClerkProvider>

// After (Frank Auth)
import { FrankAuthProvider, SignIn, UserButton } from '@frank-auth/react';

<FrankAuthProvider publishableKey="pk_test_...">
  <SignIn />
  <UserButton />
</FrankAuthProvider>
```

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📞 Support

- 📧 Email: support@frankauth.com
- 💬 Discord: [Join our community](https://discord.gg/frankauth)
- 📖 Documentation: [docs.frankauth.com](https://docs.frankauth.com)
- 🐛 Issues: [GitHub Issues](https://github.com/frankauth/react/issues)

---

Made with ❤️ by the Frank Auth team