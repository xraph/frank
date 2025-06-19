# 🎨 @frank-auth/react - Configurable Auth UI Library

## 🏗️ Complete Project Structure

```
packages/
├── react/                           # Main @frank-auth/react package
│   ├── src/
│   │   ├── index.ts                 # Main entry point
│   │   │
│   │   ├── provider/                # Auth Provider & Context
│   │   │   ├── index.ts
│   │   │   ├── auth-provider.tsx    # Main auth provider
│   │   │   ├── config-provider.tsx  # UI configuration provider
│   │   │   ├── theme-provider.tsx   # Theme customization provider
│   │   │   └── types.ts             # Provider types
│   │   │
│   │   ├── components/              # Core UI Components
│   │   │   ├── index.ts             # Export all components
│   │   │   │
│   │   │   ├── auth/                # Authentication Components
│   │   │   │   ├── index.ts
│   │   │   │   ├── sign-in/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── sign-in.tsx          # Main sign-in component
│   │   │   │   │   ├── sign-in-form.tsx     # Sign-in form
│   │   │   │   │   ├── sign-in-modal.tsx    # Modal variant
│   │   │   │   │   ├── sign-in-button.tsx   # Sign-in trigger button
│   │   │   │   │   └── sign-in-card.tsx     # Card variant
│   │   │   │   ├── sign-up/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── sign-up.tsx          # Main sign-up component
│   │   │   │   │   ├── sign-up-form.tsx     # Sign-up form
│   │   │   │   │   ├── sign-up-modal.tsx    # Modal variant
│   │   │   │   │   ├── sign-up-button.tsx   # Sign-up trigger button
│   │   │   │   │   └── sign-up-card.tsx     # Card variant
│   │   │   │   ├── user-button/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── user-button.tsx      # User menu button
│   │   │   │   │   ├── user-profile.tsx     # User profile dropdown
│   │   │   │   │   └── user-avatar.tsx      # User avatar component
│   │   │   │   ├── user-profile/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── user-profile.tsx     # Full user profile
│   │   │   │   │   ├── user-profile-modal.tsx # Modal variant
│   │   │   │   │   ├── profile-form.tsx     # Profile editing form
│   │   │   │   │   ├── security-panel.tsx   # Security settings
│   │   │   │   │   ├── mfa-setup.tsx        # MFA configuration
│   │   │   │   │   └── passkey-setup.tsx    # Passkey configuration
│   │   │   │   ├── organization/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── org-switcher.tsx     # Organization switcher
│   │   │   │   │   ├── org-profile.tsx      # Organization profile
│   │   │   │   │   ├── org-members.tsx      # Member management
│   │   │   │   │   ├── org-invitations.tsx  # Invitation management
│   │   │   │   │   └── org-settings.tsx     # Organization settings
│   │   │   │   ├── session/
│   │   │   │   │   ├── index.ts
│   │   │   │   │   ├── session-manager.tsx  # Session management
│   │   │   │   │   ├── device-list.tsx      # Active devices
│   │   │   │   │   └── session-card.tsx     # Individual session
│   │   │   │   └── common/
│   │   │   │       ├── index.ts
│   │   │   │       ├── oauth-buttons.tsx    # OAuth provider buttons
│   │   │   │       ├── magic-link.tsx       # Magic link component
│   │   │   │       ├── loading-spinner.tsx  # Loading states
│   │   │   │       ├── error-boundary.tsx   # Error handling
│   │   │   │       └── redirect-handler.tsx # Auth redirects
│   │   │   │
│   │   │   ├── forms/               # Form Components
│   │   │   │   ├── index.ts
│   │   │   │   ├── password-field.tsx       # Password input with validation
│   │   │   │   ├── email-field.tsx          # Email input with validation
│   │   │   │   ├── phone-field.tsx          # Phone input with validation
│   │   │   │   ├── verification-code.tsx    # OTP/verification code input
│   │   │   │   ├── form-wrapper.tsx         # Form container with validation
│   │   │   │   └── field-error.tsx          # Field error display
│   │   │   │
│   │   │   ├── layout/              # Layout Components
│   │   │   │   ├── index.ts
│   │   │   │   ├── auth-layout.tsx          # Authentication layout
│   │   │   │   ├── protected-layout.tsx     # Protected page layout
│   │   │   │   ├── modal-layout.tsx         # Modal layout
│   │   │   │   └── card-layout.tsx          # Card layout
│   │   │   │
│   │   │   └── ui/                  # Base UI Components (shadcn references)
│   │   │       ├── index.ts
│   │   │       ├── button.tsx               # Button component wrapper
│   │   │       ├── input.tsx                # Input component wrapper
│   │   │       ├── card.tsx                 # Card component wrapper
│   │   │       ├── dialog.tsx               # Dialog component wrapper
│   │   │       ├── dropdown.tsx             # Dropdown component wrapper
│   │   │       ├── toast.tsx                # Toast component wrapper
│   │   │       ├── avatar.tsx               # Avatar component wrapper
│   │   │       ├── badge.tsx                # Badge component wrapper
│   │   │       ├── separator.tsx            # Separator component wrapper
│   │   │       └── loading.tsx              # Loading component wrapper
│   │   │
│   │   ├── hooks/                   # Custom React Hooks
│   │   │   ├── index.ts
│   │   │   ├── use-auth.ts          # Main auth hook
│   │   │   ├── use-user.ts          # User-specific operations
│   │   │   ├── use-session.ts       # Session management
│   │   │   ├── use-organization.ts  # Organization operations
│   │   │   ├── use-config.ts        # Configuration hook
│   │   │   ├── use-theme.ts         # Theme customization
│   │   │   ├── use-permissions.ts   # Permission checking
│   │   │   ├── use-mfa.ts           # MFA operations
│   │   │   ├── use-passkeys.ts      # Passkey operations
│   │   │   ├── use-oauth.ts         # OAuth operations
│   │   │   └── use-magic-link.ts    # Magic link operations
│   │   │
│   │   ├── config/                  # Configuration System
│   │   │   ├── index.ts
│   │   │   ├── types.ts             # Configuration types
│   │   │   ├── defaults.ts          # Default configurations
│   │   │   ├── theme.ts             # Theme configuration
│   │   │   ├── validators.ts        # Config validation
│   │   │   ├── appearance.ts        # Appearance configuration
│   │   │   ├── localization.ts      # Localization configuration
│   │   │   └── organization.ts      # Organization-specific config
│   │   │
│   │   ├── types/                   # TypeScript Type Definitions
│   │   │   ├── index.ts
│   │   │   ├── auth.ts              # Auth-related types
│   │   │   ├── user.ts              # User types
│   │   │   ├── organization.ts      # Organization types
│   │   │   ├── session.ts           # Session types
│   │   │   ├── config.ts            # Configuration types
│   │   │   ├── theme.ts             # Theme types
│   │   │   ├── component.ts         # Component prop types
│   │   │   ├── api.ts               # API types
│   │   │   └── events.ts            # Event types
│   │   │
│   │   ├── utils/                   # Utility Functions
│   │   │   ├── index.ts
│   │   │   ├── api.ts               # API utilities
│   │   │   ├── auth.ts              # Auth utilities
│   │   │   ├── validation.ts        # Form validation utilities
│   │   │   ├── storage.ts           # Storage utilities
│   │   │   ├── crypto.ts            # Cryptographic utilities
│   │   │   ├── url.ts               # URL utilities
│   │   │   ├── format.ts            # Formatting utilities
│   │   │   ├── error.ts             # Error handling utilities
│   │   │   └── theme.ts             # Theme utilities
│   │   │
│   │   ├── styles/                  # Styling System
│   │   │   ├── index.ts
│   │   │   ├── globals.css          # Global styles
│   │   │   ├── components.css       # Component styles
│   │   │   ├── themes/              # Theme definitions
│   │   │   │   ├── default.css      # Default theme
│   │   │   │   ├── dark.css         # Dark theme
│   │   │   │   ├── light.css        # Light theme
│   │   │   │   └── custom.css       # Custom theme template
│   │   │   └── variables.css        # CSS custom properties
│   │   │
│   │   ├── locales/                 # Internationalization
│   │   │   ├── index.ts
│   │   │   ├── en.ts                # English (default)
│   │   │   ├── es.ts                # Spanish
│   │   │   ├── fr.ts                # French
│   │   │   ├── de.ts                # German
│   │   │   ├── pt.ts                # Portuguese
│   │   │   ├── it.ts                # Italian
│   │   │   ├── ja.ts                # Japanese
│   │   │   ├── ko.ts                # Korean
│   │   │   ├── zh.ts                # Chinese
│   │   │   └── types.ts             # Locale types
│   │   │
│   │   └── internal/                # Internal utilities (not exported)
│   │       ├── constants.ts         # Internal constants
│   │       ├── errors.ts            # Internal error types
│   │       ├── logger.ts            # Internal logging
│   │       └── debug.ts             # Debug utilities
│   │
│   ├── examples/                    # Usage Examples
│   │   ├── basic/                   # Basic usage examples
│   │   │   ├── sign-in.tsx
│   │   │   ├── sign-up.tsx
│   │   │   ├── user-profile.tsx
│   │   │   └── organization.tsx
│   │   ├── advanced/                # Advanced usage examples
│   │   │   ├── custom-theme.tsx
│   │   │   ├── multi-tenant.tsx
│   │   │   ├── custom-components.tsx
│   │   │   └── server-config.tsx
│   │   └── integration/             # Integration examples
│   │       ├── nextjs.tsx
│   │       ├── remix.tsx
│   │       ├── vite.tsx
│   │       └── gatsby.tsx
│   │
│   ├── tests/                       # Test Suite
│   │   ├── components/              # Component tests
│   │   ├── hooks/                   # Hook tests
│   │   ├── config/                  # Configuration tests
│   │   ├── utils/                   # Utility tests
│   │   ├── integration/             # Integration tests
│   │   └── setup.ts                 # Test setup
│   │
│   ├── docs/                        # Documentation
│   │   ├── README.md                # Main documentation
│   │   ├── CONFIGURATION.md         # Configuration guide
│   │   ├── CUSTOMIZATION.md         # Customization guide
│   │   ├── COMPONENTS.md            # Component reference
│   │   ├── HOOKS.md                 # Hooks reference
│   │   ├── THEMES.md                # Theming guide
│   │   ├── MIGRATION.md             # Migration guide
│   │   └── API.md                   # API reference
│   │
│   ├── package.json                 # Package configuration
│   ├── tsconfig.json                # TypeScript configuration
│   ├── tailwind.config.js           # Tailwind CSS configuration
│   ├── postcss.config.js            # PostCSS configuration
│   ├── rollup.config.js             # Build configuration
│   ├── .eslintrc.js                 # ESLint configuration
│   └── .prettierrc                  # Prettier configuration
│
└── react-native/                   # React Native version (future)
    ├── src/
    ├── package.json
    └── README.md
```

## 🎯 Key Features & Architecture

### **1. Configurable Components**
- **Server-Driven Configuration**: Components receive configuration from your Frank Auth backend
- **Organization-Level Customization**: Different orgs can have different themes and configurations
- **Runtime Configuration**: No rebuild required for configuration changes
- **Type-Safe Configuration**: Full TypeScript support for all configuration options

### **2. Customization System**
- **Component Overrides**: Replace any component with your own implementation
- **Theme System**: Comprehensive theming with CSS variables and Tailwind classes
- **Appearance Customization**: Colors, fonts, spacing, borders, shadows
- **Layout Flexibility**: Multiple layout variants (modal, card, full-page)

### **3. Three-Tier User Support**
- **Internal Users**: Platform staff components with admin features
- **External Users**: Organization member components with org context
- **End Users**: Application user components with self-service features
- **Context-Aware Rendering**: Components automatically adapt based on user type

### **4. Advanced Authentication Features**
- **Multi-Factor Authentication**: TOTP, SMS, Email, Backup codes
- **Passkey Support**: WebAuthn integration with device management
- **Social Authentication**: 20+ OAuth providers with custom styling
- **Magic Links**: Passwordless authentication
- **Session Management**: Multi-device session control

### **5. Organization Features**
- **Organization Switcher**: Multi-org support with role context
- **Member Management**: Invite, remove, and manage organization members
- **Role-Based Access**: Dynamic role assignment and permission checking
- **Billing Integration**: Subscription and usage tracking

### **6. Developer Experience**
- **Zero Configuration**: Works out of the box with sensible defaults
- **Full TypeScript**: Complete type safety and IntelliSense support
- **Tree Shaking**: Optimized bundle size with automatic dead code elimination
- **Framework Agnostic**: Works with Next.js, Remix, Vite, and other React frameworks
- **Comprehensive Testing**: Full test coverage with Jest and React Testing Library

### **7. Internationalization**
- **10+ Languages**: Built-in support for major languages
- **Custom Translations**: Easy override of any text
- **RTL Support**: Right-to-left language support
- **Pluralization**: Proper plural forms for all supported languages

### **8. Accessibility**
- **WCAG 2.1 AA**: Full accessibility compliance
- **Keyboard Navigation**: Complete keyboard support
- **Screen Reader**: Proper ARIA labels and descriptions
- **Focus Management**: Logical focus flow and focus trapping

## 🚀 Usage Examples

### Basic Setup
```tsx
import { FrankAuthProvider, SignIn, UserButton } from '@frank-auth/react';

function App() {
  return (
    <FrankAuthProvider 
      publishableKey="pk_test_..."
      organizationId="org_..."
    >
      <SignIn />
      <UserButton />
    </FrankAuthProvider>
  );
}
```

### Custom Configuration
```tsx
import { FrankAuthProvider, SignIn } from '@frank-auth/react';

const customConfig = {
  appearance: {
    themes: {
      primary: '#6366f1',
      background: '#ffffff',
      foreground: '#0f172a',
    },
    elements: {
      formButtonPrimary: 'bg-blue-600 hover:bg-blue-700',
      card: 'shadow-xl border-2',
    },
  },
  organization: {
    enabled: true,
    allowInvitations: true,
    requiredFields: ['name', 'email'],
  },
  authentication: {
    methods: ['email', 'phone', 'oauth', 'passkey'],
    mfa: {
      enabled: true,
      methods: ['totp', 'sms'],
    },
  },
};

function App() {
  return (
    <FrankAuthProvider 
      publishableKey="pk_test_..."
      config={customConfig}
    >
      <SignIn />
    </FrankAuthProvider>
  );
}
```

This structure provides a comprehensive, highly configurable authentication UI library that rivals ClerkJS while maintaining full customization capabilities and multi-tenant support.