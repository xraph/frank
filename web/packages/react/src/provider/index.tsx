/**
 * @frank-auth/react - Provider Index
 *
 * Main entry point for all authentication providers. Exports all provider
 * components, hooks, and types for easy importing.
 */

'use client';

// ============================================================================
// Provider Components
// ============================================================================

export {AuthProvider, useAuth, useAuthGuard} from './auth-provider';
import {HeroUIProvider} from '@heroui/react'
import React from 'react';
import type {FrankAuthUIConfig} from '../config';
import type {AuthProviderProps, ConfigProviderProps, ThemeProviderProps} from './types';
import {ConfigProvider, useConfig} from './config-provider';
import {ThemeProvider, useTheme} from './theme-provider';
import {AuthProvider, useAuth} from './auth-provider';

export {
    ConfigProvider, useConfig, useFeatures, useOrganizationConfig, useComponentOverrides, withConfig
} from './config-provider';
export {
    ThemeProvider, useTheme, useThemeMode, useOrganizationBranding, useThemeVariables, withTheme, ThemeSwitcher
} from './theme-provider';

// ============================================================================
// Provider Types
// ============================================================================

export type {
    // Auth types
    AuthState,
    AuthContextValue,
    AuthProviderProps,
    AuthError,
    AuthFeatures,
    OrganizationMembership,
    SignInParams,
    SignInResult,
    SignUpParams,
    SignUpResult,
    SetActiveParams,
    UpdateUserParams,

    // Config types
    ConfigState,
    ConfigContextValue,
    ConfigProviderProps,

    // Theme types
    ThemeState,
    ThemeContextValue,
    ThemeProviderProps,
    OrganizationBranding,

    // Session types
    SessionState,
    SessionContextMethods,
    SessionContextValue,

    // Organization types
    OrganizationState,
    OrganizationInvitation,
    OrganizationContextMethods,
    OrganizationContextValue,
    CreateOrganizationParams,
    UpdateOrganizationParams,
    InviteMemberParams,

    // Permission types
    PermissionState,
    PermissionContext,
    PermissionContextMethods,
    PermissionContextValue,

    // Common types
    AuthContextMethods,
    ConfigContextMethods,
    ThemeContextMethods,
} from './types';

// ============================================================================
// Combined Provider Component
// ============================================================================

/**
 * Combined provider props for convenience
 */
export interface FrankAuthProviderProps {
    children: React.ReactNode;
    config: Partial<FrankAuthUIConfig>;
    onError?: (error: any) => void;
    onSignIn?: (user: any) => void;
    onSignOut?: () => void;
    onConfigChange?: (config: FrankAuthUIConfig) => void;
    onThemeChange?: (theme: any) => void;
}

/**
 * Combined Frank Auth provider that wraps all necessary providers
 *
 * @example
 * ```tsx
 * import { FrankAuthProvider } from '@frank-auth/react';
 *
 * function App() {
 *   return (
 *     <FrankAuthProvider config={{
 *       publishableKey: 'pk_test_...',
 *       userType: 'external',
 *       theme: { mode: 'dark' }
 *     }}>
 *       <YourApp />
 *     </FrankAuthProvider>
 *   );
 * }
 * ```
 */
export function FrankAuthProvider({
                                      children,
                                      config,
                                      onError,
                                      onSignIn,
                                      onSignOut,
                                      onConfigChange,
                                      onThemeChange,
                                  }: FrankAuthProviderProps) {
    // Validate required config
    if (!config.publishableKey) {
        throw new Error('publishableKey is required in FrankAuthProvider config');
    }

    if (!config.userType) {
        throw new Error('userType is required in FrankAuthProvider config');
    }

    return (
        <HeroUIProvider>
            <ConfigProvider
                config={config}
                onConfigChange={onConfigChange}
            >
                <ThemeProvider
                    theme={config.theme}
                    mode={config.theme?.mode}
                    organizationBranding={config.organization?.settings?.branding ? {
                        primaryColor: config.organization.settings.branding.primaryColor,
                        secondaryColor: config.organization.settings.branding.secondaryColor,
                        logo: config.organization.settings.branding.logo,
                        customCSS: config.organization.settings.branding.customCSS,
                    } : undefined}
                    onThemeChange={onThemeChange}
                >
                    <AuthProvider
                        publishableKey={config.publishableKey}
                        secretKey={config.secretKey}
                        userType={config.userType}
                        apiUrl={config.apiUrl}
                        projectId={config.projectId}
                        onError={onError}
                        onSignIn={onSignIn}
                        onSignOut={onSignOut}
                        debug={config.debug}
                    >
                        {children}
                    </AuthProvider>
                </ThemeProvider>
            </ConfigProvider>
        </HeroUIProvider>
    );
}

// ============================================================================
// Provider Utility Functions
// ============================================================================

/**
 * Check if all required providers are available
 */
export function useProviderStatus() {
    const [authAvailable, setAuthAvailable] = React.useState(false);
    const [configAvailable, setConfigAvailable] = React.useState(false);
    const [themeAvailable, setThemeAvailable] = React.useState(false);

    React.useEffect(() => {
        try {
            useAuth();
            setAuthAvailable(true);
        } catch {
            setAuthAvailable(false);
        }

        try {
            useConfig();
            setConfigAvailable(true);
        } catch {
            setConfigAvailable(false);
        }

        try {
            useTheme();
            setThemeAvailable(true);
        } catch {
            setThemeAvailable(false);
        }
    }, []);

    return {
        auth: authAvailable,
        config: configAvailable,
        theme: themeAvailable,
        allAvailable: authAvailable && configAvailable && themeAvailable,
    };
}

/**
 * Higher-order component that ensures all providers are available
 */
export function withProviders<T extends object>(Component: React.ComponentType<T>) {
    const WithProvidersComponent = (props: T) => {
        const auth = useAuth();
        const config = useConfig();
        const theme = useTheme();

        return (
            <Component
                {...props}
                auth={auth}
                config={config}
                theme={theme}
            />
        );
    };

    WithProvidersComponent.displayName = `withProviders(${Component.displayName || Component.name})`;

    return WithProvidersComponent;
}

/**
 * Hook that provides all provider contexts
 */
export function useAllProviders() {
    const auth = useAuth();
    const config = useConfig();
    const theme = useTheme();

    return {
        auth,
        config,
        theme,
    };
}

// ============================================================================
// Default Export
// ============================================================================

export default FrankAuthProvider;