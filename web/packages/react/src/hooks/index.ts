/**
 * @frank-auth/react - Hooks Index
 *
 * Main entry point for all authentication hooks. Exports all hooks
 * and related utilities for easy importing and usage.
 */

// ============================================================================
// Main Authentication Hooks
// ============================================================================

// Core authentication hook
import {useAuth, useAuthActions, useAuthOrganization, useAuthState, useAuthStatus,} from './use-auth';
import {useUser, useUserActions, useUserProfile, useUserVerification,} from './use-user';

// Session management hooks
import {useMultiSession, useSession, useSessionExpiry, useSessionSecurity, useSessionStatus,} from './use-session';
// Organization management hooks
import {
    useOrganization,
    useOrganizationInvitations,
    useOrganizationMembership,
    useOrganizationSwitcher,
} from './use-organization';
// Configuration hooks
import {
    useComponentConfiguration,
    useConfig,
    useConfigValidation,
    useFeatureFlags,
    useLocalizationConfig,
    useOrganizationConfiguration,
    useThemeConfig,
} from './use-config';
// Theme hooks
import {useTheme, useThemeColors, useThemeLayout, useThemeStyles, useThemeTypography,} from './use-theme';
// Permission and authorization hooks
import {useOrganizationPermissions, usePermissionGuard, usePermissions, useSystemPermissions,} from './use-permissions';
// Multi-Factor Authentication hooks
import {useBackupCodes, useMFA, useSMSMFA, useTOTP,} from './use-mfa';
// Passkeys (WebAuthn) hooks
import {usePasskeyAuthentication, usePasskeyRegistration, usePasskeys,} from './use-passkeys';
// OAuth authentication hooks
import {useOAuth, useOAuthCallback, useOAuthProvider,} from './use-oauth';
// Magic link authentication hooks
import {useMagicLink, useMagicLinkPasswordReset, useMagicLinkSignIn, useMagicLinkVerification,} from './use-magic-link';

export {
    useAuth,
    useAuthState,
    useAuthActions,
    useAuthOrganization,
    useAuthStatus,
} from './use-auth';

// User management hooks
export {
    useUser,
    useUserProfile,
    useUserVerification,
    useUserActions,
} from './use-user';

export {
    useSession,
    useSessionStatus,
    useMultiSession,
    useSessionSecurity,
    useSessionExpiry,
} from './use-session';

export {
    useOrganization,
    useOrganizationMembership,
    useOrganizationInvitations,
    useOrganizationSwitcher,
} from './use-organization';

// ============================================================================
// Configuration and Theme Hooks
// ============================================================================

export {
    useConfig,
    useFeatureFlags,
    useThemeConfig,
    useLocalizationConfig,
    useOrganizationConfiguration,
    useComponentConfiguration,
    useConfigValidation,
} from './use-config';

export {
    useTheme,
    useThemeColors,
    useThemeTypography,
    useThemeLayout,
    useThemeStyles,
} from './use-theme';

// ============================================================================
// Security and Authentication Method Hooks
// ============================================================================
export {
    usePermissions,
    useOrganizationPermissions,
    useSystemPermissions,
    usePermissionGuard,

    // Permission constants
    PERMISSION_ACTIONS,
    PERMISSION_RESOURCES,
    SYSTEM_ROLES,
    ORGANIZATION_ROLES,
} from './use-permissions';

export {
    useMFA,
    useTOTP,
    useSMSMFA,
    useBackupCodes,

    // MFA constants
    MFA_METHOD_CONFIGS,
} from './use-mfa';

export {
    usePasskeys,
    usePasskeyRegistration,
    usePasskeyAuthentication,
} from './use-passkeys';

export {
    useOAuth,
    useOAuthProvider,
    useOAuthCallback,

    // OAuth constants
    OAUTH_PROVIDERS,
} from './use-oauth';

export {
    useMagicLink,
    useMagicLinkSignIn,
    useMagicLinkVerification,
    useMagicLinkPasswordReset,

    // Magic link constants
    MAGIC_LINK_CONFIG,
} from './use-magic-link';

// ============================================================================
// Hook Utilities and Types
// ============================================================================

// Re-export types from provider types for convenience
export type {
    // Auth types
    AuthError,
    AuthFeatures,
    AuthState,
    OrganizationMembership,
    SignInParams,
    SignInResult,
    SignUpParams,
    SignUpResult,
    SetActiveParams,
    UpdateUserParams,

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

    // Theme types
    ThemeState,
    ThemeContextValue,
    OrganizationBranding,

    // Config types
    ConfigState,
    ConfigContextValue,
} from '../provider/types';

// Re-export client types for convenience
export type {
    User,
    Session,
    Organization,
    OrganizationSettings,
    AuthStatus,
    UserType,
    AuthProvider,
    MFAMethod,
    PasskeySummary,
} from '@frank-auth/client';

// ============================================================================
// Convenience Hook Collections
// ============================================================================

/**
 * Collection of all core authentication hooks
 * Useful for understanding what's available or for testing
 */
export const CORE_AUTH_HOOKS = {
    useAuth,
    useUser,
    useSession,
    useOrganization,
    useConfig,
    useTheme,
    usePermissions,
} as const;

/**
 * Collection of all authentication method hooks
 * For different authentication strategies
 */
export const AUTH_METHOD_HOOKS = {
    useMFA,
    usePasskeys,
    useOAuth,
    useMagicLink,
} as const;

/**
 * Collection of all specialized hooks
 * For specific use cases and advanced functionality
 */
export const SPECIALIZED_HOOKS = {
    // Auth specialized
    useAuthState,
    useAuthActions,
    useAuthOrganization,
    useAuthStatus,

    // User specialized
    useUserProfile,
    useUserVerification,
    useUserActions,

    // Session specialized
    useSessionStatus,
    useMultiSession,
    useSessionSecurity,
    useSessionExpiry,

    // Organization specialized
    useOrganizationMembership,
    useOrganizationInvitations,
    useOrganizationSwitcher,

    // Config specialized
    useFeatureFlags,
    useThemeConfig,
    useLocalizationConfig,
    useOrganizationConfiguration,
    useComponentConfiguration,
    useConfigValidation,

    // Theme specialized
    useThemeColors,
    useThemeTypography,
    useThemeLayout,
    useThemeStyles,

    // Permission specialized
    useOrganizationPermissions,
    useSystemPermissions,
    usePermissionGuard,

    // MFA specialized
    useTOTP,
    useSMSMFA,
    useBackupCodes,

    // Passkeys specialized
    usePasskeyRegistration,
    usePasskeyAuthentication,

    // OAuth specialized
    useOAuthProvider,
    useOAuthCallback,

    // Magic link specialized
    useMagicLinkSignIn,
    useMagicLinkVerification,
    useMagicLinkPasswordReset,
} as const;

// ============================================================================
// Hook Groups by Use Case
// ============================================================================

/**
 * Authentication hooks for sign-in/sign-up flows
 */
export const AUTHENTICATION_HOOKS = {
    useAuth,
    useOAuth,
    useMagicLink,
    usePasskeys,
    useMFA,
} as const;

/**
 * User management hooks for profile and account management
 */
export const USER_MANAGEMENT_HOOKS = {
    useUser,
    useSession,
    usePermissions,
} as const;

/**
 * Organization management hooks for multi-tenant applications
 */
export const ORGANIZATION_HOOKS = {
    useOrganization,
    useOrganizationPermissions,
    useOrganizationConfiguration,
} as const;

/**
 * UI customization hooks for theming and configuration
 */
export const UI_CUSTOMIZATION_HOOKS = {
    useTheme,
    useConfig,
    useFeatureFlags,
    useComponentConfiguration,
} as const;

/**
 * Security hooks for advanced security features
 */
export const SECURITY_HOOKS = {
    usePermissions,
    useMFA,
    usePasskeys,
    useSessionSecurity,
} as const;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get all available hooks as an array
 * Useful for debugging or documentation
 */
export function getAllHooks() {
    return [
        ...Object.values(CORE_AUTH_HOOKS),
        ...Object.values(AUTH_METHOD_HOOKS),
        ...Object.values(SPECIALIZED_HOOKS),
    ];
}

const HOOK_CATEGORIES = {
    authentication: AUTHENTICATION_HOOKS,
    userManagement: USER_MANAGEMENT_HOOKS,
    organization: ORGANIZATION_HOOKS,
    uiCustomization: UI_CUSTOMIZATION_HOOKS,
    security: SECURITY_HOOKS,
};


/**
 * Get hooks by category
 * Useful for conditional loading or feature detection
 */
export function getHooksByCategory(category: keyof typeof HOOK_CATEGORIES) {
    return HOOK_CATEGORIES[category];
}

/**
 * Check if a hook is available
 * Useful for feature detection
 */
export function isHookAvailable(hookName: string): boolean {
    const allHooks = getAllHooks();
    return allHooks.some(hook => hook.name === hookName);
}

// ============================================================================
// Development Utilities
// ============================================================================

/**
 * Hook metadata for development and documentation
 */
export const HOOK_METADATA = {
    // Core hooks
    useAuth: {
        description: 'Main authentication hook providing access to auth state and methods',
        category: 'core',
        dependencies: ['AuthProvider'],
        returnType: 'UseAuthReturn',
    },
    useUser: {
        description: 'User management hook for profile operations and verification',
        category: 'core',
        dependencies: ['AuthProvider'],
        returnType: 'UseUserReturn',
    },
    useSession: {
        description: 'Session management hook for multi-session and security features',
        category: 'core',
        dependencies: ['AuthProvider'],
        returnType: 'UseSessionReturn',
    },
    useOrganization: {
        description: 'Organization management hook for multi-tenant operations',
        category: 'core',
        dependencies: ['AuthProvider'],
        returnType: 'UseOrganizationReturn',
    },
    useConfig: {
        description: 'Configuration hook for UI settings and feature flags',
        category: 'core',
        dependencies: ['ConfigProvider'],
        returnType: 'UseConfigReturn',
    },
    useTheme: {
        description: 'Theme management hook for styling and customization',
        category: 'core',
        dependencies: ['ThemeProvider'],
        returnType: 'UseThemeReturn',
    },
    usePermissions: {
        description: 'Permission and authorization hook for role-based access control',
        category: 'security',
        dependencies: ['AuthProvider'],
        returnType: 'UsePermissionsReturn',
    },
    useMFA: {
        description: 'Multi-factor authentication hook for TOTP, SMS, and other MFA methods',
        category: 'security',
        dependencies: ['AuthProvider'],
        returnType: 'UseMFAReturn',
    },
    usePasskeys: {
        description: 'Passkeys (WebAuthn) hook for passwordless authentication',
        category: 'authentication',
        dependencies: ['AuthProvider'],
        returnType: 'UsePasskeysReturn',
    },
    useOAuth: {
        description: 'OAuth authentication hook for social sign-in providers',
        category: 'authentication',
        dependencies: ['AuthProvider'],
        returnType: 'UseOAuthReturn',
    },
    useMagicLink: {
        description: 'Magic link authentication hook for passwordless email authentication',
        category: 'authentication',
        dependencies: ['AuthProvider'],
        returnType: 'UseMagicLinkReturn',
    },
} as const;

/**
 * Get hook metadata
 */
export function getHookMetadata(hookName: keyof typeof HOOK_METADATA) {
    return HOOK_METADATA[hookName];
}

/**
 * Get hooks by category from metadata
 */
export function getHooksByMetadataCategory(category: string) {
    return Object.entries(HOOK_METADATA)
        .filter(([_, meta]) => meta.category === category)
        .map(([name]) => name);
}

// ============================================================================
// Export Default
// ============================================================================

// Export the main auth hook as default for convenience
export { useAuth as default } from './use-auth';
