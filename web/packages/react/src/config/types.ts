/**
 * @frank-auth/react - Configuration Types
 *
 * Comprehensive type definitions for the configuration system supporting
 * multi-tenant authentication with HeroUI and custom theming.
 */

import {ComponentType, ReactNode} from 'react';

import type {UserType} from '@frank-auth/client';
import {Locale, LocaleDirection, LocaleMessages} from '../locales';
import {BorderRadius, LayoutConfig, Shadows, type Theme, ThemeMode, Typography} from "../types";
import {ThemeUtils} from "../utils";
import {LinksPathConfig} from "@/provider/types";


/**
 * Theme mode options
 */
export type {
    ThemeMode,
    Theme,
};

/**
 * Theme mode options
 */
export {
    ThemeUtils
};

/**
 * Component size variants
 */
export type ComponentSize = 'sm' | 'md' | 'lg';

/**
 * Color scheme variants
 */
export type ColorVariant = 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

/**
 * Appearance modes for components
 */
export type AppearanceMode = 'system' | 'light' | 'dark';

// ============================================================================
// Theme Configuration Types
// ============================================================================

/**
 * Component appearance configuration
 */
export interface ComponentAppearance {
    // Form components
    input: {
        variant: 'flat' | 'bordered' | 'underlined' | 'faded';
        size: ComponentSize;
        radius: keyof BorderRadius;
        color: ColorVariant;
        labelPlacement: 'inside' | 'outside' | 'outside-left';
    };

    button: {
        variant: 'solid' | 'bordered' | 'light' | 'flat' | 'faded' | 'shadow' | 'ghost';
        size: ComponentSize;
        radius: keyof BorderRadius;
        color: ColorVariant;
        disableAnimation: boolean;
        disableRipple: boolean;
    };

    card: {
        variant: 'shadow' | 'bordered' | 'flat';
        radius: keyof BorderRadius;
        shadow: keyof Shadows;
        isBlurred: boolean;
    };

    modal: {
        size: ComponentSize | 'xs' | 'xl' | '2xl' | '3xl' | '4xl' | '5xl' | 'full';
        radius: keyof BorderRadius;
        shadow: keyof Shadows;
        backdrop: 'transparent' | 'opaque' | 'blur';
        placement: 'auto' | 'top' | 'center' | 'bottom';
    };

    // Navigation components
    navbar: {
        variant: 'sticky' | 'floating' | 'static';
        maxWidth: string;
        height: string;
        isBlurred: boolean;
    };

    // Data display
    table: {
        variant: 'striped' | 'bordered';
        size: ComponentSize;
        radius: keyof BorderRadius;
        shadow: keyof Shadows;
        isCompact: boolean;
    };
}

/**
 * Branding configuration from organization settings
 */
export interface BrandingConfig {
    logo: {
        url?: string;
        alt: string;
        width?: number;
        height?: number;
    };
    favicon: {
        url?: string;
        type?: string;
    };
    colors: {
        primary: string;
        secondary: string;
        accent?: string;
    };
    fonts: {
        primary: string;
        secondary?: string;
    };
    customCSS?: string;
}

/**
 * Application appearance configuration
 */
export interface AppearanceConfig {
    titleAlignment?: 'left' | 'center' | 'right';
    mode: AppearanceMode;
    layout: LayoutConfig;
    components: ComponentAppearance;
    branding: BrandingConfig;
    customCSS?: string;
}

// ============================================================================
// Localization Configuration Types
// ============================================================================

/**
 * Localization configuration
 */
export interface LocalizationConfig {
    defaultLocale: Locale;
    fallbackLocale: Locale;
    supportedLocales: Locale[];
    dateFormat: string;
    timeFormat: string;
    numberFormat: Intl.NumberFormatOptions;
    direction: LocaleDirection;
    messages: Partial<LocaleMessages>;
}

// ============================================================================
// Organization Configuration Types
// ============================================================================

/**
 * Organization-specific settings from the backend
 */
export interface OrganizationSettings {
    // Authentication settings
    allowPublicSignup: boolean;
    requireEmailVerification: boolean;
    requirePhoneVerification: boolean;
    allowedDomains?: string[];

    // MFA settings
    mfaRequired: boolean;
    allowedMfaMethods: string[];

    // Password policy
    passwordPolicy: {
        minLength: number;
        requireUppercase: boolean;
        requireLowercase: boolean;
        requireNumbers: boolean;
        requireSymbols: boolean;
    };

    // Session settings
    sessionSettings: {
        maxDuration: number;
        inactivityTimeout: number;
        multipleSessionsAllowed: boolean;
    };

    // Branding settings
    branding: {
        primaryColor: string;
        secondaryColor: string;
        logo?: string;
        favicon?: string;
        customCSS?: string;
    };

    // Custom fields
    customFields?: Array<{
        key: string;
        label: string;
        type: 'text' | 'email' | 'number' | 'select' | 'checkbox';
        required: boolean;
        options?: string[];
    }>;
}

/**
 * Organization configuration for UI components
 */
export interface OrganizationConfig {
    id: string;
    name: string;
    slug: string;
    settings: OrganizationSettings;
    features: {
        sso: boolean;
        mfa: boolean;
        auditLogs: boolean;
        customBranding: boolean;
        apiAccess: boolean;
    };
    limits: {
        maxUsers: number;
        maxSessions: number;
        apiRequestLimit: number;
    };
}

// ============================================================================
// Component Override Types
// ============================================================================

/**
 * Component override configuration
 */
export interface ComponentOverrides {
    // Layout components
    Layout?: ComponentType<any>;
    Header?: ComponentType<any>;
    Footer?: ComponentType<any>;
    Sidebar?: ComponentType<any>;

    // Authentication components
    SignInForm?: ComponentType<any>;
    SignUpForm?: ComponentType<any>;
    SignInModal?: ComponentType<any>;
    SignInCard?: ComponentType<any>;
    ForgotPasswordForm?: ComponentType<any>;
    ResetPasswordForm?: ComponentType<any>;
    MFAForm?: ComponentType<any>;
    MagicLink?: ComponentType<any>;

    // User components
    UserProfile?: ComponentType<any>;
    UserSettings?: ComponentType<any>;
    UserAvatar?: ComponentType<any>;
    UserButton?: ComponentType<any>;
    PasskeySetup?: ComponentType<any>;
    MFASetup?: ComponentType<any>;

    // Organization components
    OrganizationProfile?: ComponentType<any>;
    OrganizationSettings?: ComponentType<any>;
    MemberList?: ComponentType<any>;
    InviteMember?: ComponentType<any>;

    // Common components
    Button?: ComponentType<any>;
    Input?: ComponentType<any>;
    Card?: ComponentType<any>;
    Modal?: ComponentType<any>;
    LoadingSpinner?: ComponentType<any>;
    ErrorBoundary?: ComponentType<any>;
    FormWrapper?: ComponentType<any>;

    // Fields components
    EmailField?: ComponentType<any>;
    PasswordField?: ComponentType<any>;
    FieldError?: ComponentType<any>;
}

// ============================================================================
// Main Configuration Interface
// ============================================================================

/**
 * Available authentication features
 */
export interface AuthFeatures {
    signUp: boolean;
    signIn: boolean;
    passwordReset: boolean;
    mfa: boolean;
    passkeys: boolean;
    oauth: boolean;
    magicLink: boolean;
    sso: boolean;
    organizationManagement: boolean;
    userProfile: boolean;
    sessionManagement: boolean;
}


/**
 * Main Frank Auth configuration interface
 */
export interface FrankAuthUIConfig {
    // Core settings
    publishableKey: string;
    apiUrl?: string;
    frontendUrl?: string;
    userType: UserType;

    // Organization context
    organizationId?: string;
    organization?: OrganizationConfig;

    // UI configuration
    theme: Partial<Theme>;
    appearance: Partial<AppearanceConfig>;
    localization: Partial<LocalizationConfig>;
    linksPath?: Partial<LinksPathConfig>

    // Component customization
    components?: ComponentOverrides;

    // Feature flags
    features: AuthFeatures ;

    // Development settings
    debug?: boolean;
    telemetry?: boolean;

    // Custom elements
    customHead?: ReactNode;
    customFooter?: ReactNode;

    // Event handlers
    onSignIn?: (user: any) => void;
    onSignOut?: () => void;
    onUserUpdate?: (user: any) => void;
    onOrganizationUpdate?: (organization: any) => void;
    onError?: (error: Error) => void;
}

// ============================================================================
// Validation Types
// ============================================================================

/**
 * Configuration validation error
 */
export interface ConfigValidationError {
    path: string;
    message: string;
    value?: any;
}

/**
 * Configuration validation result
 */
export interface ConfigValidationResult {
    isValid: boolean;
    errors: ConfigValidationError[];
    warnings: ConfigValidationError[];
}

// ============================================================================
// Export all types
// ============================================================================

export type {
    // Re-export commonly used types
    Locale,
    LocaleDirection,
    UserType,
    Typography,
};