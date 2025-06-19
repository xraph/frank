/**
 * @frank-auth/react - Default Configurations
 *
 * Comprehensive default configuration values for all aspects of the UI library.
 * Based on HeroUI design system with sensible defaults for multi-tenant auth.
 */

import {
    AppearanceConfig,
    AppearanceMode,
    BrandingConfig,
    ComponentAppearance,
    ComponentSize,
    FrankAuthUIConfig,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
    ThemeUtils,
    Typography,
    UserType,
} from './types';
import {AVAILABLE_LOCALES, DEFAULT_LOCALE, getLocale} from "../locales";
import {Animations, BorderRadius, LayoutConfig, Shadows, Spacing, ThemeColors} from "../types";

// ============================================================================
// Default Color Palette (Based on HeroUI)
// ============================================================================

export const DEFAULT_COLOR_PALETTE = ThemeUtils.generateColorPalette('#3b82f6');

export const DEFAULT_THEME_COLOR: ThemeColors = {
    primary: {
        50: '#eff6ff',
        100: '#dbeafe',
        200: '#bfdbfe',
        300: '#93c5fd',
        400: '#60a5fa',
        500: '#3b82f6',
        600: '#2563eb',
        700: '#1d4ed8',
        800: '#1e40af',
        900: '#1e3a8a',
        950: '#172554',
        DEFAULT: '#3b82f6',
        foreground: '#ffffff',
    },
    secondary: {
        50: '#f8fafc',
        100: '#f1f5f9',
        200: '#e2e8f0',
        300: '#cbd5e1',
        400: '#94a3b8',
        500: '#64748b',
        600: '#475569',
        700: '#334155',
        800: '#1e293b',
        900: '#0f172a',
        950: '#020617',
        DEFAULT: '#64748b',
        foreground: '#ffffff',
    },
    background: '#ffffff',
    foreground: '#0f172a',
    card: '#ffffff',
    cardForeground: '#0f172a',
    popover: '#ffffff',
    popoverForeground: '#0f172a',
    muted: '#f1f5f9',
    mutedForeground: '#64748b',
    accent: '#f1f5f9',
    accentForeground: '#0f172a',
    destructive: '#ef4444',
    destructiveForeground: '#ffffff',
    border: '#e2e8f0',
    input: '#e2e8f0',
    ring: '#3b82f6',
    success: '#10b981',
    successForeground: '#ffffff',
    warning: '#f59e0b',
    warningForeground: '#ffffff',
    danger: '#ef4444',
    dangerForeground: '#ffffff',
    info: '#3b82f6',
    infoForeground: '#ffffff',
    content1: '',
    content2: '',
    content3: '',
    content4: '',
    primaryForeground: '',
    secondaryForeground: '',
    divider: '',
    inputForeground: '',
    focus: '',
    focusVisible: '',
    overlay: '',
    selection: '',
    selectionForeground: '',
    disabled: '',
    disabledForeground: ''
};

// ============================================================================
// Default Typography
// ============================================================================

export const DEFAULT_TYPOGRAPHY: Typography = {
    fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        serif: ['JetBrains Mono', 'ui-monospace', 'monospace'],
    },
    fontSize: {
        xs: ['0.75rem', {lineHeight: '1rem'}],
        sm: ['0.875rem', {lineHeight: '1.25rem'}],
        base: ['1rem', {lineHeight: '1.5rem'}],
        lg: ['1.125rem', {lineHeight: '1.75rem'}],
        xl: ['1.25rem', {lineHeight: '1.75rem'}],
        '2xl': ['1.5rem', {lineHeight: '2rem'}],
        '3xl': ['1.875rem', {lineHeight: '2.25rem'}],
        '4xl': ['2.25rem', {lineHeight: '2.5rem'}],
        '5xl': ['3rem', {lineHeight: '1'}],
        '6xl': ['4rem', {lineHeight: '1'}],
        '7xl': ['5rem', {lineHeight: '1'}],
        '8xl': ['6rem', {lineHeight: '1'}],
        '9xl': ['7rem', {lineHeight: '1'}]
    },
    fontWeight: {
        light: '300',
        normal: '400',
        medium: '500',
        semibold: '600',
        bold: '700',
        thin: '',
        extralight: '',
        extrabold: '',
        black: ''
    },
    lineHeight: {
        none: '',
        tight: '',
        snug: '',
        normal: '',
        relaxed: '',
        loose: ''
    },
    letterSpacing: {
        tighter: '',
        tight: '',
        normal: '',
        wide: '',
        wider: '',
        widest: ''
    }
};

// ============================================================================
// Default Spacing
// ============================================================================

export const DEFAULT_SPACING: Spacing = {
    xs: '0.5rem',
    sm: '0.75rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    '2xl': '2.5rem',
    '3xl': '3rem',
    '4xl': '4rem',
    '5xl': '5rem',
};

// ============================================================================
// Default Border Radius
// ============================================================================

export const DEFAULT_BORDER_RADIUS: BorderRadius = {
    none: '0px',
    sm: '0.125rem',
    md: '0.375rem',
    lg: '0.5rem',
    xl: '0.75rem',
    '2xl': '1rem',
    '3xl': '1.5rem',
    full: '9999px',
    base: ''
};

// ============================================================================
// Default Shadows
// ============================================================================

export const DEFAULT_SHADOWS: Shadows = {
    sm: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
    md: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
    lg: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
    xl: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
    '2xl': '0 25px 50px -12px rgb(0 0 0 / 0.25)',
    inner: 'inset 0 2px 4px 0 rgb(0 0 0 / 0.05)',
    none: '0 0 #0000',
    base: ''
};

// ============================================================================
// Default Animations
// ============================================================================

export const DEFAULT_ANIMATIONS: Animations = {
    duration: {
        fast: '150ms',
        normal: '200ms',
        slow: '300ms',
    },
    easing: {
        linear: 'linear',
        ease: 'ease',
        'ease-in': 'ease-in',
        'ease-out': 'ease-out',
        'ease-in-out': 'ease-in-out',
    },
};

// ============================================================================
// Default Theme Configuration
// ============================================================================

export const DEFAULT_THEME_CONFIG: Theme = {
    ...ThemeUtils.generateTheme({
        animations: 'enhanced',
        mode: 'light',
        borderRadius: 'medium',
        colorHarmony: 'complementary',
        contrastRatio: 'AAA',
        shadows: 'none',
        secondaryColor: '#64748b',
        primaryColor: '#3b82f6',
    }) as Theme,
    typography: DEFAULT_TYPOGRAPHY,
    spacing: DEFAULT_SPACING,
    borderRadius: DEFAULT_BORDER_RADIUS,
    shadows: DEFAULT_SHADOWS,
    animations: DEFAULT_ANIMATIONS,
};

// ============================================================================
// Default Layout Configuration
// ============================================================================

export const DEFAULT_LAYOUT_CONFIG: LayoutConfig = {
    containerMaxWidth: '1200px',
    sidebarWidth: '280px',
    headerHeight: '64px',
    footerHeight: '80px',
    contentPadding: '24px',
};

// ============================================================================
// Default Component Appearance
// ============================================================================

export const DEFAULT_COMPONENT_APPEARANCE: ComponentAppearance = {
    input: {
        variant: 'bordered',
        size: 'md' as ComponentSize,
        radius: 'md',
        color: 'default',
        labelPlacement: 'inside',
    },
    button: {
        variant: 'solid',
        size: 'md' as ComponentSize,
        radius: 'md',
        color: 'primary',
        disableAnimation: false,
        disableRipple: false,
    },
    card: {
        variant: 'shadow',
        radius: 'lg',
        shadow: 'md',
        isBlurred: false,
    },
    modal: {
        size: 'md' as ComponentSize,
        radius: 'lg',
        shadow: 'lg',
        backdrop: 'opaque',
        placement: 'auto',
    },
    navbar: {
        variant: 'sticky',
        maxWidth: '1200px',
        height: '64px',
        isBlurred: true,
    },
    table: {
        variant: 'striped',
        size: 'md' as ComponentSize,
        radius: 'lg',
        shadow: 'sm',
        isCompact: false,
    },
};

// ============================================================================
// Default Branding Configuration
// ============================================================================

export const DEFAULT_BRANDING_CONFIG: BrandingConfig = {
    logo: {
        alt: 'Frank Auth',
        width: 120,
        height: 32,
    },
    favicon: {
        type: 'image/svg+xml',
    },
    colors: {
        primary: '#3b82f6',
        secondary: '#64748b',
    },
    fonts: {
        primary: 'Inter, ui-sans-serif, system-ui, sans-serif',
    },
};

// ============================================================================
// Default Appearance Configuration
// ============================================================================

export const DEFAULT_APPEARANCE_CONFIG: AppearanceConfig = {
    mode: 'system' as AppearanceMode,
    layout: DEFAULT_LAYOUT_CONFIG,
    components: DEFAULT_COMPONENT_APPEARANCE,
    branding: DEFAULT_BRANDING_CONFIG,
};

// ============================================================================
// Default Locale Messages
// ============================================================================

export const DEFAULT_LOCALE_MESSAGES = getLocale(DEFAULT_LOCALE);

// ============================================================================
// Default Localization Configuration
// ============================================================================

export const DEFAULT_LOCALIZATION_CONFIG: LocalizationConfig = {
    defaultLocale: DEFAULT_LOCALE,
    fallbackLocale: DEFAULT_LOCALE,
    supportedLocales: AVAILABLE_LOCALES,
    dateFormat: 'MMM d, yyyy',
    timeFormat: 'h:mm a',
    numberFormat: {
        style: 'decimal',
        minimumFractionDigits: 0,
        maximumFractionDigits: 2,
    },
    direction: 'ltr',
    messages: DEFAULT_LOCALE_MESSAGES,
};

// ============================================================================
// Default Organization Configuration
// ============================================================================

export const DEFAULT_ORGANIZATION_CONFIG: Partial<OrganizationConfig> = {
    settings: {
        allowPublicSignup: true,
        requireEmailVerification: true,
        requirePhoneVerification: false,
        mfaRequired: false,
        allowedMfaMethods: ['totp', 'sms', 'email'],
        passwordPolicy: {
            minLength: 8,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSymbols: false,
        },
        sessionSettings: {
            maxDuration: 86400, // 24 hours
            inactivityTimeout: 1800, // 30 minutes
            multipleSessionsAllowed: true,
        },
        branding: {
            primaryColor: '#3b82f6',
            secondaryColor: '#64748b',
        },
    },
    features: {
        sso: false,
        mfa: true,
        auditLogs: false,
        customBranding: false,
        apiAccess: true,
    },
    limits: {
        maxUsers: 100,
        maxSessions: 10,
        apiRequestLimit: 1000,
    },
};

// ============================================================================
// Default Main Configuration
// ============================================================================

export const DEFAULT_FRANK_AUTH_CONFIG: Partial<FrankAuthUIConfig> = {
    apiUrl: 'https://api.frankauth.com',
    userType: 'external' as UserType,
    theme: DEFAULT_THEME_CONFIG,
    appearance: DEFAULT_APPEARANCE_CONFIG,
    localization: DEFAULT_LOCALIZATION_CONFIG,
    features: {
        signUp: true,
        signIn: true,
        passwordReset: true,
        mfa: true,
        sso: false,
        organizationManagement: true,
        userProfile: true,
        sessionManagement: true,
    },
    debug: false,
    telemetry: true,
};

// ============================================================================
// Configuration Presets
// ============================================================================

/**
 * Preset configurations for different use cases
 */
export const CONFIG_PRESETS = {
    // Minimal configuration for simple auth
    minimal: {
        features: {
            signUp: true,
            signIn: true,
            passwordReset: true,
            mfa: false,
            sso: false,
            organizationManagement: false,
            userProfile: false,
            sessionManagement: false,
        },
        appearance: {
            components: {
                input: { variant: 'flat' as const },
                button: { variant: 'flat' as const },
                card: { variant: 'flat' as const },
            },
        },
    },

    // Enterprise configuration with all features
    enterprise: {
        features: {
            signUp: true,
            signIn: true,
            passwordReset: true,
            mfa: true,
            sso: true,
            organizationManagement: true,
            userProfile: true,
            sessionManagement: true,
        },
        organization: {
            settings: {
                mfaRequired: true,
                allowedMfaMethods: ['totp', 'webauthn'],
                passwordPolicy: {
                    minLength: 12,
                    requireUppercase: true,
                    requireLowercase: true,
                    requireNumbers: true,
                    requireSymbols: true,
                },
            },
            features: {
                sso: true,
                mfa: true,
                auditLogs: true,
                customBranding: true,
                apiAccess: true,
            },
        },
    },

    // B2B SaaS configuration
    b2b: {
        userType: 'external' as UserType,
        features: {
            signUp: false, // Invitation-only
            signIn: true,
            passwordReset: true,
            mfa: true,
            sso: true,
            organizationManagement: true,
            userProfile: true,
            sessionManagement: true,
        },
        organization: {
            settings: {
                allowPublicSignup: false,
                requireEmailVerification: true,
                mfaRequired: true,
            },
        },
    },

    // Consumer app configuration
    consumer: {
        userType: 'end_user' as UserType,
        features: {
            signUp: true,
            signIn: true,
            passwordReset: true,
            mfa: false,
            sso: true,
            organizationManagement: false,
            userProfile: true,
            sessionManagement: false,
        },
        appearance: {
            components: {
                input: { variant: 'bordered' as const },
                button: { variant: 'shadow' as const },
                card: { variant: 'shadow' as const },
            },
        },
    },
} as const;

// ============================================================================
// Export defaults
// ============================================================================

export {
    DEFAULT_THEME_CONFIG as defaultTheme,
    DEFAULT_APPEARANCE_CONFIG as defaultAppearance,
    DEFAULT_LOCALIZATION_CONFIG as defaultLocalization,
    DEFAULT_ORGANIZATION_CONFIG as defaultOrganization,
    DEFAULT_FRANK_AUTH_CONFIG as defaultConfig,
};