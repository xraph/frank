/**
 * @frank-auth/react - useConfig Hook
 *
 * Configuration hook that provides access to UI configuration, feature flags,
 * localization settings, and organization-specific configuration.
 */

import {useCallback, useMemo} from 'react';

import type {
    AppearanceConfig,
    ComponentOverrides,
    FrankAuthUIConfig,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
} from '../config';

import {useConfig as useConfigProvider} from '../provider/config-provider';
import {useAuth} from './use-auth';

import type {AuthFeatures, LinksPathConfig} from '../provider/types';

// ============================================================================
// Config Hook Interface
// ============================================================================

export interface UseConfigReturn {
    // Core configuration
    config: FrankAuthUIConfig;
    publishableKey: string;
    apiUrl: string;
    userType: string;
    debug: boolean;

    // UI configuration
    theme: Theme;
    appearance: AppearanceConfig;
    localization: LocalizationConfig;
    components: ComponentOverrides;
    titleAlignment: 'left' | 'center' | 'right';
    linksPath?: LinksPathConfig;


    // Organization configuration
    organization: OrganizationConfig | undefined;
    organizationSettings: any;

    // Feature flags
    features: AuthFeatures;

    // Configuration methods
    updateConfig: (updates: Partial<FrankAuthUIConfig>) => void;
    setTheme: (theme: Partial<Theme>) => void;
    setAppearance: (appearance: Partial<AppearanceConfig>) => void;
    setLocale: (locale: string) => void;
    resetToDefaults: () => void;

    // Feature flag helpers
    hasFeature: (feature: keyof AuthFeatures) => boolean;
    requireFeature: (feature: keyof AuthFeatures) => void;

    // Validation
    isConfigValid: boolean;
    configErrors: string[];

    // State helpers
    isLoaded: boolean;
    isMultiTenant: boolean;
    isCustomBranded: boolean;
}

// ============================================================================
// Main useConfig Hook
// ============================================================================

/**
 * Configuration hook providing access to all UI configuration and settings
 *
 * @example Basic configuration access
 * ```tsx
 * import { useConfig } from '@frank-auth/react';
 *
 * function ConfigDisplay() {
 *   const {
 *     theme,
 *     features,
 *     hasFeature,
 *     organization,
 *     setTheme
 *   } = useConfig();
 *
 *   return (
 *     <div>
 *       <p>Theme mode: {theme.mode}</p>
 *       <p>MFA enabled: {hasFeature('mfa') ? 'Yes' : 'No'}</p>
 *       {organization && <p>Organization: {organization.name}</p>}
 *
 *       <button onClick={() => setTheme({ mode: 'dark' })}>
 *         Switch to Dark Mode
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Feature-based conditional rendering
 * ```tsx
 * function ConditionalFeatures() {
 *   const { hasFeature, requireFeature } = useConfig();
 *
 *   // Conditional rendering
 *   if (!hasFeature('mfa')) {
 *     return <div>MFA not available</div>;
 *   }
 *
 *   // Feature requirement (throws if not available)
 *   const handleMFASetup = () => {
 *     requireFeature('mfa');
 *     // MFA setup logic...
 *   };
 *
 *   return <button onClick={handleMFASetup}>Setup MFA</button>;
 * }
 * ```
 *
 * @example Organization-specific configuration
 * ```tsx
 * function OrganizationConfig() {
 *   const {
 *     organization,
 *     organizationSettings,
 *     isMultiTenant,
 *     isCustomBranded
 *   } = useConfig();
 *
 *   if (!isMultiTenant) {
 *     return <div>Single tenant mode</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <h3>{organization?.name}</h3>
 *       {isCustomBranded && (
 *         <img src={organizationSettings?.branding?.logo} alt="Organization Logo" />
 *       )}
 *       <p>MFA Required: {organizationSettings?.mfaRequired ? 'Yes' : 'No'}</p>
 *     </div>
 *   );
 * }
 * ```
 */
export function useConfig(): UseConfigReturn {
    const configProvider = useConfigProvider();
    const { activeOrganization } = useAuth();

    // Feature flag helpers
    const hasFeature = useCallback((feature: keyof AuthFeatures): boolean => {
        return configProvider.features[feature];
    }, [configProvider.features]);

    const requireFeature = useCallback((feature: keyof AuthFeatures): void => {
        if (!configProvider.features[feature]) {
            throw new Error(`Feature ${feature} is not enabled`);
        }
    }, [configProvider.features]);

    // Configuration validation
    const { isConfigValid, configErrors } = useMemo(() => {
        const errors: string[] = [];

        // Validate required configuration
        if (!configProvider.publishableKey) {
            errors.push('Publishable key is required');
        }

        if (!configProvider.userType) {
            errors.push('User type is required');
        }

        // Validate publishable key format
        if (configProvider.publishableKey &&
            !/^pk_(test|live)_[a-zA-Z0-9_]+$/.test(configProvider.publishableKey)) {
            errors.push('Invalid publishable key format');
        }

        // Validate API URL format
        if (configProvider.apiUrl) {
            try {
                new URL(configProvider.apiUrl);
            } catch {
                errors.push('Invalid API URL format');
            }
        }

        // Validate user type
        if (configProvider.userType &&
            !['internal', 'external', 'end_user'].includes(configProvider.userType)) {
            errors.push('Invalid user type');
        }

        return {
            isConfigValid: errors.length === 0,
            configErrors: errors,
        };
    }, [configProvider.publishableKey, configProvider.userType, configProvider.apiUrl]);

    // State helpers
    const isMultiTenant = useMemo(() => !!configProvider.organizationConfig, [configProvider.organizationConfig]);
    const isCustomBranded = useMemo(() => {
        return !!(configProvider.organizationSettings?.branding?.logoUrl ||
            configProvider.organizationSettings?.branding?.primaryColor ||
            configProvider.organizationSettings?.branding?.customCss);
    }, [configProvider.organizationSettings]);

    return {
        // Core configuration
        config: configProvider.config,
        publishableKey: configProvider.publishableKey,
        apiUrl: configProvider.apiUrl,
        userType: configProvider.userType,
        debug: configProvider.debug,

        // UI configuration
        titleAlignment: configProvider.config?.appearance?.titleAlignment ?? 'left',
        theme: configProvider.theme,
        appearance: configProvider.appearance,
        localization: configProvider.localization,
        components: configProvider.components,
        linksPath: configProvider.linksPath,

        // Organization configuration
        organization: configProvider.organizationConfig,
        organizationSettings: configProvider.organizationSettings,

        // Feature flags
        features: configProvider.features,

        // Configuration methods
        updateConfig: configProvider.updateConfig,
        setTheme: configProvider.setTheme,
        setAppearance: configProvider.setAppearance,
        setLocale: configProvider.setLocale,
        resetToDefaults: configProvider.resetToDefaults,

        // Feature flag helpers
        hasFeature,
        requireFeature,

        // Validation
        isConfigValid,
        configErrors,

        // State helpers
        isLoaded: configProvider.isLoaded,
        isMultiTenant,
        isCustomBranded,
    };
}

// ============================================================================
// Specialized Config Hooks
// ============================================================================

/**
 * Hook for feature flags only
 */
export function useFeatureFlags() {
    const { features, hasFeature, requireFeature } = useConfig();

    return {
        features,
        hasFeature,
        requireFeature,

        // Convenience methods for common features
        canSignUp: hasFeature('signUp'),
        canSignIn: hasFeature('signIn'),
        canResetPassword: hasFeature('passwordReset'),
        hasMFA: hasFeature('mfa'),
        hasPasskeys: hasFeature('passkeys'),
        hasOAuth: hasFeature('oauth'),
        hasMagicLink: hasFeature('magicLink'),
        hasSSO: hasFeature('sso'),
        hasOrganizationManagement: hasFeature('organizationManagement'),
        hasUserProfile: hasFeature('userProfile'),
        hasSessionManagement: hasFeature('sessionManagement'),
    };
}

/**
 * Hook for theme configuration
 */
export function useThemeConfig() {
    const { theme, setTheme, appearance, setAppearance } = useConfig();

    return {
        theme,
        appearance,
        setTheme,
        setAppearance,

        // Theme helpers
        mode: theme.mode,
        colors: theme.colors,
        typography: theme.typography,
        spacing: theme.spacing,
        borderRadius: theme.borderRadius,
        shadows: theme.shadows,

        // Appearance helpers
        layout: appearance.layout,
        components: appearance.components,
        branding: appearance.branding,

        // Quick theme updates
        setMode: (mode: 'light' | 'dark' | 'system') => setTheme({ mode }),
        setPrimaryColor: (color: string) => setTheme({
            colors: { ...theme.colors, primary: { ...theme.colors.primary, DEFAULT: color } }
        }),
        setSecondaryColor: (color: string) => setTheme({
            colors: { ...theme.colors, secondary: { ...theme.colors.secondary, DEFAULT: color } }
        }),
    };
}

/**
 * Hook for localization configuration
 */
export function useLocalizationConfig() {
    const { localization, setLocale } = useConfig();

    return {
        localization,
        setLocale,

        // Localization helpers
        currentLocale: localization.defaultLocale,
        supportedLocales: localization.supportedLocales,
        dateFormat: localization.dateFormat,
        timeFormat: localization.timeFormat,
        direction: localization.direction,

        // Quick locale updates
        isRTL: localization.direction === 'rtl',
        setEnglish: () => setLocale('en'),
        setSpanish: () => setLocale('es'),
        setFrench: () => setLocale('fr'),
        setGerman: () => setLocale('de'),
    };
}

/**
 * Hook for organization-specific configuration
 */
export function useOrganizationConfiguration() {
    const {
        organization,
        organizationSettings,
        isMultiTenant,
        isCustomBranded,
        features,
    } = useConfig();

    const organizationFeatures = useMemo(() => {
        if (!organization) return {};

        return {
            sso: organization.features?.sso || false,
            mfa: organization.features?.mfa || false,
            auditLogs: organization.features?.auditLogs || false,
            customBranding: organization.features?.customBranding || false,
            apiAccess: organization.features?.apiAccess || false,
        };
    }, [organization]);

    return {
        organization,
        organizationSettings,
        isMultiTenant,
        isCustomBranded,
        features: organizationFeatures,

        // Organization helpers
        organizationId: organization?.id || null,
        organizationName: organization?.name || null,
        organizationSlug: organization?.slug || null,

        // Settings helpers
        allowPublicSignup: organizationSettings?.allowPublicSignup || false,
        requireEmailVerification: organizationSettings?.requireEmailVerification || false,
        requirePhoneVerification: organizationSettings?.requirePhoneVerification || false,
        mfaRequired: organizationSettings?.mfaRequired || false,
        allowedMfaMethods: organizationSettings?.allowedMfaMethods || [],

        // Branding helpers
        branding: organizationSettings?.branding,
        logo: organizationSettings?.branding?.logo,
        primaryColor: organizationSettings?.branding?.primaryColor,
        secondaryColor: organizationSettings?.branding?.secondaryColor,
        customCSS: organizationSettings?.branding?.customCSS,

        // Limits
        limits: organization?.limits,
        maxUsers: organization?.limits?.maxUsers || 0,
        maxSessions: organization?.limits?.maxSessions || 0,
        apiRequestLimit: organization?.limits?.apiRequestLimit || 0,
    };
}

/**
 * Hook for component overrides
 */
export function useComponentConfiguration() {
    const { components } = useConfig();

    const getComponent = useCallback(<T extends keyof ComponentOverrides>(
        componentName: T,
        defaultComponent: any
    ) => {
        return components[componentName] || defaultComponent;
    }, [components]);

    const hasOverride = useCallback((componentName: keyof ComponentOverrides) => {
        return !!components[componentName];
    }, [components]);

    return {
        components,
        getComponent,
        hasOverride,

        // Component availability checks
        hasCustomLayout: hasOverride('Layout'),
        hasCustomHeader: hasOverride('Header'),
        hasCustomFooter: hasOverride('Footer'),
        hasCustomSignInForm: hasOverride('SignInForm'),
        hasCustomSignUpForm: hasOverride('SignUpForm'),
        hasCustomUserProfile: hasOverride('UserProfile'),
        hasCustomButton: hasOverride('Button'),
        hasCustomInput: hasOverride('Input'),
        hasCustomCard: hasOverride('Card'),
        hasCustomModal: hasOverride('Modal'),
    };
}

/**
 * Hook for configuration validation and debugging
 */
export function useConfigValidation() {
    const {
        isConfigValid,
        configErrors,
        debug,
        publishableKey,
        apiUrl,
        userType,
    } = useConfig();

    const warnings = useMemo(() => {
        const warnings: string[] = [];

        // Development warnings
        if (publishableKey?.startsWith('pk_test_') &&
            typeof window !== 'undefined' &&
            window.location.hostname !== 'localhost' &&
            !window.location.hostname.includes('127.0.0.1')) {
            warnings.push('Using test publishable key in production environment');
        }

        if (apiUrl?.startsWith('http://') &&
            typeof window !== 'undefined' &&
            window.location.protocol === 'https:') {
            warnings.push('Using HTTP API URL on HTTPS site');
        }

        return warnings;
    }, [publishableKey, apiUrl]);

    return {
        isValid: isConfigValid,
        errors: configErrors,
        warnings,
        debug,

        // Helper methods
        hasErrors: configErrors.length > 0,
        hasWarnings: warnings.length > 0,
        isProduction: !publishableKey?.startsWith('pk_test_'),
        isTestMode: publishableKey?.startsWith('pk_test_'),

        // Validation helpers
        validatePublishableKey: () => {
            if (!publishableKey) return false;
            return /^pk_(test|live)_[a-zA-Z0-9_]+$/.test(publishableKey);
        },
        validateApiUrl: () => {
            if (!apiUrl) return true; // Optional
            try {
                new URL(apiUrl);
                return true;
            } catch {
                return false;
            }
        },
        validateUserType: () => {
            return ['internal', 'external', 'end_user'].includes(userType);
        },
    };
}