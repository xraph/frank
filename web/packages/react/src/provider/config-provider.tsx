/**
 * @frank-auth/react - Config Provider
 *
 * Configuration provider that manages UI configuration, themes, localization,
 * and organization-specific settings for the authentication components.
 */

'use client';

import React, {createContext, useCallback, useContext, useEffect, useMemo, useReducer} from 'react';

import type {Organization, OrganizationSettings} from '@frank-auth/client';

import type {
    AppearanceConfig,
    ComponentOverrides,
    FrankAuthUIConfig,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
} from '../config';
import {ConfigManager, createFrankAuthConfig, defaultConfig, validateFrankAuthConfig,} from '../config';

import type {AuthFeatures, ConfigContextValue, ConfigProviderProps, ConfigState,} from './types';

// ============================================================================
// Config Context
// ============================================================================

const ConfigContext = createContext<ConfigContextValue | null>(null);

// ============================================================================
// Config Reducer
// ============================================================================

type ConfigAction =
    | { type: 'SET_LOADED'; payload: boolean }
    | { type: 'SET_CONFIG'; payload: FrankAuthUIConfig }
    | { type: 'UPDATE_CONFIG'; payload: Partial<FrankAuthUIConfig> }
    | { type: 'SET_ORGANIZATION'; payload: OrganizationConfig }
    | { type: 'SET_ORGANIZATION_SETTINGS'; payload: OrganizationSettings }
    | { type: 'SET_THEME'; payload: Theme }
    | { type: 'SET_APPEARANCE'; payload: AppearanceConfig }
    | { type: 'SET_LOCALIZATION'; payload: LocalizationConfig }
    | { type: 'SET_COMPONENTS'; payload: ComponentOverrides }
    | { type: 'SET_FEATURES'; payload: AuthFeatures }
    | { type: 'SET_DEBUG'; payload: boolean }
    | { type: 'RESET_CONFIG' };

function configReducer(state: ConfigState, action: ConfigAction): ConfigState {
    switch (action.type) {
        case 'SET_LOADED':
            return { ...state, isLoaded: action.payload };

        case 'SET_CONFIG':
            return {
                ...state,
                config: action.payload,
                publishableKey: action.payload.publishableKey,
                userType: action.payload.userType,
                apiUrl: action.payload.apiUrl || state.apiUrl,
                theme: action.payload.theme || state.theme,
                appearance: action.payload.appearance || state.appearance,
                localization: action.payload.localization || state.localization,
                components: action.payload.components || state.components,
                linksPath: { ...(state.linksPath ?? {}), ...action.payload.linksPath},
                features: action.payload.features || state.features,
                debug: action.payload.debug || state.debug,
                frontendUrl: action.payload.frontendUrl || state.frontendUrl,
            };

        case 'UPDATE_CONFIG':
            const updatedConfig = { ...state.config, ...action.payload };
            return {
                ...state,
                config: updatedConfig,
                theme: action.payload.theme || state.theme,
                appearance: action.payload.appearance || state.appearance,
                localization: action.payload.localization || state.localization,
                components: action.payload.components || state.components,
                linksPath: { ...(state.linksPath ?? {}), ...action.payload.linksPath},
                features: action.payload.features || state.features,
                debug: action.payload.debug !== undefined ? action.payload.debug : state.debug,
                frontendUrl: action.payload.frontendUrl || state.frontendUrl,
            };

        case 'SET_ORGANIZATION':
            return {
                ...state,
                organizationConfig: action.payload,
                config: {
                    ...state.config,
                    organization: action.payload,
                    organizationId: action.payload.id,
                },
            };

        case 'SET_ORGANIZATION_SETTINGS':
            return {
                ...state,
                organizationSettings: action.payload,
            };

        case 'SET_THEME':
            return {
                ...state,
                theme: action.payload,
                config: {
                    ...state.config,
                    theme: action.payload,
                },
            };

        case 'SET_APPEARANCE':
            return {
                ...state,
                appearance: action.payload,
                config: {
                    ...state.config,
                    appearance: action.payload,
                },
            };

        case 'SET_LOCALIZATION':
            return {
                ...state,
                localization: action.payload,
                config: {
                    ...state.config,
                    localization: action.payload,
                },
            };

        case 'SET_COMPONENTS':
            return {
                ...state,
                components: action.payload,
                config: {
                    ...state.config,
                    components: action.payload,
                },
            };

        case 'SET_FEATURES':
            return {
                ...state,
                features: action.payload,
                config: {
                    ...state.config,
                    features: action.payload,
                },
            };

        case 'SET_DEBUG':
            return {
                ...state,
                debug: action.payload,
                config: {
                    ...state.config,
                    debug: action.payload,
                },
            };

        case 'RESET_CONFIG':
            return {
                ...initialConfigState,
                publishableKey: state.publishableKey,
                userType: state.userType,
                apiUrl: state.apiUrl,
                isLoaded: true,
            };

        default:
            return state;
    }
}

// ============================================================================
// Initial State
// ============================================================================

const initialConfigState: ConfigState = {
    isLoaded: false,
    config: defaultConfig as FrankAuthUIConfig,
    publishableKey: '',
    userType: 'external',
    apiUrl: 'https://api.frankauth.com',
    theme: defaultConfig.theme!,
    appearance: defaultConfig.appearance!,
    localization: defaultConfig.localization!,
    components: {},
    linksPath: {
        signUp: '/auth/sign-up',
        magicLink: '/auth/magic-link',
        verify: '/auth/verify',
        signIn: '/auth/sign-in',
        resetPassword: '/auth/reset-password',
        forgotPassword: '/auth/forgot-password',
        signOut: '/auth/sign-out'
    },
    features: {
        signUp: true,
        signIn: true,
        passwordReset: true,
        mfa: false,
        passkeys: false,
        oauth: false,
        magicLink: false,
        sso: false,
        organizationManagement: false,
        userProfile: true,
        sessionManagement: true,
    },
    debug: false,
};

// ============================================================================
// Config Provider Component
// ============================================================================

export function ConfigProvider({
                                   children,
                                   config: initialConfig,
                                   onConfigChange,
                               }: ConfigProviderProps) {
    const [state, dispatch] = useReducer(configReducer, initialConfigState);

    // Initialize config manager
    const configManager = useMemo(() => {
        try {
            const validatedConfig = createFrankAuthConfig(initialConfig);
            return new ConfigManager(validatedConfig);
        } catch (error) {
            console.error('[FrankAuth] Invalid configuration:', error);
            throw error;
        }
    }, [initialConfig]);

    // Initialize state with provided config
    useEffect(() => {
        const validatedConfig = configManager.getConfig();
        dispatch({ type: 'SET_CONFIG', payload: validatedConfig });
        dispatch({ type: 'SET_LOADED', payload: true });
    }, [configManager]);

    // Subscribe to config manager changes
    useEffect(() => {
        const unsubscribe = configManager.subscribe((updatedConfig) => {
            dispatch({ type: 'SET_CONFIG', payload: updatedConfig });
            onConfigChange?.(updatedConfig);
        });

        return unsubscribe;
    }, [configManager, onConfigChange]);

    // Apply configuration to DOM
    useEffect(() => {
        if (typeof window !== 'undefined' && state.isLoaded) {
            configManager.applyToDOM();
        }
    }, [configManager, state.isLoaded, state.theme, state.appearance]);

    // Update config method
    const updateConfig = useCallback((updates: Partial<FrankAuthUIConfig>) => {
        try {
            // Validate updates
            const validation = validateFrankAuthConfig({ ...state.config, ...updates });
            if (!validation.isValid) {
                const errorMessages = validation.errors.map(e => e.message).join(', ');
                throw new Error(`Configuration validation failed: ${errorMessages}`);
            }

            configManager.updateConfig(updates);
            dispatch({ type: 'UPDATE_CONFIG', payload: updates });
        } catch (error) {
            console.error('[FrankAuth] Configuration update failed:', error);
            throw error;
        }
    }, [configManager, state.config]);

    // Set organization method
    const setOrganization = useCallback((organization: Organization) => {
        try {
            // Transform organization to config format
            const organizationConfig: OrganizationConfig = {
                id: organization.id,
                name: organization.name,
                slug: organization.slug || '',
                settings: organization.settings || {} as any,
                features: {
                    sso: organization.ssoEnabled || false,
                    mfa: organization.settings?.mfaSettings?.enabled || false,
                    auditLogs: organization.settings?.auditSettings?.enabled || false,
                    customBranding: organization.settings?.branding ? true : false,
                    apiAccess: organization.apiEnabled || false,
                },
                limits: {
                    maxUsers: organization.userLimit || 100,
                    maxSessions: organization.sessionLimit || 10,
                    apiRequestLimit: organization.apiRequestLimit || 1000,
                },
            };

            configManager.setOrganization(organizationConfig);
            dispatch({ type: 'SET_ORGANIZATION', payload: organizationConfig });

            // Update features based on organization settings
            const updatedFeatures = determineOrganizationFeatures(organizationConfig);
            dispatch({ type: 'SET_FEATURES', payload: updatedFeatures });
        } catch (error) {
            console.error('[FrankAuth] Failed to set organization:', error);
            throw error;
        }
    }, [configManager]);

    // Set theme method
    const setTheme = useCallback((theme: Partial<Theme>) => {
        try {
            configManager.getThemeManager().setTheme(theme);
            dispatch({ type: 'SET_THEME', payload: configManager.getThemeManager().getTheme() });
        } catch (error) {
            console.error('[FrankAuth] Failed to set theme:', error);
            throw error;
        }
    }, [configManager]);

    // Set appearance method
    const setAppearance = useCallback((appearance: Partial<AppearanceConfig>) => {
        try {
            configManager.getAppearanceManager().updateConfig(appearance);
            dispatch({ type: 'SET_APPEARANCE', payload: configManager.getAppearanceManager().getConfig() });
        } catch (error) {
            console.error('[FrankAuth] Failed to set appearance:', error);
            throw error;
        }
    }, [configManager]);

    // Set locale method
    const setLocale = useCallback((locale: string) => {
        try {
            configManager.getLocalizationManager().setLocale(locale as any);
            dispatch({ type: 'SET_LOCALIZATION', payload: {
                    ...state.localization,
                    defaultLocale: locale as any,
                }});
        } catch (error) {
            console.error('[FrankAuth] Failed to set locale:', error);
            throw error;
        }
    }, [configManager, state.localization]);

    // Apply organization branding method
    const applyOrganizationBranding = useCallback((organization: Organization) => {
        try {
            if (organization.settings?.branding) {
                const branding = {
                    logo: {
                        url: organization.logoUrl,
                        alt: organization.name,
                    },
                    colors: {
                        primary: organization.settings.branding.primaryColor || '#3b82f6',
                        secondary: organization.settings.branding.secondaryColor || '#64748b',
                    },
                    fonts: {
                        primary: 'Inter, ui-sans-serif, system-ui, sans-serif',
                    },
                    customCSS: organization.settings.branding.customCSS,
                };

                configManager.getThemeManager().applyBranding(branding);
                configManager.getAppearanceManager().applyOrganizationBranding(organization as any);
            }
        } catch (error) {
            console.error('[FrankAuth] Failed to apply organization branding:', error);
            throw error;
        }
    }, [configManager]);

    // Reset to defaults method
    const resetToDefaults = useCallback(() => {
        try {
            configManager.reset();
            dispatch({ type: 'RESET_CONFIG' });
        } catch (error) {
            console.error('[FrankAuth] Failed to reset configuration:', error);
            throw error;
        }
    }, [configManager]);

    // Helper function to determine organization features
    const determineOrganizationFeatures = (organizationConfig: OrganizationConfig): AuthFeatures => {
        const settings = organizationConfig.settings;

        return {
            signUp: settings.allowPublicSignup || false,
            signIn: true,
            passwordReset: true,
            mfa: organizationConfig.features.mfa,
            passkeys: (settings.authConfig as any)?.passkeysEnabled || false,
            oauth: (settings.authConfig as any)?.oauthEnabled || false,
            magicLink: (settings.authConfig as any)?.magicLinkEnabled || false,
            sso: organizationConfig.features.sso,
            organizationManagement: true,
            userProfile: true,
            sessionManagement: true,
        };
    };

    // Context value
    const contextValue: ConfigContextValue = {
        // State
        ...state,

        // Methods
        updateConfig,
        setOrganization,
        setTheme,
        setAppearance,
        setLocale,
        applyOrganizationBranding,
        resetToDefaults,
    };

    return (
        <ConfigContext.Provider value={contextValue}>
            {children}
        </ConfigContext.Provider>
    );
}

// ============================================================================
// Hook to use config context
// ============================================================================

export function useConfig() {
    const context = useContext(ConfigContext);

    if (!context) {
        throw new Error('useConfig must be used within a ConfigProvider');
    }

    return context;
}

// ============================================================================
// Hook for feature flags
// ============================================================================

export function useFeatures() {
    const { features } = useConfig();

    return {
        ...features,
        hasFeature: (feature: keyof AuthFeatures) => features[feature],
        requireFeature: (feature: keyof AuthFeatures) => {
            if (!features[feature]) {
                throw new Error(`Feature ${feature} is not enabled`);
            }
        },
    };
}

// ============================================================================
// Hook for organization configuration
// ============================================================================

export function useOrganizationConfig() {
    const { organizationConfig, organizationSettings, setOrganization, applyOrganizationBranding } = useConfig();

    return {
        organization: organizationConfig,
        settings: organizationSettings,
        setOrganization,
        applyBranding: applyOrganizationBranding,
        hasOrganization: !!organizationConfig,
        isMultiTenant: !!organizationConfig,
    };
}

// ============================================================================
// Hook for component overrides
// ============================================================================

export function useComponentOverrides() {
    const { components } = useConfig();

    const getComponent = useCallback(<T extends keyof ComponentOverrides>(
        componentName: T,
        defaultComponent: any
    ) => {
        return components[componentName] || defaultComponent;
    }, [components]);

    return {
        components,
        getComponent,
        hasOverride: (componentName: keyof ComponentOverrides) => !!components[componentName],
    };
}

// ============================================================================
// Higher-order component for configuration
// ============================================================================

export function withConfig<T extends object>(Component: React.ComponentType<T>) {
    const WithConfigComponent = (props: T) => {
        const config = useConfig();

        return <Component {...props} config={config} />;
    };

    WithConfigComponent.displayName = `withConfig(${Component.displayName || Component.name})`;

    return WithConfigComponent;
}

// ============================================================================
// Export config provider
// ============================================================================

export { ConfigContext };
export type { ConfigContextValue };
