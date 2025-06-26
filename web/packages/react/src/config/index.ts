/**
 * @frank-auth/react - Configuration System
 *
 * Unified entry point for the Frank Auth React UI configuration system.
 * Provides comprehensive configuration management for themes, appearance,
 * localization, and organization-specific settings.
 *
 * @example Basic Usage
 * ```typescript
 * import { createFrankAuthConfig } from '@frank-auth/react/config';
 *
 * const config = createFrankAuthConfig({
 *   publishableKey: 'pk_test_...',
 *   userType: 'external',
 *   theme: {
 *     mode: 'dark',
 *     colors: {
 *       primary: '#3b82f6',
 *     },
 *   },
 * });
 * ```
 *
 * @example Advanced Usage
 * ```typescript
 * import { 
 *   ConfigManager,
 *   ThemeManager,
 *   AppearanceManager,
 *   LocalizationManager,
 *   OrganizationConfigManager
 * } from '@frank-auth/react/config';
 *
 * const configManager = new ConfigManager({
 *   publishableKey: 'pk_test_...',
 *   userType: 'external',
 *   organizationId: 'org_123',
 * });
 *
 * // Listen for configuration changes
 * configManager.subscribe((config) => {
 *   console.log('Configuration updated:', config);
 * });
 * ```
 */

import {AppearanceManager} from './appearance';
import {LocalizationManager} from './localization';
import {OrganizationConfigManager, transformOrganizationSettings} from './organization';
import {ThemeManager} from './theme';
import {ConfigValidationResult, FrankAuthUIConfig, OrganizationConfig, UserType} from './types';
import {CONFIG_PRESETS, DEFAULT_FRANK_AUTH_CONFIG,} from './defaults';
import {
    assertValidConfig,
    getConfigErrors,
    getConfigWarnings,
    isValidConfig,
    validateApiUrl,
    validateAppearanceConfig,
    validateComponentOverrides,
    validateFrankAuthConfig,
    validateLocale,
    validateLocalizationConfig,
    validateOrganizationConfig,
    validatePublishableKey,
    validateThemeConfig,
    validateUserType,
} from './validators';

// ============================================================================
// Type Exports
// ============================================================================

// Core configuration types
export type {
    FrankAuthUIConfig,
    ConfigValidationError,
    ConfigValidationResult,
} from './types';

// Theme types
export type {
    ThemeMode,
    Typography,
} from './types';

// Appearance types
export type {
    AppearanceConfig,
    AppearanceMode,
    ComponentAppearance,
    BrandingConfig,
    ComponentSize,
    ColorVariant,
} from './types';

// Localization types
export type {
    LocalizationConfig,
    Locale,
    LocaleDirection,
} from './types';

// Organization types
export type {
    OrganizationConfig,
    OrganizationSettings,
    UserType,
    ComponentOverrides,
} from './types';

// Extended organization types
export type {
    OrganizationFeatureFlags,
    OrganizationLimits,
    OrganizationCompliance,
    ExtendedOrganizationConfig,
} from './organization';

// ============================================================================
// Default Configuration Exports
// ============================================================================

export {
    // Main defaults
    DEFAULT_FRANK_AUTH_CONFIG as defaultConfig,
    CONFIG_PRESETS as configPresets,

    // Theme defaults
    DEFAULT_THEME_CONFIG as defaultTheme,
    DEFAULT_COLOR_PALETTE as defaultColors,
    DEFAULT_TYPOGRAPHY as defaultTypography,
    DEFAULT_SPACING as defaultSpacing,
    DEFAULT_BORDER_RADIUS as defaultBorderRadius,
    DEFAULT_SHADOWS as defaultShadows,
    DEFAULT_ANIMATIONS as defaultAnimations,

    // Appearance defaults
    DEFAULT_APPEARANCE_CONFIG as defaultAppearance,
    DEFAULT_COMPONENT_APPEARANCE as defaultComponentAppearance,
    DEFAULT_LAYOUT_CONFIG as defaultLayout,
    DEFAULT_BRANDING_CONFIG as defaultBranding,

    // Localization defaults
    DEFAULT_LOCALIZATION_CONFIG as defaultLocalization,
    DEFAULT_LOCALE_MESSAGES as defaultMessages,

    // Organization defaults
    DEFAULT_ORGANIZATION_CONFIG as defaultOrganization,
} from './defaults';

// ============================================================================
// Manager Class Exports
// ============================================================================

export {
    ThemeManager,
    THEME_PRESETS as themePresets,
    createThemeManager,
    createDarkTheme,
    getThemeCSS,
    validateTheme,
} from './theme';

export {
    AppearanceManager,
    INPUT_VARIANTS as inputVariants,
    BUTTON_VARIANTS as buttonVariants,
    CARD_VARIANTS as cardVariants,
    SIZE_CONFIGS as sizeConfigs,
    MODAL_SIZES as modalSizes,
    BREAKPOINTS as breakpoints,
    RESPONSIVE_UTILITIES as responsiveUtils,
    createAppearanceManager,
    getComponentClassNames,
    appearanceConfigToTailwind,
    createResponsiveProps,
} from './appearance';

export {
    LocalizationManager,
    createLocalizationManager,
    detectBrowserLocale,
    getLocaleDirection,
    isRTL,
    createTranslationNamespace,
} from './localization';

export {
    OrganizationConfigManager,
    createOrganizationConfigManager,
    transformOrganizationSettings,
    getFeaturesByTier,
} from './organization';

// ============================================================================
// Validation Exports
// ============================================================================
export {
    validateFrankAuthConfig,
    validateThemeConfig,
    validateAppearanceConfig,
    validateLocalizationConfig,
    validateOrganizationConfig,
    validateComponentOverrides,
    validatePublishableKey,
    validateApiUrl,
    validateUserType,
    validateLocale,
    assertValidConfig,
    isValidConfig,
    getConfigErrors,
    getConfigWarnings,
} from './validators';

// ============================================================================
// Main Configuration Manager
// ============================================================================

/**
 * Comprehensive configuration manager that orchestrates all configuration aspects
 */
export class ConfigManager {
    private config: FrankAuthUIConfig;
    private themeManager: ThemeManager;
    private appearanceManager: AppearanceManager;
    private localizationManager: LocalizationManager;
    private organizationManager?: OrganizationConfigManager;
    private listeners: Set<(config: FrankAuthUIConfig) => void> = new Set();

    constructor(initialConfig: Partial<FrankAuthUIConfig>) {
        // Validate and merge with defaults
        this.config = { ...DEFAULT_FRANK_AUTH_CONFIG, ...initialConfig } as FrankAuthUIConfig;

        // Initialize managers
        this.themeManager = new ThemeManager(this.config.theme);
        this.appearanceManager = new AppearanceManager(this.config.appearance);
        this.localizationManager = new LocalizationManager(this.config.localization);

        // Initialize organization manager if organization config is provided
        if (this.config.organization) {
            this.organizationManager = new OrganizationConfigManager(
                this.config.organization,
                this.themeManager,
                this.appearanceManager
            );
        }

        this.setupManagerListeners();
        this.applyInitialConfiguration();
    }

    /**
     * Get current configuration
     */
    getConfig(): FrankAuthUIConfig {
        return { ...this.config };
    }

    /**
     * Update configuration
     */
    updateConfig(updates: Partial<FrankAuthUIConfig>): void {
        this.config = { ...this.config, ...updates };

        // Update individual managers
        if (updates.theme) {
            this.themeManager.setTheme(updates.theme);
        }

        if (updates.appearance) {
            this.appearanceManager.updateConfig(updates.appearance);
        }

        if (updates.localization) {
            this.localizationManager.updateConfig(updates.localization);
        }

        if (updates.organization && this.organizationManager) {
            this.organizationManager.updateConfig(updates.organization);
        }

        this.notifyListeners();
    }

    /**
     * Set organization configuration
     */
    setOrganization(organization: OrganizationConfig): void {
        this.config.organization = organization;
        this.config.projectId = organization.id;

        // Create or update organization manager
        if (!this.organizationManager) {
            this.organizationManager = new OrganizationConfigManager(
                organization,
                this.themeManager,
                this.appearanceManager
            );

            // Subscribe to organization changes
            this.organizationManager.subscribe((orgConfig) => {
                this.config.organization = orgConfig;
                this.notifyListeners();
            });
        } else {
            this.organizationManager.updateConfig(organization);
        }

        // Apply organization-specific UI configuration
        const orgUIConfig = this.organizationManager.generateUIConfig();
        this.updateConfig(orgUIConfig);
    }

    /**
     * Get theme manager
     */
    getThemeManager(): ThemeManager {
        return this.themeManager;
    }

    /**
     * Get appearance manager
     */
    getAppearanceManager(): AppearanceManager {
        return this.appearanceManager;
    }

    /**
     * Get localization manager
     */
    getLocalizationManager(): LocalizationManager {
        return this.localizationManager;
    }

    /**
     * Get organization manager
     */
    getOrganizationManager(): OrganizationConfigManager | undefined {
        return this.organizationManager;
    }

    /**
     * Apply configuration to DOM
     */
    applyToDOM(): void {
        this.themeManager.applyToDOM();
        this.appearanceManager.applyToDOM();

        // Apply locale direction
        const direction = this.localizationManager.getCurrentLocaleMetadata().direction;
        if (typeof document !== 'undefined') {
            document.documentElement.dir = direction;
            document.documentElement.lang = this.localizationManager.getCurrentLocale();
        }
    }

    /**
     * Generate complete CSS for server-side rendering
     */
    generateCSS(): string {
        let css = '';

        // Theme CSS
        css += this.themeManager.generateCSSVariables();
        css += '\n';

        // Appearance CSS
        css += this.appearanceManager.generateCSS();
        css += '\n';

        return css;
    }

    /**
     * Validate current configuration
     */
    validateConfig(): ConfigValidationResult {
        return validateFrankAuthConfig(this.config);
    }

    /**
     * Subscribe to configuration changes
     */
    subscribe(callback: (config: FrankAuthUIConfig) => void): () => void {
        this.listeners.add(callback);
        return () => {
            this.listeners.delete(callback);
        };
    }

    /**
     * Reset to default configuration
     */
    reset(): void {
        this.config = { ...DEFAULT_FRANK_AUTH_CONFIG } as any;

        this.themeManager.setTheme(this.config.theme || {});
        this.appearanceManager.updateConfig(this.config.appearance || {});
        this.localizationManager.updateConfig(this.config.localization || {});

        this.notifyListeners();
    }

    /**
     * Destroy and cleanup
     */
    destroy(): void {
        this.listeners.clear();
    }

    // Private methods

    private setupManagerListeners(): void {
        // Listen to theme changes
        this.themeManager.subscribe((theme) => {
            this.config.theme = theme;
            this.notifyListeners();
        });

        // Listen to appearance changes
        this.appearanceManager.subscribe((appearance) => {
            this.config.appearance = appearance;
            this.notifyListeners();
        });

        // Listen to localization changes
        this.localizationManager.subscribe((locale) => {
            if (this.config.localization) {
                this.config.localization.defaultLocale = locale;
            }
            this.notifyListeners();
        });
    }

    private applyInitialConfiguration(): void {
        // Apply organization branding if available
        if (this.config.organization?.settings.branding) {
            this.themeManager.applyBranding({
                logo: {
                    url: this.config.organization.settings.branding.logo,
                    alt: this.config.organization.name,
                },
                colors: {
                    primary: this.config.organization.settings.branding.primaryColor || '#3b82f6',
                    secondary: this.config.organization.settings.branding.secondaryColor || '#64748b',
                },
                fonts: {
                    primary: 'Inter, ui-sans-serif, system-ui, sans-serif',
                },
                customCSS: this.config.organization.settings.branding.customCSS,
            });
        }

        // Apply to DOM if in browser environment
        if (typeof window !== 'undefined') {
            this.applyToDOM();
        }
    }

    private notifyListeners(): void {
        this.listeners.forEach(callback => callback(this.config));
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a complete Frank Auth configuration with validation
 */
export function createFrankAuthConfig(config: Partial<FrankAuthUIConfig>): FrankAuthUIConfig {
    const validate = validateFrankAuthConfig;

    // Validate configuration
    const validation = validate(config);
    if (!validation.isValid) {
        throw new Error(`Invalid configuration: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    // Merge with defaults
    return { ...DEFAULT_FRANK_AUTH_CONFIG, ...config } as FrankAuthUIConfig;
}

/**
 * Create a configuration manager instance
 */
export function createConfigManager(config: Partial<FrankAuthUIConfig>): ConfigManager {
    return new ConfigManager(config);
}

/**
 * Create configuration from organization settings (useful for server-side setup)
 */
export function createConfigFromOrganization(
    publishableKey: string,
    userType: UserType,
    organizationSettings: any
): FrankAuthUIConfig {
    const organization = transformOrganizationSettings(organizationSettings);

    return createFrankAuthConfig({
        publishableKey,
        userType,
        organization,
    });
}

/**
 * Merge multiple configuration objects with proper type safety
 */
export function mergeConfigs(...configs: Partial<FrankAuthUIConfig>[]): FrankAuthUIConfig {
    let merged = { ...DEFAULT_FRANK_AUTH_CONFIG };

    for (const config of configs) {
        merged = {
            ...merged,
            ...config,
            theme: { ...merged.theme, ...config.theme },
            appearance: {
                ...merged.appearance,
                ...config.appearance,
                layout: { ...merged.appearance?.layout, ...config.appearance?.layout },
                components: { ...merged.appearance?.components, ...config.appearance?.components },
                branding: { ...merged.appearance?.branding, ...config.appearance?.branding },
            },
            localization: { ...merged.localization, ...config.localization },
            organization: { ...merged.organization, ...config.organization },
            features: { ...merged.features, ...config.features },
            components: { ...merged.components, ...config.components },
        };
    }

    return merged as FrankAuthUIConfig;
}

/**
 * Create a configuration preset
 */
export function createConfigPreset(
    presetName: 'minimal' | 'enterprise' | 'b2b' | 'consumer',
    overrides?: Partial<FrankAuthUIConfig>
): Partial<FrankAuthUIConfig> {
    const preset = CONFIG_PRESETS[presetName];
    if (!preset) {
        throw new Error(`Unknown preset: ${presetName}`);
    }

    return overrides ? mergeConfigs(preset, overrides) : preset;
}

// ============================================================================
// Re-export everything for convenience
// ============================================================================

// Export all types
export * from './types';

// Export main manager as default
export { ConfigManager as default };