/**
 * @frank-auth/react - Configuration Validators
 *
 * Comprehensive validation system for all configuration types with
 * detailed error reporting and type safety.
 */

import type {
    AppearanceConfig,
    AppearanceMode,
    ColorVariant,
    ComponentOverrides,
    ComponentSize,
    ConfigValidationError,
    ConfigValidationResult,
    FrankAuthUIConfig,
    Locale,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
    ThemeMode,
    UserType,
} from './types';

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Creates a validation error
 */
function createError(path: string, message: string, value?: any): ConfigValidationError {
    return {path, message, value};
}

/**
 * Creates a validation warning
 */
function createWarning(path: string, message: string, value?: any): ConfigValidationError {
    return {path, message, value};
}

/**
 * Validates if a value is a valid URL
 */
function isValidUrl(url: string): boolean {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

/**
 * Validates if a value is a valid hex color
 */
function isValidHexColor(color: string): boolean {
    return /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color);
}

/**
 * Validates if a value is a valid CSS value
 */
function isValidCSSValue(value: string): boolean {
    // Basic CSS value validation - can be extended
    return typeof value === 'string' && value.length > 0;
}

/**
 * Validates if a value is one of the allowed options
 */
function isValidOption<T extends string>(value: string, options: readonly T[]): value is T {
    return options.includes(value as T);
}

/**
 * Validates if an object has required properties
 */
function hasRequiredProperties(obj: any, properties: string[]): boolean {
    return properties.every(prop => prop in obj && obj[prop] !== undefined);
}

// ============================================================================
// Specific Validators
// ============================================================================

/**
 * Validates publishable key format
 */
export function validatePublishableKey(key: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!key) {
        errors.push(createError('publishableKey', 'Publishable key is required'));
        return errors;
    }

    if (typeof key !== 'string') {
        errors.push(createError('publishableKey', 'Publishable key must be a string', key));
        return errors;
    }

    // Check format: pk_test_... or pk_live_...
    if (!/^pk_(test|live)_[a-zA-Z0-9_]+$/.test(key)) {
        errors.push(createError('publishableKey', 'Invalid publishable key format. Expected: pk_test_... or pk_live_...', key));
    }

    if (key.length < 20) {
        errors.push(createError('publishableKey', 'Publishable key appears to be too short', key));
    }

    return errors;
}

/**
 * Validates API URL
 */
export function validateApiUrl(url?: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!url) {
        return errors; // API URL is optional
    }

    if (typeof url !== 'string') {
        errors.push(createError('apiUrl', 'API URL must be a string', url));
        return errors;
    }

    if (!isValidUrl(url)) {
        errors.push(createError('apiUrl', 'Invalid API URL format', url));
    }

    // Check for HTTPS in production
    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
        errors.push(createWarning('apiUrl', 'Consider using HTTPS for production API URL', url));
    }

    return errors;
}

/**
 * Validates user type
 */
export function validateUserType(userType: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validUserTypes: UserType[] = ['internal', 'external', 'end_user'];

    if (!isValidOption(userType, validUserTypes)) {
        errors.push(createError('userType', `Invalid user type. Must be one of: ${validUserTypes.join(', ')}`, userType));
    }

    return errors;
}

/**
 * Validates locale
 */
export function validateLocale(locale: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validLocales: Locale[] = ['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh'];

    if (!isValidOption(locale, validLocales)) {
        errors.push(createError('locale', `Invalid locale. Must be one of: ${validLocales.join(', ')}`, locale));
    }

    return errors;
}

// ============================================================================
// Theme Validation
// ============================================================================

/**
 * Validates theme mode
 */
export function validateThemeMode(mode: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validModes: ThemeMode[] = ['light', 'dark', 'system'];

    if (!isValidOption(mode, validModes)) {
        errors.push(createError('theme.mode', `Invalid theme mode. Must be one of: ${validModes.join(', ')}`, mode));
    }

    return errors;
}

/**
 * Validates color palette
 */
export function validateColorPalette(colors: any, path = 'theme.colors'): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!colors || typeof colors !== 'object') {
        errors.push(createError(path, 'Colors must be an object', colors));
        return errors;
    }

    // Validate required color properties
    const requiredColors = ['primary', 'secondary', 'background', 'foreground'];
    for (const colorKey of requiredColors) {
        if (!(colorKey in colors)) {
            errors.push(createError(`${path}.${colorKey}`, `Missing required color: ${colorKey}`));
            continue;
        }

        const colorValue = colors[colorKey];

        // Primary and secondary should be objects with shades
        if (colorKey === 'primary' || colorKey === 'secondary') {
            if (typeof colorValue !== 'object') {
                errors.push(createError(`${path}.${colorKey}`, `${colorKey} must be an object with color shades`, colorValue));
                continue;
            }

            // Check for required shades
            const requiredShades = ['DEFAULT', 'foreground'];
            for (const shade of requiredShades) {
                if (!(shade in colorValue)) {
                    errors.push(createError(`${path}.${colorKey}.${shade}`, `Missing required shade: ${shade}`));
                } else if (!isValidHexColor(colorValue[shade])) {
                    errors.push(createError(`${path}.${colorKey}.${shade}`, 'Invalid hex color format', colorValue[shade]));
                }
            }
        } else {
            // Background, foreground should be hex colors
            if (!isValidHexColor(colorValue)) {
                errors.push(createError(`${path}.${colorKey}`, 'Invalid hex color format', colorValue));
            }
        }
    }

    return errors;
}

/**
 * Validates typography configuration
 */
export function validateTypography(typography: any, path = 'theme.typography'): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!typography || typeof typography !== 'object') {
        errors.push(createError(path, 'Typography must be an object', typography));
        return errors;
    }

    // Validate font families
    if (typography.fontFamily) {
        if (typeof typography.fontFamily !== 'object') {
            errors.push(createError(`${path}.fontFamily`, 'Font family must be an object', typography.fontFamily));
        } else {
            if (typography.fontFamily.sans && !Array.isArray(typography.fontFamily.sans)) {
                errors.push(createError(`${path}.fontFamily.sans`, 'Sans font family must be an array', typography.fontFamily.sans));
            }
            if (typography.fontFamily.mono && !Array.isArray(typography.fontFamily.mono)) {
                errors.push(createError(`${path}.fontFamily.mono`, 'Mono font family must be an array', typography.fontFamily.mono));
            }
        }
    }

    // Validate font sizes
    if (typography.fontSize) {
        if (typeof typography.fontSize !== 'object') {
            errors.push(createError(`${path}.fontSize`, 'Font size must be an object', typography.fontSize));
        } else {
            Object.entries(typography.fontSize).forEach(([size, value]) => {
                if (!Array.isArray(value) || value.length !== 2) {
                    errors.push(createError(`${path}.fontSize.${size}`, 'Font size value must be an array with [size, lineHeight]', value));
                }
            });
        }
    }

    return errors;
}

/**
 * Validates complete theme configuration
 */
export function validateThemeConfig(theme: Partial<Theme>): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!theme || typeof theme !== 'object') {
        errors.push(createError('theme', 'Theme must be an object', theme));
        return errors;
    }

    // Validate theme mode
    if (theme.mode) {
        errors.push(...validateThemeMode(theme.mode));
    }

    // Validate colors
    if (theme.colors) {
        errors.push(...validateColorPalette(theme.colors));
    }

    // Validate typography
    if (theme.typography) {
        errors.push(...validateTypography(theme.typography));
    }

    // Validate spacing
    if (theme.spacing) {
        if (typeof theme.spacing !== 'object') {
            errors.push(createError('theme.spacing', 'Spacing must be an object', theme.spacing));
        } else {
            Object.entries(theme.spacing).forEach(([key, value]) => {
                if (!isValidCSSValue(value as string)) {
                    errors.push(createError(`theme.spacing.${key}`, 'Invalid CSS value for spacing', value));
                }
            });
        }
    }

    return errors;
}

// ============================================================================
// Appearance Validation
// ============================================================================

/**
 * Validates appearance mode
 */
export function validateAppearanceMode(mode: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validModes: AppearanceMode[] = ['system', 'light', 'dark'];

    if (!isValidOption(mode, validModes)) {
        errors.push(createError('appearance.mode', `Invalid appearance mode. Must be one of: ${validModes.join(', ')}`, mode));
    }

    return errors;
}

/**
 * Validates component size
 */
export function validateComponentSize(size: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validSizes: ComponentSize[] = ['sm', 'md', 'lg'];

    if (!isValidOption(size, validSizes)) {
        errors.push(createError('size', `Invalid component size. Must be one of: ${validSizes.join(', ')}`, size));
    }

    return errors;
}

/**
 * Validates color variant
 */
export function validateColorVariant(variant: string): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];
    const validVariants: ColorVariant[] = ['default', 'primary', 'secondary', 'success', 'warning', 'danger'];

    if (!isValidOption(variant, validVariants)) {
        errors.push(createError('color', `Invalid color variant. Must be one of: ${validVariants.join(', ')}`, variant));
    }

    return errors;
}

/**
 * Validates branding configuration
 */
export function validateBrandingConfig(branding: any, path = 'appearance.branding'): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!branding || typeof branding !== 'object') {
        errors.push(createError(path, 'Branding must be an object', branding));
        return errors;
    }

    // Validate logo
    if (branding.logo) {
        if (branding.logo.url && !isValidUrl(branding.logo.url)) {
            errors.push(createError(`${path}.logo.url`, 'Invalid logo URL', branding.logo.url));
        }
        if (!branding.logo.alt) {
            errors.push(createError(`${path}.logo.alt`, 'Logo alt text is required for accessibility'));
        }
    }

    // Validate colors
    if (branding.colors) {
        if (branding.colors.primary && !isValidHexColor(branding.colors.primary)) {
            errors.push(createError(`${path}.colors.primary`, 'Invalid hex color format', branding.colors.primary));
        }
        if (branding.colors.secondary && !isValidHexColor(branding.colors.secondary)) {
            errors.push(createError(`${path}.colors.secondary`, 'Invalid hex color format', branding.colors.secondary));
        }
    }

    return errors;
}

/**
 * Validates appearance configuration
 */
export function validateAppearanceConfig(appearance: Partial<AppearanceConfig>): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!appearance || typeof appearance !== 'object') {
        errors.push(createError('appearance', 'Appearance must be an object', appearance));
        return errors;
    }

    // Validate appearance mode
    if (appearance.mode) {
        errors.push(...validateAppearanceMode(appearance.mode));
    }

    // Validate branding
    if (appearance.branding) {
        errors.push(...validateBrandingConfig(appearance.branding));
    }

    // Validate component appearance
    if (appearance.components) {
        const {components} = appearance;

        if (components.input?.size) {
            errors.push(...validateComponentSize(components.input.size));
        }
        if (components.input?.color) {
            errors.push(...validateColorVariant(components.input.color));
        }
        if (components.button?.size) {
            errors.push(...validateComponentSize(components.button.size));
        }
        if (components.button?.color) {
            errors.push(...validateColorVariant(components.button.color));
        }
    }

    return errors;
}

// ============================================================================
// Localization Validation
// ============================================================================

/**
 * Validates localization configuration
 */
export function validateLocalizationConfig(localization: Partial<LocalizationConfig>): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!localization || typeof localization !== 'object') {
        errors.push(createError('localization', 'Localization must be an object', localization));
        return errors;
    }

    // Validate default locale
    if (localization.defaultLocale) {
        errors.push(...validateLocale(localization.defaultLocale).map(error => ({
            ...error,
            path: `localization.${error.path}`,
        })));
    }

    // Validate fallback locale
    if (localization.fallbackLocale) {
        errors.push(...validateLocale(localization.fallbackLocale).map(error => ({
            ...error,
            path: `localization.${error.path}`,
        })));
    }

    // Validate supported locales
    if (localization.supportedLocales) {
        if (!Array.isArray(localization.supportedLocales)) {
            errors.push(createError('localization.supportedLocales', 'Supported locales must be an array', localization.supportedLocales));
        } else {
            localization.supportedLocales.forEach((locale, index) => {
                errors.push(...validateLocale(locale).map(error => ({
                    ...error,
                    path: `localization.supportedLocales[${index}]`,
                })));
            });
        }
    }

    // Validate date/time formats
    if (localization.dateFormat && typeof localization.dateFormat !== 'string') {
        errors.push(createError('localization.dateFormat', 'Date format must be a string', localization.dateFormat));
    }

    if (localization.timeFormat && typeof localization.timeFormat !== 'string') {
        errors.push(createError('localization.timeFormat', 'Time format must be a string', localization.timeFormat));
    }

    return errors;
}

// ============================================================================
// Organization Validation
// ============================================================================

/**
 * Validates organization configuration
 */
export function validateOrganizationConfig(organization: Partial<OrganizationConfig>): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!organization || typeof organization !== 'object') {
        errors.push(createError('organization', 'Organization must be an object', organization));
        return errors;
    }

    // Validate organization ID
    if (organization.id && typeof organization.id !== 'string') {
        errors.push(createError('organization.id', 'Organization ID must be a string', organization.id));
    }

    // Validate organization name
    if (organization.name && typeof organization.name !== 'string') {
        errors.push(createError('organization.name', 'Organization name must be a string', organization.name));
    }

    // Validate settings
    if (organization.settings) {
        const {settings} = organization;

        // Validate password policy
        if (settings.passwordPolicy) {
            if (settings.passwordPolicy.minLength && typeof settings.passwordPolicy.minLength !== 'number') {
                errors.push(createError('organization.settings.passwordPolicy.minLength', 'Min length must be a number', settings.passwordPolicy.minLength));
            }
            if (settings.passwordPolicy.minLength && settings.passwordPolicy.minLength < 4) {
                errors.push(createWarning('organization.settings.passwordPolicy.minLength', 'Minimum password length should be at least 4 characters'));
            }
        }

        // Validate session settings
        if (settings.sessionSettings) {
            if (settings.sessionSettings.maxDuration && typeof settings.sessionSettings.maxDuration !== 'number') {
                errors.push(createError('organization.settings.sessionSettings.maxDuration', 'Max duration must be a number', settings.sessionSettings.maxDuration));
            }
        }

        // Validate branding
        if (settings.branding) {
            errors.push(...validateBrandingConfig(settings.branding, 'organization.settings.branding'));
        }
    }

    return errors;
}

// ============================================================================
// Component Override Validation
// ============================================================================

/**
 * Validates component overrides
 */
export function validateComponentOverrides(components: ComponentOverrides): ConfigValidationError[] {
    const errors: ConfigValidationError[] = [];

    if (!components || typeof components !== 'object') {
        errors.push(createError('components', 'Components must be an object', components));
        return errors;
    }

    // Validate that each override is a valid React component
    Object.entries(components).forEach(([componentName, Component]) => {
        if (Component && typeof Component !== 'function') {
            errors.push(createError(`components.${componentName}`, 'Component override must be a React component (function)', Component));
        }
    });

    return errors;
}

// ============================================================================
// Main Configuration Validation
// ============================================================================

/**
 * Validates the complete Frank Auth UI configuration
 */
export function validateFrankAuthConfig(config: Partial<FrankAuthUIConfig>): ConfigValidationResult {
    const errors: ConfigValidationError[] = [];
    const warnings: ConfigValidationError[] = [];

    if (!config || typeof config !== 'object') {
        return {
            isValid: false,
            errors: [createError('config', 'Configuration must be an object', config)],
            warnings: [],
        };
    }

    // Validate required fields
    if (!config.publishableKey) {
        errors.push(createError('publishableKey', 'Publishable key is required'));
    } else {
        errors.push(...validatePublishableKey(config.publishableKey));
    }

    if (!config.userType) {
        errors.push(createError('userType', 'User type is required'));
    } else {
        errors.push(...validateUserType(config.userType));
    }

    // Validate optional fields
    if (config.apiUrl) {
        const apiUrlErrors = validateApiUrl(config.apiUrl);
        errors.push(...apiUrlErrors.filter(e => e.path.includes('error')));
        warnings.push(...apiUrlErrors.filter(e => e.path.includes('warning')));
    }

    if (config.theme) {
        errors.push(...validateThemeConfig(config.theme));
    }

    if (config.appearance) {
        errors.push(...validateAppearanceConfig(config.appearance));
    }

    if (config.localization) {
        errors.push(...validateLocalizationConfig(config.localization));
    }

    if (config.organization) {
        errors.push(...validateOrganizationConfig(config.organization));
    }

    if (config.components) {
        errors.push(...validateComponentOverrides(config.components));
    }

    // Validate features
    if (config.features) {
        if (typeof config.features !== 'object') {
            errors.push(createError('features', 'Features must be an object', config.features));
        } else {
            // Check for at least one authentication method enabled
            if (!config.features.signIn && !config.features.sso) {
                warnings.push(createWarning('features', 'At least one authentication method (signIn or sso) should be enabled'));
            }
        }
    }

    return {
        isValid: errors.length === 0,
        errors,
        warnings,
    };
}

// ============================================================================
// Quick Validation Functions
// ============================================================================

/**
 * Quick validation that throws on errors
 */
export function assertValidConfig(config: Partial<FrankAuthUIConfig>): void {
    const result = validateFrankAuthConfig(config);

    if (!result.isValid) {
        const errorMessages = result.errors.map(error => `${error.path}: ${error.message}`);
        throw new Error(`Invalid Frank Auth configuration:\n${errorMessages.join('\n')}`);
    }
}

/**
 * Validates configuration and returns boolean
 */
export function isValidConfig(config: Partial<FrankAuthUIConfig>): boolean {
    return validateFrankAuthConfig(config).isValid;
}

/**
 * Gets validation errors as formatted strings
 */
export function getConfigErrors(config: Partial<FrankAuthUIConfig>): string[] {
    const result = validateFrankAuthConfig(config);
    return result.errors.map(error => `${error.path}: ${error.message}`);
}

/**
 * Gets validation warnings as formatted strings
 */
export function getConfigWarnings(config: Partial<FrankAuthUIConfig>): string[] {
    const result = validateFrankAuthConfig(config);
    return result.warnings.map(warning => `${warning.path}: ${warning.message}`);
}