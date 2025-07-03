/**
 * @frank-auth/react - Appearance Configuration
 *
 * Advanced appearance management system with component-level customization,
 * branding integration, and responsive design support.
 */

import type {
    AppearanceConfig,
    BrandingConfig,
    ColorVariant,
    ComponentAppearance,
    ComponentSize,
    OrganizationConfig,
} from './types';

import {
    DEFAULT_APPEARANCE_CONFIG,
    DEFAULT_BRANDING_CONFIG,
    DEFAULT_COMPONENT_APPEARANCE,
    DEFAULT_LAYOUT_CONFIG,
} from './defaults';

// ============================================================================
// Component Variant Configurations
// ============================================================================

/**
 * Input component appearance variants
 */
export const INPUT_VARIANTS = {
    flat: {
        className: 'bg-default-100 hover:bg-default-200 focus:bg-default-100',
        style: {
            backgroundColor: 'hsl(var(--color-default-100))',
            border: 'none',
            borderRadius: 'var(--border-radius-md)',
        },
    },
    bordered: {
        className: 'border-2 border-default-200 hover:border-default-300 focus:border-primary',
        style: {
            backgroundColor: 'transparent',
            border: '2px solid hsl(var(--color-default-200))',
            borderRadius: 'var(--border-radius-md)',
        },
    },
    underlined: {
        className: 'border-b-2 border-default-300 hover:border-default-400 focus:border-primary',
        style: {
            backgroundColor: 'transparent',
            border: 'none',
            borderBottom: '2px solid hsl(var(--color-default-300))',
            borderRadius: '0',
        },
    },
    faded: {
        className: 'bg-default-50 hover:bg-default-100 focus:bg-default-100 border border-default-200',
        style: {
            backgroundColor: 'hsl(var(--color-default-50))',
            border: '1px solid hsl(var(--color-default-200))',
            borderRadius: 'var(--border-radius-md)',
        },
    },
} as const;

/**
 * Button component appearance variants
 */
export const BUTTON_VARIANTS = {
    solid: {
        className: 'bg-primary text-primary-foreground hover:bg-primary-600 focus:bg-primary-700',
        style: {
            backgroundColor: 'hsl(var(--color-primary))',
            color: 'hsl(var(--color-primary-foreground))',
            border: 'none',
        },
    },
    bordered: {
        className: 'border-2 border-primary text-primary hover:bg-primary hover:text-primary-foreground',
        style: {
            backgroundColor: 'transparent',
            color: 'hsl(var(--color-primary))',
            border: '2px solid hsl(var(--color-primary))',
        },
    },
    light: {
        className: 'bg-primary-100 text-primary-700 hover:bg-primary-200',
        style: {
            backgroundColor: 'hsl(var(--color-primary-100))',
            color: 'hsl(var(--color-primary-700))',
            border: 'none',
        },
    },
    flat: {
        className: 'bg-default-100 text-default-700 hover:bg-default-200',
        style: {
            backgroundColor: 'hsl(var(--color-default-100))',
            color: 'hsl(var(--color-default-700))',
            border: 'none',
        },
    },
    faded: {
        className: 'bg-default-50 text-default-700 hover:bg-default-100 border border-default-200',
        style: {
            backgroundColor: 'hsl(var(--color-default-50))',
            color: 'hsl(var(--color-default-700))',
            border: '1px solid hsl(var(--color-default-200))',
        },
    },
    shadow: {
        className: 'bg-primary text-primary-foreground hover:bg-primary-600 shadow-lg hover:shadow-xl',
        style: {
            backgroundColor: 'hsl(var(--color-primary))',
            color: 'hsl(var(--color-primary-foreground))',
            border: 'none',
            boxShadow: 'var(--shadow-lg)',
        },
    },
    ghost: {
        className: 'text-primary hover:bg-primary-100 hover:text-primary-700',
        style: {
            backgroundColor: 'transparent',
            color: 'hsl(var(--color-primary))',
            border: 'none',
        },
    },
} as const;

/**
 * Card component appearance variants
 */
export const CARD_VARIANTS = {
    shadow: {
        className: 'bg-card text-card-foreground shadow-md',
        style: {
            backgroundColor: 'hsl(var(--color-card))',
            color: 'hsl(var(--color-card-foreground))',
            boxShadow: 'var(--shadow-md)',
        },
    },
    bordered: {
        className: 'bg-card text-card-foreground border border-border',
        style: {
            backgroundColor: 'hsl(var(--color-card))',
            color: 'hsl(var(--color-card-foreground))',
            border: '1px solid hsl(var(--color-border))',
        },
    },
    flat: {
        className: 'bg-default-50 text-default-900',
        style: {
            backgroundColor: 'hsl(var(--color-default-50))',
            color: 'hsl(var(--color-default-900))',
        },
    },
} as const;

// ============================================================================
// Size Configurations
// ============================================================================

/**
 * Component size configurations
 */
export const SIZE_CONFIGS = {
    sm: {
        padding: 'var(--spacing-sm)',
        fontSize: 'var(--font-size-sm)',
        height: '32px',
        minHeight: '32px',
    },
    md: {
        padding: 'var(--spacing-md)',
        fontSize: 'var(--font-size-base)',
        height: '40px',
        minHeight: '40px',
    },
    lg: {
        padding: 'var(--spacing-lg)',
        fontSize: 'var(--font-size-lg)',
        height: '48px',
        minHeight: '48px',
    },
} as const;

/**
 * Modal size configurations
 */
export const MODAL_SIZES = {
    xs: { width: '320px', maxWidth: '90vw' },
    sm: { width: '400px', maxWidth: '90vw' },
    md: { width: '512px', maxWidth: '90vw' },
    lg: { width: '640px', maxWidth: '90vw' },
    xl: { width: '768px', maxWidth: '90vw' },
    '2xl': { width: '896px', maxWidth: '95vw' },
    '3xl': { width: '1024px', maxWidth: '95vw' },
    '4xl': { width: '1280px', maxWidth: '95vw' },
    '5xl': { width: '1536px', maxWidth: '95vw' },
    full: { width: '100vw', height: '100vh', maxWidth: '100vw', maxHeight: '100vh' },
} as const;

// ============================================================================
// Responsive Breakpoints
// ============================================================================

/**
 * Responsive breakpoints
 */
export const BREAKPOINTS = {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
} as const;

/**
 * Responsive utilities
 */
export const RESPONSIVE_UTILITIES = {
    /**
     * Check if screen size matches breakpoint
     */
    isBreakpoint: (breakpoint: keyof typeof BREAKPOINTS): boolean => {
        if (typeof window === 'undefined') return false;
        return window.matchMedia(`(min-width: ${BREAKPOINTS[breakpoint]})`).matches;
    },

    /**
     * Get current breakpoint
     */
    getCurrentBreakpoint: (): keyof typeof BREAKPOINTS => {
        if (typeof window === 'undefined') return 'md';

        const breakpoints = Object.entries(BREAKPOINTS).reverse();
        for (const [name, size] of breakpoints) {
            if (window.matchMedia(`(min-width: ${size})`).matches) {
                return name as keyof typeof BREAKPOINTS;
            }
        }
        return 'sm';
    },

    /**
     * Create responsive value getter
     */
    getResponsiveValue: <T>(values: Partial<Record<keyof typeof BREAKPOINTS, T>>, fallback: T): T => {
        const currentBreakpoint = RESPONSIVE_UTILITIES.getCurrentBreakpoint();
        const orderedBreakpoints: (keyof typeof BREAKPOINTS)[] = ['2xl', 'xl', 'lg', 'md', 'sm'];

        // Find the first matching value from current breakpoint down
        const currentIndex = orderedBreakpoints.indexOf(currentBreakpoint);
        for (let i = currentIndex; i < orderedBreakpoints.length; i++) {
            const breakpoint = orderedBreakpoints[i];
            if (values[breakpoint] !== undefined) {
                return values[breakpoint]!;
            }
        }

        return fallback;
    },
};

// ============================================================================
// Appearance Manager Class
// ============================================================================

export class AppearanceManager {
    private config: AppearanceConfig;
    private listeners: Set<(config: AppearanceConfig) => void> = new Set();

    constructor(initialConfig?: Partial<AppearanceConfig>) {
        this.config = this.mergeAppearanceConfig(DEFAULT_APPEARANCE_CONFIG, initialConfig);
    }

    /**
     * Get current appearance configuration
     */
    getConfig(): AppearanceConfig {
        return { ...this.config };
    }

    /**
     * Update appearance configuration
     */
    updateConfig(updates: Partial<AppearanceConfig>): void {
        this.config = this.mergeAppearanceConfig(this.config, updates);
        this.notifyListeners();
    }

    /**
     * Apply organization branding
     */
    applyOrganizationBranding(organization: OrganizationConfig): void {
        const branding: BrandingConfig = {
            logo: {
                url: organization.settings.branding?.logo,
                alt: organization.name,
            },
            colors: {
                primary: organization.settings.branding?.primaryColor || this.config.branding.colors.primary,
                secondary: organization.settings.branding?.secondaryColor || this.config.branding.colors.secondary,
            },
            fonts: this.config.branding.fonts,
            customCSS: organization.settings.branding?.customCSS,
        };

        this.updateConfig({ branding });
    }

    /**
     * Get component styles for a specific component
     */
    getComponentStyles(
        componentType: keyof ComponentAppearance,
        variant?: string,
        size?: ComponentSize,
        color?: ColorVariant
    ): {
        className: string;
        style: React.CSSProperties;
    } {
        const componentConfig = this.config.components[componentType];

        // Get base styles
        let styles = this.getBaseComponentStyles(componentType, componentConfig);

        // Apply variant styles
        if (variant) {
            const variantStyles = this.getVariantStyles(componentType, variant);
            styles = this.mergeStyles(styles, variantStyles);
        }

        // Apply size styles
        const actualSize = size || (componentConfig as any)?.size || 'md';
        const sizeStyles = this.getSizeStyles(actualSize);
        styles = this.mergeStyles(styles, sizeStyles);

        // Apply color styles
        if (color) {
            const colorStyles = this.getColorStyles(color);
            styles = this.mergeStyles(styles, colorStyles);
        }

        return styles;
    }

    /**
     * Get layout styles
     */
    getLayoutStyles(): React.CSSProperties {
        return {
            '--container-max-width': this.config.layout.containerMaxWidth,
            '--sidebar-width': this.config.layout.sidebarWidth,
            '--header-height': this.config.layout.headerHeight,
            '--footer-height': this.config.layout.footerHeight,
            '--content-padding': this.config.layout.contentPadding,
        } as React.CSSProperties;
    }

    /**
     * Get branding CSS variables
     */
    getBrandingVariables(): Record<string, string> {
        const { branding } = this.config;
        return {
            '--brand-primary': branding.colors.primary,
            '--brand-secondary': branding.colors.secondary,
            '--brand-accent': branding.colors.accent || branding.colors.primary,
            '--brand-font-primary': branding.fonts.primary,
            '--brand-font-secondary': branding.fonts.secondary || branding.fonts.primary,
        };
    }

    /**
     * Generate complete CSS for appearance
     */
    generateCSS(): string {
        const brandingVars = this.getBrandingVariables();
        const layoutStyles = this.getLayoutStyles();

        let css = ':root {\n';

        // Add branding variables
        Object.entries(brandingVars).forEach(([property, value]) => {
            css += `  ${property}: ${value};\n`;
        });

        // Add layout variables
        Object.entries(layoutStyles).forEach(([property, value]) => {
            css += `  ${property}: ${value};\n`;
        });

        css += '}\n\n';

        // Add custom CSS if provided
        if (this.config.customCSS) {
            css += this.config.customCSS + '\n';
        }

        if (this.config.branding.customCSS) {
            css += this.config.branding.customCSS + '\n';
        }

        return css;
    }

    /**
     * Apply appearance to DOM
     */
    applyToDOM(): void {
        if (typeof document === 'undefined') return;

        // Apply CSS variables
        const brandingVars = this.getBrandingVariables();
        const layoutStyles = this.getLayoutStyles();
        const root = document.documentElement;

        Object.entries({ ...brandingVars, ...layoutStyles }).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });

        // Apply custom CSS if not already applied
        const customCSSId = 'frank-auth-custom-css';
        let styleEl = document.getElementById(customCSSId) as HTMLStyleElement;

        if (!styleEl) {
            styleEl = document.createElement('style');
            styleEl.id = customCSSId;
            document.head.appendChild(styleEl);
        }

        const customCSS = [this.config.customCSS, this.config.branding.customCSS]
            .filter(Boolean)
            .join('\n');

        styleEl.textContent = customCSS;
    }

    /**
     * Subscribe to appearance changes
     */
    subscribe(callback: (config: AppearanceConfig) => void): () => void {
        this.listeners.add(callback);
        return () => {
            this.listeners.delete(callback);
        };
    }

    // Private methods

    private mergeAppearanceConfig(
        base: AppearanceConfig,
        override?: Partial<AppearanceConfig>
    ): AppearanceConfig {
        if (!override) return { ...base };

        return {
            ...base,
            ...override,
            layout: { ...base.layout, ...override.layout },
            components: { ...base.components, ...override.components },
            branding: {
                ...base.branding,
                ...override.branding,
                logo: { ...base.branding.logo, ...override.branding?.logo },
                colors: { ...base.branding.colors, ...override.branding?.colors },
                fonts: { ...base.branding.fonts, ...override.branding?.fonts },
            },
        };
    }

    private getBaseComponentStyles(
        componentType: keyof ComponentAppearance,
        config: any
    ): { className: string; style: React.CSSProperties } {
        return {
            className: `frank-${componentType}`,
            style: {
                borderRadius: `var(--border-radius-${config?.radius || 'md'})`,
                transition: 'all var(--duration-normal) var(--easing-ease-out)',
            },
        };
    }

    private getVariantStyles(
        componentType: keyof ComponentAppearance,
        variant: string
    ): { className: string; style: React.CSSProperties } {
        switch (componentType) {
            case 'input':
                return INPUT_VARIANTS[variant as keyof typeof INPUT_VARIANTS] || INPUT_VARIANTS.bordered;
            case 'button':
                return BUTTON_VARIANTS[variant as keyof typeof BUTTON_VARIANTS] || BUTTON_VARIANTS.solid;
            case 'card':
                return CARD_VARIANTS[variant as keyof typeof CARD_VARIANTS] || CARD_VARIANTS.shadow;
            default:
                return { className: '', style: {} };
        }
    }

    private getSizeStyles(size: ComponentSize): { className: string; style: React.CSSProperties } {
        const sizeConfig = SIZE_CONFIGS[size];
        return {
            className: `frank-size-${size}`,
            style: {
                padding: sizeConfig.padding,
                fontSize: sizeConfig.fontSize,
                minHeight: sizeConfig.minHeight,
            },
        };
    }

    private getColorStyles(color: ColorVariant): { className: string; style: React.CSSProperties } {
        return {
            className: `frank-color-${color}`,
            style: {
                '--component-color': `var(--color-${color})`,
                '--component-color-foreground': `var(--color-${color}-foreground)`,
            } as React.CSSProperties,
        };
    }

    private mergeStyles(
        base: { className: string; style: React.CSSProperties },
        override: { className: string; style: React.CSSProperties }
    ): { className: string; style: React.CSSProperties } {
        return {
            className: [base.className, override.className].filter(Boolean).join(' '),
            style: { ...base.style, ...override.style },
        };
    }

    private notifyListeners(): void {
        this.listeners.forEach(callback => callback(this.config));
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create an appearance manager instance
 */
export function createAppearanceManager(config?: Partial<AppearanceConfig>): AppearanceManager {
    return new AppearanceManager(config);
}

/**
 * Get component class names based on configuration
 */
export function getComponentClassNames(
    componentType: keyof ComponentAppearance,
    config: ComponentAppearance,
    variant?: string,
    size?: ComponentSize,
    color?: ColorVariant,
    additionalClasses?: string[]
): string {
    const classes: string[] = [`frank-${componentType}`];

    // Add variant class
    if (variant) {
        classes.push(`frank-${componentType}-${variant}`);
    }

    // Add size class
    const actualSize = size || (config[componentType] as any)?.size || 'md';
    classes.push(`frank-size-${actualSize}`);

    // Add color class
    if (color) {
        classes.push(`frank-color-${color}`);
    }

    // Add additional classes
    if (additionalClasses) {
        classes.push(...additionalClasses);
    }

    return classes.join(' ');
}

/**
 * Convert appearance config to Tailwind classes
 */
export function appearanceConfigToTailwind(config: ComponentAppearance): Record<string, string> {
    const tailwindClasses: Record<string, string> = {};

    // Convert input config
    if (config.input) {
        const { variant, size, color, radius } = config.input;
        const classes = ['transition-all', 'duration-200'];

        // Variant classes
        switch (variant) {
            case 'flat':
                classes.push('bg-default-100', 'hover:bg-default-200', 'focus:bg-default-100');
                break;
            case 'bordered':
                classes.push('border-2', 'border-default-200', 'hover:border-default-300', 'focus:border-primary');
                break;
            case 'underlined':
                classes.push('border-b-2', 'border-default-300', 'hover:border-default-400', 'focus:border-primary');
                break;
            case 'faded':
                classes.push('bg-default-50', 'border', 'border-default-200', 'hover:bg-default-100');
                break;
        }

        // Size classes
        switch (size) {
            case 'sm':
                classes.push('px-2', 'py-1', 'text-sm', 'h-8');
                break;
            case 'md':
                classes.push('px-3', 'py-2', 'text-base', 'h-10');
                break;
            case 'lg':
                classes.push('px-4', 'py-3', 'text-lg', 'h-12');
                break;
        }

        // Radius classes
        if (radius === 'none') classes.push('rounded-none');
        else if (radius === 'sm') classes.push('rounded-sm');
        else if (radius === 'md') classes.push('rounded-md');
        else if (radius === 'lg') classes.push('rounded-lg');
        else if (radius === 'xl') classes.push('rounded-xl');
        else if (radius === 'full') classes.push('rounded-full');

        tailwindClasses.input = classes.join(' ');
    }

    return tailwindClasses;
}

/**
 * Create responsive component props
 */
export function createResponsiveProps<T>(
    values: Partial<Record<keyof typeof BREAKPOINTS, T>>,
    fallback: T
): T {
    return RESPONSIVE_UTILITIES.getResponsiveValue(values, fallback);
}

// ============================================================================
// Export appearance utilities
// ============================================================================

export {
    DEFAULT_APPEARANCE_CONFIG,
    DEFAULT_COMPONENT_APPEARANCE,
    DEFAULT_LAYOUT_CONFIG,
    DEFAULT_BRANDING_CONFIG,
};