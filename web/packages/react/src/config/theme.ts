/**
 * @frank-auth/react - Theme Configuration
 *
 * Advanced theme management system with support for light/dark modes,
 * custom color palettes, and HeroUI integration.
 */

import {BrandingConfig, Theme, ThemeMode, ThemeUtils,} from './types';

import {DEFAULT_COLOR_PALETTE, DEFAULT_THEME_CONFIG,} from './defaults';
import {generateColorPalette} from '../utils';
import {ThemeColors} from '../types';

// ============================================================================
// Theme Utilities
// ============================================================================

/**
 * Creates a dark theme variant from a light theme
 */
export function createDarkTheme(lightTheme: Theme): Theme {
    const darkColors: ThemeColors = {
        ...lightTheme.colors,
        // Invert background colors
        background: '#0f172a',
        foreground: '#f8fafc',
        card: '#1e293b',
        cardForeground: '#f8fafc',
        popover: '#1e293b',
        popoverForeground: '#f8fafc',
        muted: '#334155',
        mutedForeground: '#94a3b8',
        accent: '#334155',
        accentForeground: '#f8fafc',
        border: '#334155',
        input: '#334155',
        ring: lightTheme.palette.primary.DEFAULT,
    };

    return {
        ...lightTheme,
        mode: 'dark',
        colors: darkColors,
        palette: {
            ...lightTheme.palette,

            // Adjust primary colors for dark mode
            primary: {
                ...lightTheme.palette.primary,
                DEFAULT: lightTheme.colors.primary[400],
                foreground: '#000000',
            },

            // Adjust secondary colors for dark mode
            secondary: {
                ...lightTheme.palette.secondary,
                DEFAULT: lightTheme.colors.secondary[400],
                foreground: '#000000',
            },
        }
    };
}

// ============================================================================
// Predefined Themes
// ============================================================================

/**
 * Blue theme (default)
 */
export const BLUE_THEME: Theme = {
    ...DEFAULT_THEME_CONFIG,
    colors: {
        ...DEFAULT_THEME_CONFIG.colors,
        primary: generateColorPalette('#3b82f6'),
    },
    palette: {
        ...DEFAULT_COLOR_PALETTE,
        primary: generateColorPalette('#3b82f6'),
    },
};

/**
 * Purple theme
 */
export const PURPLE_THEME: Theme = {
    ...DEFAULT_THEME_CONFIG,
    colors: {
        ...DEFAULT_THEME_CONFIG.colors,
        primary: generateColorPalette('#8b5cf6'),
        secondary: generateColorPalette('#6366f1'),
    },
    palette: {
        ...DEFAULT_COLOR_PALETTE,
        primary: generateColorPalette('#8b5cf6'),
        secondary: generateColorPalette('#6366f1'),
    },
};

/**
 * Green theme
 */
export const GREEN_THEME: Theme = {
    ...DEFAULT_THEME_CONFIG,
    colors: {
        ...DEFAULT_THEME_CONFIG.colors,
        primary: generateColorPalette('#10b981'),
        secondary: generateColorPalette('#059669'),
    },
    palette: {
        ...DEFAULT_COLOR_PALETTE,
        primary: generateColorPalette('#10b981'),
        secondary: generateColorPalette('#059669'),
    },
};

/**
 * Orange theme
 */
export const ORANGE_THEME: Theme = {
    ...DEFAULT_THEME_CONFIG,
    colors: {
        ...DEFAULT_THEME_CONFIG.colors,
        primary: generateColorPalette('#f97316').DEFAULT,
        secondary: generateColorPalette('#ea580c').DEFAULT,
    },
    palette: {
        ...DEFAULT_COLOR_PALETTE,
        primary: generateColorPalette('#f97316'),
        secondary: generateColorPalette('#ea580c'),
    },
};

/**
 * Pink theme
 */
export const PINK_THEME: Theme = {
    ...DEFAULT_THEME_CONFIG,
    colors: {
        ...DEFAULT_THEME_CONFIG.colors,
        primary: generateColorPalette('#ec4899').DEFAULT,
        secondary: generateColorPalette('#db2777').DEFAULT,
    },
    palette: {
        ...DEFAULT_COLOR_PALETTE,
        primary: generateColorPalette('#ec4899'),
        secondary: generateColorPalette('#db2777'),
    },
};

/**
 * Available theme presets
 */
export const THEME_PRESETS = {
    blue: BLUE_THEME,
    purple: PURPLE_THEME,
    green: GREEN_THEME,
    orange: ORANGE_THEME,
    pink: PINK_THEME,
} as const;

export type ThemePreset = keyof typeof THEME_PRESETS;

// ============================================================================
// Theme Manager Class
// ============================================================================

export class ThemeManager {
    private currentTheme: Theme;
    private systemPreference: ThemeMode;
    private listeners: Set<(theme: Theme) => void> = new Set();

    constructor(initialTheme?: Partial<Theme>) {
        this.currentTheme = this.mergeTheme(DEFAULT_THEME_CONFIG, initialTheme);
        this.systemPreference = this.detectSystemPreference();

        // Listen for system theme changes
        if (typeof window !== 'undefined') {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', () => {
                this.systemPreference = this.detectSystemPreference();
                this.updateTheme();
            });
        }
    }

    /**
     * Get current theme
     */
    getTheme(): Theme {
        return { ...this.currentTheme };
    }

    /**
     * Set theme configuration
     */
    setTheme(theme: Partial<Theme>): void {
        this.currentTheme = this.mergeTheme(this.currentTheme, theme);
        this.updateTheme();
    }

    /**
     * Apply a theme preset
     */
    applyPreset(preset: ThemePreset): void {
        this.currentTheme = { ...THEME_PRESETS[preset] };
        this.updateTheme();
    }

    /**
     * Set theme mode
     */
    setMode(mode: ThemeMode): void {
        this.currentTheme.mode = mode;
        this.updateTheme();
    }

    /**
     * Get effective theme mode (resolves 'system' to 'light' or 'dark')
     */
    getEffectiveMode(): 'light' | 'dark' {
        if (this.currentTheme.mode === 'system') {
            return this.systemPreference === 'dark' ? 'dark' : 'light';
        }
        return this.currentTheme.mode === 'dark' ? 'dark' : 'light';
    }

    /**
     * Apply branding colors to theme
     */
    applyBranding(branding: BrandingConfig): void {
        if (branding.colors?.primary) {
            this.currentTheme.palette.primary = generateColorPalette(branding.colors.primary);
        }

        if (branding.colors?.secondary) {
            this.currentTheme.palette.secondary = generateColorPalette(branding.colors.secondary);
        }

        if (branding.fonts?.primary) {
            this.currentTheme.typography.fontFamily.sans = [
                branding.fonts.primary,
                ...this.currentTheme.typography.fontFamily.sans,
            ];
        }

        this.updateTheme();
    }

    /**
     * Generate CSS variables for the current theme
     */
    generateCSSVariables(): Record<string, string> {
        const theme = this.getResolvedTheme();
        return ThemeUtils.generateCSSVariables(theme);
    }

    /**
     * Apply theme to DOM
     */
    applyToDOM(): void {
        if (typeof document === 'undefined') return;

        const variables = this.generateCSSVariables();
        const root = document.documentElement;

        // Apply CSS variables
        Object.entries(variables).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });

        // Apply theme class
        const effectiveMode = this.getEffectiveMode();
        root.classList.remove('light', 'dark');
        root.classList.add(effectiveMode);
    }

    /**
     * Subscribe to theme changes
     */
    subscribe(callback: (theme: Theme) => void): () => void {
        this.listeners.add(callback);
        return () => {
            this.listeners.delete(callback);
        };
    }

    // Private methods

    private detectSystemPreference(): ThemeMode {
        if (typeof window === 'undefined') return 'light';
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    private mergeTheme(base: Theme, override?: Partial<Theme>): Theme {
        if (!override) return { ...base };

        return {
            ...base,
            ...override,
            colors: { ...base.colors, ...override.colors },
            typography: {
                ...base.typography,
                ...override.typography,
                fontFamily: { ...base.typography.fontFamily, ...override.typography?.fontFamily },
                fontSize: { ...base.typography.fontSize, ...override.typography?.fontSize },
                fontWeight: { ...base.typography.fontWeight, ...override.typography?.fontWeight },
            },
            spacing: { ...base.spacing, ...override.spacing },
            borderRadius: { ...base.borderRadius, ...override.borderRadius },
            shadows: { ...base.shadows, ...override.shadows },
            animations: {
                ...base.animations,
                ...override.animations,
                duration: { ...base.animations.duration, ...override.animations?.duration },
                timingFunction: { ...base.animations.timingFunction, ...override.animations?.timingFunction },
                keyframes: { ...base.animations.keyframes, ...override.animations?.keyframes },
            },
        };
    }

    private getResolvedTheme(): Theme {
        const effectiveMode = this.getEffectiveMode();

        if (effectiveMode === 'dark' && this.currentTheme.mode !== 'dark') {
            return createDarkTheme(this.currentTheme);
        }

        return this.currentTheme;
    }

    private updateTheme(): void {
        this.applyToDOM();
        this.listeners.forEach(callback => callback(this.currentTheme));
    }
}

// ============================================================================
// Theme Hooks and Utilities
// ============================================================================

/**
 * Create a theme manager instance
 */
export function createThemeManager(initialTheme?: Partial<Theme>): ThemeManager {
    return new ThemeManager(initialTheme);
}

/**
 * Get theme CSS for server-side rendering
 */
export function getThemeCSS(theme: Theme): string {
    const manager = new ThemeManager(theme);
    const variables = manager.generateCSSVariables();

    return `:root {
    ${Object.entries(variables)
        .map(([property, value]) => `${property}: ${value};`)
        .join('\n    ')}
  }`;
}

/**
 * Validate theme configuration
 */
export function validateTheme(theme: Partial<Theme>): boolean {
    try {
        // Basic validation - ensure required color properties exist
        if (theme.colors) {
            const requiredColors = ['primary', 'secondary', 'background', 'foreground'];
            for (const color of requiredColors) {
                if (!(color in theme.colors)) {
                    return false;
                }
            }
        }

        // Validate typography if provided
        if (theme.typography) {
            if (theme.typography.fontFamily && !Array.isArray(theme.typography.fontFamily.sans)) {
                return false;
            }
        }

        return true;
    } catch {
        return false;
    }
}

// ============================================================================
// Export theme utilities
// ============================================================================

export {
    DEFAULT_THEME_CONFIG,
};