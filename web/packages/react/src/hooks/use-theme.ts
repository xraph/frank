/**
 * @frank-auth/react - useTheme Hook
 *
 * Enhanced theme hook that provides comprehensive theme management,
 * organization branding, and CSS customization capabilities.
 */

import {useCallback, useMemo} from 'react';

import type {Organization} from '@frank-auth/client';
import type {Theme} from '../config';

import {useTheme as useThemeProvider} from '../provider/theme-provider';
import {useAuth} from './use-auth';

import type {OrganizationBranding} from '../provider/types';

// ============================================================================
// Theme Hook Interface
// ============================================================================

export interface UseThemeReturn {
    // Theme state
    theme: Theme;
    mode: 'light' | 'dark' | 'system';
    effectiveMode: 'light' | 'dark';
    isSystemMode: boolean;
    isCustomized: boolean;

    // CSS variables and styling
    cssVariables: Record<string, string>;
    generateCSS: () => string;

    // Theme management
    setTheme: (theme: Partial<Theme>) => void;
    setMode: (mode: 'light' | 'dark' | 'system') => void;
    resetTheme: () => void;

    // Organization branding
    organizationBranding?: OrganizationBranding;
    applyBranding: (branding: OrganizationBranding) => void;
    applyOrganizationBranding: (organization: Organization) => void;
    isCustomBranded: boolean;

    // Color management
    colors: Theme['colors'];
    primaryColor: string;
    secondaryColor: string;
    backgroundColor: string;
    foregroundColor: string;

    // Typography
    typography: Theme['typography'];
    fontFamily: string[];

    // Spacing and layout
    spacing: Theme['spacing'];
    borderRadius: Theme['borderRadius'];
    shadows: Theme['shadows'];

    // Utilities
    getColorValue: (colorName: string, shade?: string) => string;
    getFontSize: (size: string) => string;
    getSpacing: (size: string) => string;
    getBorderRadius: (size: string) => string;
    getShadow: (size: string) => string;

    // Mode switching
    toggleMode: () => void;
    setLightMode: () => void;
    setDarkMode: () => void;
    setSystemMode: () => void;

    // Theme presets
    applyPreset: (preset: ThemePreset) => void;
    availablePresets: ThemePreset[];
}

export type ThemePreset = 'blue' | 'purple' | 'green' | 'orange' | 'pink' | 'red' | 'gray';

// ============================================================================
// Theme Presets
// ============================================================================

const THEME_PRESETS: Record<ThemePreset, Partial<Theme>> = {
    blue: {
        colors: {
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
        },
    },
    purple: {
        colors: {
            primary: {
                50: '#faf5ff',
                100: '#f3e8ff',
                200: '#e9d5ff',
                300: '#d8b4fe',
                400: '#c084fc',
                500: '#a855f7',
                600: '#9333ea',
                700: '#7c3aed',
                800: '#6b21a8',
                900: '#581c87',
                950: '#3b0764',
                DEFAULT: '#a855f7',
                foreground: '#ffffff',
            },
        },
    },
    green: {
        colors: {
            primary: {
                50: '#f0fdf4',
                100: '#dcfce7',
                200: '#bbf7d0',
                300: '#86efac',
                400: '#4ade80',
                500: '#22c55e',
                600: '#16a34a',
                700: '#15803d',
                800: '#166534',
                900: '#14532d',
                950: '#052e16',
                DEFAULT: '#22c55e',
                foreground: '#ffffff',
            },
        },
    },
    orange: {
        colors: {
            primary: {
                50: '#fff7ed',
                100: '#ffedd5',
                200: '#fed7aa',
                300: '#fdba74',
                400: '#fb923c',
                500: '#f97316',
                600: '#ea580c',
                700: '#c2410c',
                800: '#9a3412',
                900: '#7c2d12',
                950: '#431407',
                DEFAULT: '#f97316',
                foreground: '#ffffff',
            },
        },
    },
    pink: {
        colors: {
            primary: {
                50: '#fdf2f8',
                100: '#fce7f3',
                200: '#fbcfe8',
                300: '#f9a8d4',
                400: '#f472b6',
                500: '#ec4899',
                600: '#db2777',
                700: '#be185d',
                800: '#9d174d',
                900: '#831843',
                950: '#500724',
                DEFAULT: '#ec4899',
                foreground: '#ffffff',
            },
        },
    },
    red: {
        colors: {
            primary: {
                50: '#fef2f2',
                100: '#fee2e2',
                200: '#fecaca',
                300: '#fca5a5',
                400: '#f87171',
                500: '#ef4444',
                600: '#dc2626',
                700: '#b91c1c',
                800: '#991b1b',
                900: '#7f1d1d',
                950: '#450a0a',
                DEFAULT: '#ef4444',
                foreground: '#ffffff',
            },
        },
    },
    gray: {
        colors: {
            primary: {
                50: '#f9fafb',
                100: '#f3f4f6',
                200: '#e5e7eb',
                300: '#d1d5db',
                400: '#9ca3af',
                500: '#6b7280',
                600: '#4b5563',
                700: '#374151',
                800: '#1f2937',
                900: '#111827',
                950: '#030712',
                DEFAULT: '#6b7280',
                foreground: '#ffffff',
            },
        },
    },
};

// ============================================================================
// Main useTheme Hook
// ============================================================================

/**
 * Enhanced theme hook providing comprehensive theme management capabilities
 *
 * @example Basic theme usage
 * ```tsx
 * import { useTheme } from '@frank-auth/react';
 *
 * function ThemeManager() {
 *   const {
 *     mode,
 *     effectiveMode,
 *     toggleMode,
 *     primaryColor,
 *     setLightMode,
 *     setDarkMode,
 *     applyPreset
 *   } = useTheme();
 *
 *   return (
 *     <div>
 *       <p>Current mode: {mode} (effective: {effectiveMode})</p>
 *       <p>Primary color: {primaryColor}</p>
 *
 *       <button onClick={toggleMode}>Toggle Mode</button>
 *       <button onClick={setLightMode}>Light Mode</button>
 *       <button onClick={setDarkMode}>Dark Mode</button>
 *
 *       <select onChange={(e) => applyPreset(e.target.value as any)}>
 *         <option value="blue">Blue</option>
 *         <option value="purple">Purple</option>
 *         <option value="green">Green</option>
 *       </select>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Organization branding
 * ```tsx
 * function BrandedTheme() {
 *   const { applyOrganizationBranding, isCustomBranded } = useTheme();
 *   const { activeOrganization } = useAuth();
 *
 *   useEffect(() => {
 *     if (activeOrganization) {
 *       applyOrganizationBranding(activeOrganization);
 *     }
 *   }, [activeOrganization, applyOrganizationBranding]);
 *
 *   return (
 *     <div>
 *       {isCustomBranded ? (
 *         <p>Custom organization branding applied</p>
 *       ) : (
 *         <p>Using default theme</p>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example CSS utilities
 * ```tsx
 * function StyledComponent() {
 *   const {
 *     getColorValue,
 *     getFontSize,
 *     getSpacing,
 *     cssVariables
 *   } = useTheme();
 *
 *   const customStyles = {
 *     backgroundColor: getColorValue('primary', '100'),
 *     fontSize: getFontSize('lg'),
 *     padding: getSpacing('md'),
 *   };
 *
 *   return (
 *     <div style={customStyles}>
 *       <p>Themed component with utility functions</p>
 *       <p>CSS Variables available: {Object.keys(cssVariables).length}</p>
 *     </div>
 *   );
 * }
 * ```
 */
export function useTheme(): UseThemeReturn {
    const themeProvider = useThemeProvider();
    const { activeOrganization } = useAuth();

    // Enhanced mode switching
    const toggleMode = useCallback(() => {
        if (themeProvider.mode === 'light') {
            themeProvider.setMode('dark');
        } else if (themeProvider.mode === 'dark') {
            themeProvider.setMode('system');
        } else {
            themeProvider.setMode('light');
        }
    }, [themeProvider]);

    const setLightMode = useCallback(() => themeProvider.setMode('light'), [themeProvider]);
    const setDarkMode = useCallback(() => themeProvider.setMode('dark'), [themeProvider]);
    const setSystemMode = useCallback(() => themeProvider.setMode('system'), [themeProvider]);

    // Color utilities
    const colors = useMemo(() => themeProvider.theme.colors, [themeProvider.theme.colors]);
    const primaryColor = useMemo(() => colors.primary.DEFAULT, [colors.primary]);
    const secondaryColor = useMemo(() => colors.secondary.DEFAULT, [colors.secondary]);
    const backgroundColor = useMemo(() => colors.background, [colors.background]);
    const foregroundColor = useMemo(() => colors.foreground, [colors.foreground]);

    // Typography utilities
    const typography = useMemo(() => themeProvider.theme.typography, [themeProvider.theme.typography]);
    const fontFamily = useMemo(() => typography.fontFamily.sans, [typography.fontFamily.sans]);

    // Layout utilities
    const spacing = useMemo(() => themeProvider.theme.spacing, [themeProvider.theme.spacing]);
    const borderRadius = useMemo(() => themeProvider.theme.borderRadius, [themeProvider.theme.borderRadius]);
    const shadows = useMemo(() => themeProvider.theme.shadows, [themeProvider.theme.shadows]);

    // Utility functions
    const getColorValue = useCallback((colorName: string, shade?: string): string => {
        const colorObj = (colors as any)[colorName];
        if (!colorObj) return '';

        if (shade && typeof colorObj === 'object') {
            return colorObj[shade] || colorObj.DEFAULT || '';
        }

        return typeof colorObj === 'string' ? colorObj : colorObj.DEFAULT || '';
    }, [colors]);

    const getFontSize = useCallback((size: string): string => {
        const fontSize = (typography.fontSize as any)[size];
        if (Array.isArray(fontSize)) {
            return fontSize[0];
        }
        return fontSize || '';
    }, [typography.fontSize]);

    const getSpacing = useCallback((size: string): string => {
        return (spacing as any)[size] || '';
    }, [spacing]);

    const getBorderRadius = useCallback((size: string): string => {
        return (borderRadius as any)[size] || '';
    }, [borderRadius]);

    const getShadow = useCallback((size: string): string => {
        return (shadows as any)[size] || '';
    }, [shadows]);

    // Theme presets
    const applyPreset = useCallback((preset: ThemePreset) => {
        const presetTheme = THEME_PRESETS[preset];
        if (presetTheme) {
            themeProvider.setTheme(presetTheme);
        }
    }, [themeProvider]);

    const availablePresets = useMemo(() => Object.keys(THEME_PRESETS) as ThemePreset[], []);

    // Organization branding
    const applyOrganizationBranding = useCallback((organization: Organization) => {
        if (organization.settings?.branding) {
            const branding: OrganizationBranding = {
                primaryColor: organization.settings.branding.primaryColor,
                secondaryColor: organization.settings.branding.secondaryColor,
                logo: organization.logoUrl,
                favicon: organization.settings.branding.favicon,
                customCSS: organization.settings.branding.customCSS,
            };

            themeProvider.applyBranding(branding);
        }
    }, [themeProvider]);

    const isCustomBranded = useMemo(() => {
        return !!(themeProvider.organizationBranding?.primaryColor ||
            themeProvider.organizationBranding?.logo ||
            themeProvider.organizationBranding?.customCSS);
    }, [themeProvider.organizationBranding]);

    return {
        // Theme state
        theme: themeProvider.theme,
        mode: themeProvider.mode,
        effectiveMode: themeProvider.effectiveMode,
        isSystemMode: themeProvider.isSystemMode,
        isCustomized: themeProvider.isCustomized,

        // CSS variables and styling
        cssVariables: themeProvider.cssVariables,
        generateCSS: themeProvider.generateCSS,

        // Theme management
        setTheme: themeProvider.setTheme,
        setMode: themeProvider.setMode,
        resetTheme: themeProvider.resetTheme,

        // Organization branding
        organizationBranding: themeProvider.organizationBranding,
        applyBranding: themeProvider.applyBranding,
        applyOrganizationBranding,
        isCustomBranded,

        // Color management
        colors,
        primaryColor,
        secondaryColor,
        backgroundColor,
        foregroundColor,

        // Typography
        typography,
        fontFamily,

        // Spacing and layout
        spacing,
        borderRadius,
        shadows,

        // Utilities
        getColorValue,
        getFontSize,
        getSpacing,
        getBorderRadius,
        getShadow,

        // Mode switching
        toggleMode,
        setLightMode,
        setDarkMode,
        setSystemMode,

        // Theme presets
        applyPreset,
        availablePresets,
    };
}

// ============================================================================
// Specialized Theme Hooks
// ============================================================================

/**
 * Hook for color management and utilities
 */
export function useThemeColors() {
    const {
        colors,
        primaryColor,
        secondaryColor,
        backgroundColor,
        foregroundColor,
        getColorValue,
        setTheme,
        theme,
    } = useTheme();

    const setPrimaryColor = useCallback((color: string) => {
        setTheme({
            colors: {
                ...theme.colors,
                primary: {
                    ...theme.colors.primary,
                    DEFAULT: color,
                },
            },
        });
    }, [setTheme, theme.colors]);

    const setSecondaryColor = useCallback((color: string) => {
        setTheme({
            colors: {
                ...theme.colors,
                secondary: {
                    ...theme.colors.secondary,
                    DEFAULT: color,
                },
            },
        });
    }, [setTheme, theme.colors]);

    return {
        colors,
        primaryColor,
        secondaryColor,
        backgroundColor,
        foregroundColor,
        getColorValue,
        setPrimaryColor,
        setSecondaryColor,

        // Color palette helpers
        getPrimaryShade: (shade: string) => getColorValue('primary', shade),
        getSecondaryShade: (shade: string) => getColorValue('secondary', shade),
        getSuccessColor: () => getColorValue('success'),
        getWarningColor: () => getColorValue('warning'),
        getDangerColor: () => getColorValue('danger'),
        getInfoColor: () => getColorValue('info'),
    };
}

/**
 * Hook for typography management
 */
export function useThemeTypography() {
    const {
        typography,
        fontFamily,
        getFontSize,
        setTheme,
        theme,
    } = useTheme();

    const setFontFamily = useCallback((fonts: string[]) => {
        setTheme({
            typography: {
                ...theme.typography,
                fontFamily: {
                    ...theme.typography.fontFamily,
                    sans: fonts,
                },
            },
        });
    }, [setTheme, theme.typography]);

    return {
        typography,
        fontFamily,
        getFontSize,
        setFontFamily,

        // Typography helpers
        fontSizes: typography.fontSize,
        fontWeights: typography.fontWeight,
        lineHeights: typography.lineHeight,
        letterSpacing: typography.letterSpacing,

        // Quick size getters
        getSmallSize: () => getFontSize('sm'),
        getBaseSize: () => getFontSize('base'),
        getLargeSize: () => getFontSize('lg'),
        getXLSize: () => getFontSize('xl'),
    };
}

/**
 * Hook for spacing and layout utilities
 */
export function useThemeLayout() {
    const {
        spacing,
        borderRadius,
        shadows,
        getSpacing,
        getBorderRadius,
        getShadow,
    } = useTheme();

    return {
        spacing,
        borderRadius,
        shadows,
        getSpacing,
        getBorderRadius,
        getShadow,

        // Spacing helpers
        getSmallSpacing: () => getSpacing('sm'),
        getMediumSpacing: () => getSpacing('md'),
        getLargeSpacing: () => getSpacing('lg'),

        // Border radius helpers
        getSmallRadius: () => getBorderRadius('sm'),
        getMediumRadius: () => getBorderRadius('md'),
        getLargeRadius: () => getBorderRadius('lg'),
        getFullRadius: () => getBorderRadius('full'),

        // Shadow helpers
        getSmallShadow: () => getShadow('sm'),
        getMediumShadow: () => getShadow('md'),
        getLargeShadow: () => getShadow('lg'),
    };
}

/**
 * Hook for CSS-in-JS styling with theme values
 */
export function useThemeStyles() {
    const {
        cssVariables,
        generateCSS,
        getColorValue,
        getFontSize,
        getSpacing,
        getBorderRadius,
        getShadow,
    } = useTheme();

    const createStyles = useCallback((stylesFn: (theme: any) => any) => {
        return stylesFn({
            colors: { get: getColorValue },
            fontSize: { get: getFontSize },
            spacing: { get: getSpacing },
            borderRadius: { get: getBorderRadius },
            shadows: { get: getShadow },
        });
    }, [getColorValue, getFontSize, getSpacing, getBorderRadius, getShadow]);

    const getThemeValue = useCallback((path: string) => {
        return cssVariables[`--${path.replace('.', '-')}`] || '';
    }, [cssVariables]);

    return {
        cssVariables,
        generateCSS,
        createStyles,
        getThemeValue,

        // Pre-built common styles
        cardStyles: {
            backgroundColor: getColorValue('card'),
            color: getColorValue('cardForeground'),
            borderRadius: getBorderRadius('lg'),
            boxShadow: getShadow('md'),
            padding: getSpacing('lg'),
        },
        buttonStyles: {
            backgroundColor: getColorValue('primary'),
            color: getColorValue('primaryForeground'),
            borderRadius: getBorderRadius('md'),
            padding: `${getSpacing('sm')} ${getSpacing('md')}`,
            fontSize: getFontSize('base'),
            fontWeight: '500',
            border: 'none',
            cursor: 'pointer',
        },
        inputStyles: {
            backgroundColor: getColorValue('input'),
            color: getColorValue('foreground'),
            border: `1px solid ${getColorValue('border')}`,
            borderRadius: getBorderRadius('md'),
            padding: getSpacing('sm'),
            fontSize: getFontSize('base'),
        },
    };
}