/**
 * @frank-auth/react - Theme Provider
 *
 * Theme provider that manages theme state, mode switching, organization branding,
 * and CSS variable generation for the authentication components.
 */

'use client';

import React, {createContext, useCallback, useContext, useEffect, useMemo, useReducer} from 'react';

import type {Organization} from '@frank-auth/client';

import type {Theme} from '../config';
import {createThemeManager, defaultTheme} from '../config';

import type {OrganizationBranding, ThemeContextValue, ThemeProviderProps, ThemeState,} from './types';

// ============================================================================
// Theme Context
// ============================================================================

const ThemeContext = createContext<ThemeContextValue | null>(null);

// ============================================================================
// Theme Reducer
// ============================================================================

type ThemeAction =
    | { type: 'SET_THEME'; payload: Theme }
    | { type: 'SET_MODE'; payload: 'light' | 'dark' | 'system' }
    | { type: 'SET_EFFECTIVE_MODE'; payload: 'light' | 'dark' }
    | { type: 'SET_SYSTEM_MODE'; payload: boolean }
    | { type: 'SET_CSS_VARIABLES'; payload: Record<string, string> }
    | { type: 'SET_CUSTOMIZED'; payload: boolean }
    | { type: 'SET_ORGANIZATION_BRANDING'; payload: OrganizationBranding | undefined }
    | { type: 'RESET_THEME' };

function themeReducer(state: ThemeState, action: ThemeAction): ThemeState {
    switch (action.type) {
        case 'SET_THEME':
            return {
                ...state,
                theme: action.payload,
                isCustomized: true,
            };

        case 'SET_MODE':
            return {
                ...state,
                mode: action.payload,
                isSystemMode: action.payload === 'system',
            };

        case 'SET_EFFECTIVE_MODE':
            return {
                ...state,
                effectiveMode: action.payload,
            };

        case 'SET_SYSTEM_MODE':
            return {
                ...state,
                isSystemMode: action.payload,
            };

        case 'SET_CSS_VARIABLES':
            return {
                ...state,
                cssVariables: action.payload,
            };

        case 'SET_CUSTOMIZED':
            return {
                ...state,
                isCustomized: action.payload,
            };

        case 'SET_ORGANIZATION_BRANDING':
            return {
                ...state,
                organizationBranding: action.payload,
                isCustomized: !!action.payload,
            };

        case 'RESET_THEME':
            return {
                ...initialThemeState,
            };

        default:
            return state;
    }
}

// ============================================================================
// Initial State
// ============================================================================

const initialThemeState: ThemeState = {
    theme: defaultTheme,
    mode: 'system',
    effectiveMode: 'light',
    isSystemMode: true,
    cssVariables: {},
    isCustomized: false,
};

// ============================================================================
// Theme Provider Component
// ============================================================================

export function ThemeProvider({
                                  children,
                                  theme: initialTheme,
                                  mode: initialMode = 'system',
                                  organizationBranding,
                                  onThemeChange,
                              }: ThemeProviderProps) {
    const [state, dispatch] = useReducer(themeReducer, {
        ...initialThemeState,
        theme: initialTheme ? { ...defaultTheme, ...initialTheme } : defaultTheme,
        mode: initialMode,
        isSystemMode: initialMode === 'system',
    });

    // Initialize theme manager
    const themeManager = useMemo(() => {
        return createThemeManager(state.theme);
    }, []);

    // Detect system preference
    const detectSystemPreference = useCallback((): 'light' | 'dark' => {
        if (typeof window === 'undefined') return 'light';
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }, []);

    // Update effective mode based on current mode and system preference
    const updateEffectiveMode = useCallback(() => {
        let effectiveMode: 'light' | 'dark';

        if (state.mode === 'system') {
            effectiveMode = detectSystemPreference();
        } else {
            effectiveMode = state.mode;
        }

        if (effectiveMode !== state.effectiveMode) {
            dispatch({ type: 'SET_EFFECTIVE_MODE', payload: effectiveMode });
        }
    }, [state.mode, state.effectiveMode, detectSystemPreference]);

    // Listen for system theme changes
    useEffect(() => {
        if (typeof window === 'undefined') return;

        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        const handleChange = () => {
            if (state.mode === 'system') {
                updateEffectiveMode();
            }
        };

        mediaQuery.addEventListener('change', handleChange);

        // Initial check
        updateEffectiveMode();

        return () => {
            mediaQuery.removeEventListener('change', handleChange);
        };
    }, [state.mode, updateEffectiveMode]);

    // Update theme manager when theme changes
    useEffect(() => {
        themeManager.setTheme(state.theme);
        themeManager.setMode(state.effectiveMode);

        // Generate CSS variables
        const cssVariables = themeManager.generateCSSVariables();
        dispatch({ type: 'SET_CSS_VARIABLES', payload: cssVariables });

        // Notify parent component
        onThemeChange?.(state.theme);
    }, [themeManager, state.theme, state.effectiveMode, onThemeChange]);

    // Apply organization branding on initialization
    useEffect(() => {
        if (organizationBranding) {
            dispatch({ type: 'SET_ORGANIZATION_BRANDING', payload: organizationBranding });
            themeManager.applyBranding({
                logo: {
                    url: organizationBranding.logo,
                    alt: 'Organization Logo',
                },
                colors: {
                    primary: organizationBranding.primaryColor || '#3b82f6',
                    secondary: organizationBranding.secondaryColor || '#64748b',
                },
                fonts: {
                    primary: organizationBranding.fonts?.primary || 'Inter, ui-sans-serif, system-ui, sans-serif',
                    secondary: organizationBranding.fonts?.secondary,
                },
                customCSS: organizationBranding.customCSS,
            });
        }
    }, [organizationBranding, themeManager]);

    // Apply theme to DOM
    useEffect(() => {
        if (typeof document === 'undefined') return;

        // Apply CSS variables to root element
        const root = document.documentElement;
        Object.entries(state.cssVariables).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });

        // Apply theme mode class
        root.classList.remove('light', 'dark');
        root.classList.add(state.effectiveMode);

        // Apply data attributes for CSS selectors
        root.setAttribute('data-theme', state.effectiveMode);
        root.setAttribute('data-theme-mode', state.mode);
        root.setAttribute('data-theme-customized', state.isCustomized.toString());
    }, [state.cssVariables, state.effectiveMode, state.mode, state.isCustomized]);

    // Set theme method
    const setTheme = useCallback((theme: Partial<Theme>) => {
        const newTheme = { ...state.theme, ...theme };
        dispatch({ type: 'SET_THEME', payload: newTheme });
    }, [state.theme]);

    // Set mode method
    const setMode = useCallback((mode: 'light' | 'dark' | 'system') => {
        dispatch({ type: 'SET_MODE', payload: mode });

        // Immediately update effective mode if not system
        if (mode !== 'system') {
            dispatch({ type: 'SET_EFFECTIVE_MODE', payload: mode });
        } else {
            // Use current system preference
            const systemPreference = detectSystemPreference();
            dispatch({ type: 'SET_EFFECTIVE_MODE', payload: systemPreference });
        }
    }, [detectSystemPreference]);

    // Apply branding method
    const applyBranding = useCallback((branding: OrganizationBranding) => {
        dispatch({ type: 'SET_ORGANIZATION_BRANDING', payload: branding });

        // Apply branding to theme manager
        themeManager.applyBranding({
            logo: {
                url: branding.logo,
                alt: 'Organization Logo',
            },
            colors: {
                primary: branding.primaryColor || state.theme.colors.primary.DEFAULT,
                secondary: branding.secondaryColor || state.theme.colors.secondary.DEFAULT,
            },
            fonts: {
                primary: branding.fonts?.primary || state.theme.typography.fontFamily.sans[0],
                secondary: branding.fonts?.secondary,
            },
            customCSS: branding.customCSS,
        });
    }, [themeManager, state.theme]);

    // Reset theme method
    const resetTheme = useCallback(() => {
        themeManager.setTheme(defaultTheme);
        dispatch({ type: 'RESET_THEME' });
    }, [themeManager]);

    // Generate CSS method
    const generateCSS = useCallback((): string => {
        let css = ':root {\n';

        // Add CSS variables
        Object.entries(state.cssVariables).forEach(([property, value]) => {
            css += `  ${property}: ${value};\n`;
        });

        css += '}\n\n';

        // Add theme mode specific styles
        css += `[data-theme="light"] {\n`;
        css += `  color-scheme: light;\n`;
        css += `}\n\n`;

        css += `[data-theme="dark"] {\n`;
        css += `  color-scheme: dark;\n`;
        css += `}\n\n`;

        // Add organization branding styles if available
        if (state.organizationBranding?.customCSS) {
            css += `/* Organization Custom CSS */\n`;
            css += state.organizationBranding.customCSS;
            css += '\n\n';
        }

        return css;
    }, [state.cssVariables, state.organizationBranding]);

    // Context value
    const contextValue: ThemeContextValue = {
        // State
        ...state,

        // Methods
        setTheme,
        setMode,
        applyBranding,
        resetTheme,
        generateCSS,
    };

    return (
        <ThemeContext.Provider value={contextValue}>
            {children}
        </ThemeContext.Provider>
    );
}

// ============================================================================
// Hook to use theme context
// ============================================================================

export function useTheme() {
    const context = useContext(ThemeContext);

    if (!context) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }

    return context;
}

// ============================================================================
// Hook for theme mode switching
// ============================================================================

export function useThemeMode() {
    const { mode, effectiveMode, setMode, isSystemMode } = useTheme();

    return {
        mode,
        effectiveMode,
        isSystemMode,
        setMode,
        toggleMode: () => {
            if (mode === 'light') {
                setMode('dark');
            } else if (mode === 'dark') {
                setMode('light');
            } else {
                // If system mode, toggle to opposite of current effective mode
                setMode(effectiveMode === 'light' ? 'dark' : 'light');
            }
        },
        setLightMode: () => setMode('light'),
        setDarkMode: () => setMode('dark'),
        setSystemMode: () => setMode('system'),
    };
}

// ============================================================================
// Hook for organization branding
// ============================================================================

export function useOrganizationBranding() {
    const { organizationBranding, applyBranding, isCustomized } = useTheme();

    const applyOrganizationBranding = useCallback((organization: Organization) => {
        if (organization.settings?.branding) {
            const branding: OrganizationBranding = {
                primaryColor: organization.settings.branding.primaryColor,
                secondaryColor: organization.settings.branding.secondaryColor,
                logo: organization.logoUrl,
                favicon: organization.settings.branding.favicon,
                customCSS: organization.settings.branding.customCSS,
            };

            applyBranding(branding);
        }
    }, [applyBranding]);

    return {
        branding: organizationBranding,
        isCustomBranded: isCustomized,
        applyOrganizationBranding,
        applyBranding,
        hasLogo: !!organizationBranding?.logo,
        hasCustomCSS: !!organizationBranding?.customCSS,
        primaryColor: organizationBranding?.primaryColor,
        secondaryColor: organizationBranding?.secondaryColor,
    };
}

// ============================================================================
// Hook for CSS variables
// ============================================================================

export function useThemeVariables() {
    const { cssVariables, generateCSS } = useTheme();

    return {
        variables: cssVariables,
        getVariable: (name: string) => cssVariables[name],
        generateCSS,
        applyToElement: (element: HTMLElement) => {
            Object.entries(cssVariables).forEach(([property, value]) => {
                element.style.setProperty(property, value);
            });
        },
    };
}

// ============================================================================
// Higher-order component for theme
// ============================================================================

export function withTheme<T extends object>(Component: React.ComponentType<T>) {
    const WithThemeComponent = (props: T) => {
        const theme = useTheme();

        return <Component {...props} theme={theme} />;
    };

    WithThemeComponent.displayName = `withTheme(${Component.displayName || Component.name})`;

    return WithThemeComponent;
}

// ============================================================================
// Theme switching button component
// ============================================================================

export function ThemeSwitcher({
                                  className,
                                  iconClassName,
                                  showLabel = false,
                                  ...props
                              }: {
    className?: string;
    iconClassName?: string;
    showLabel?: boolean;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
    const { mode, effectiveMode, toggleMode } = useThemeMode();

    const getIcon = () => {
        if (mode === 'system') {
            return effectiveMode === 'dark' ? '🌙' : '☀️';
        }
        return mode === 'dark' ? '🌙' : '☀️';
    };

    const getLabel = () => {
        if (mode === 'system') {
            return `System (${effectiveMode})`;
        }
        return mode === 'dark' ? 'Dark' : 'Light';
    };

    return (
        <button
            type="button"
            onClick={toggleMode}
            className={className}
            title={`Switch to ${effectiveMode === 'dark' ? 'light' : 'dark'} mode`}
            {...props}
        >
            <span className={iconClassName}>
                {getIcon()}
            </span>
            {showLabel && <span>{getLabel()}</span>}
        </button>
    );
}

// ============================================================================
// Export theme provider
// ============================================================================

export { ThemeContext };
export type { ThemeContextValue };