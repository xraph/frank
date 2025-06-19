import type {CSSProperties} from 'react';
import type {JSONObject} from './index';

// Theme mode
export type ThemeMode = 'light' | 'dark' | 'system';

// Color palette
export interface ColorPalette {
    50: string;
    100: string;
    200: string;
    300: string;
    400: string;
    500: string;
    600: string;
    700: string;
    800: string;
    900: string;
    950: string;
    DEFAULT: string;
    foreground: string;
}
// Color palette
export interface ColorPalettes {
    // Primary colors
    primary: ColorPalette;

    // Secondary colors
    secondary: ColorPalette;

    // Neutral colors
    neutral: ColorPalette;

    // Semantic colors
    success: ColorPalette;

    warning: ColorPalette;

    danger: ColorPalette;

    info: ColorPalette;


    // success: '#10b981',
    // 'success-foreground': '#ffffff',
    // warning: '#f59e0b',
    // 'warning-foreground': '#ffffff',
    // danger: '#ef4444',
    // 'danger-foreground': '#ffffff',
    // info: '#3b82f6',
    // 'info-foreground': '#ffffff',
}

// Theme colors (semantic)
export interface ThemeColors {
    // Base colors
    background: string;
    foreground: string;

    // Card colors
    card: string;
    cardForeground: string;
    popover: string;
    popoverForeground: string;
    ring: string;
    destructive: string;
    destructiveForeground: string;

    // Content colors
    content1: string;
    content2: string;
    content3: string;
    content4: string;

    // Primary colors
    primary: ColorPalette;
    primaryForeground: string;

    // Secondary colors
    secondary: ColorPalette;
    secondaryForeground: string;

    // Accent colors
    accent: string;
    accentForeground: string;

    // Muted colors
    muted: string;
    mutedForeground: string;

    // Border colors
    border: string;
    divider: string;

    // Input colors
    input: string;
    inputForeground: string;

    // Focus colors
    focus: string;
    focusVisible: string;

    // Overlay colors
    overlay: string;

    // Semantic colors
    success: string;
    successForeground: string;
    warning: string;
    warningForeground: string;
    danger: string;
    dangerForeground: string;
    info: string;
    infoForeground: string;

    // Selection colors
    selection: string;
    selectionForeground: string;

    // Disabled colors
    disabled: string;
    disabledForeground: string;
}

// Typography system
export interface Typography {
    // Font families
    fontFamily: {
        sans: string[];
        serif: string[];
        mono: string[];
    };

    // Font sizes
    fontSize: {
        xs: [string, { lineHeight: string; letterSpacing?: string }];
        sm: [string, { lineHeight: string; letterSpacing?: string }];
        base: [string, { lineHeight: string; letterSpacing?: string }];
        lg: [string, { lineHeight: string; letterSpacing?: string }];
        xl: [string, { lineHeight: string; letterSpacing?: string }];
        '2xl': [string, { lineHeight: string; letterSpacing?: string }];
        '3xl': [string, { lineHeight: string; letterSpacing?: string }];
        '4xl': [string, { lineHeight: string; letterSpacing?: string }];
        '5xl': [string, { lineHeight: string; letterSpacing?: string }];
        '6xl': [string, { lineHeight: string; letterSpacing?: string }];
        '7xl': [string, { lineHeight: string; letterSpacing?: string }];
        '8xl': [string, { lineHeight: string; letterSpacing?: string }];
        '9xl': [string, { lineHeight: string; letterSpacing?: string }];
    };

    // Font weights
    fontWeight: {
        thin: string;
        extralight: string;
        light: string;
        normal: string;
        medium: string;
        semibold: string;
        bold: string;
        extrabold: string;
        black: string;
    };

    // Line heights
    lineHeight: {
        none: string;
        tight: string;
        snug: string;
        normal: string;
        relaxed: string;
        loose: string;
    };

    // Letter spacing
    letterSpacing: {
        tighter: string;
        tight: string;
        normal: string;
        wide: string;
        wider: string;
        widest: string;
    };
}

// Spacing system
export interface Spacing {
    0: string;
    px: string;
    0.5: string;
    1: string;
    1.5: string;
    2: string;
    2.5: string;
    3: string;
    3.5: string;
    4: string;
    5: string;
    6: string;
    7: string;
    8: string;
    9: string;
    10: string;
    11: string;
    12: string;
    14: string;
    16: string;
    20: string;
    24: string;
    28: string;
    32: string;
    36: string;
    40: string;
    44: string;
    48: string;
    52: string;
    56: string;
    60: string;
    64: string;
    72: string;
    80: string;
    96: string;
}

// Border radius system
export interface BorderRadius {
    none: string;
    sm: string;
    base: string;
    md: string;
    lg: string;
    xl: string;
    '2xl': string;
    '3xl': string;
    full: string;
}

// Shadow system
export interface Shadows {
    none: string;
    sm: string;
    base: string;
    md: string;
    lg: string;
    xl: string;
    '2xl': string;
    inner: string;
}

// Animation system
export interface Animations {
    // Durations
    duration: {
        0: string;
        75: string;
        100: string;
        150: string;
        200: string;
        300: string;
        500: string;
        700: string;
        1000: string;
        slow: string;
        fast: string;
        normal: string;
    };

    // Timing functions
    timingFunction: {
        linear: string;
        in: string;
        out: string;
        inOut: string;
    };

    // Common animations
    keyframes: {
        spin: Record<string, CSSProperties>;
        ping: Record<string, CSSProperties>;
        pulse: Record<string, CSSProperties>;
        bounce: Record<string, CSSProperties>;
        fadeIn: Record<string, CSSProperties>;
        fadeOut: Record<string, CSSProperties>;
        slideIn: Record<string, CSSProperties>;
        slideOut: Record<string, CSSProperties>;
        scaleIn: Record<string, CSSProperties>;
        scaleOut: Record<string, CSSProperties>;
    };
}

// Breakpoints system
export interface Breakpoints {
    xs: string;
    sm: string;
    md: string;
    lg: string;
    xl: string;
    '2xl': string;
}

// Z-index system
export interface ZIndex {
    auto: string;
    0: string;
    10: string;
    20: string;
    30: string;
    40: string;
    50: string;
    dropdown: string;
    modal: string;
    popover: string;
    tooltip: string;
    overlay: string;
    max: string;
}

// Component theme variants
export interface ComponentVariants {
    // Button variants
    button: {
        solid: ComponentVariant;
        bordered: ComponentVariant;
        light: ComponentVariant;
        flat: ComponentVariant;
        faded: ComponentVariant;
        shadow: ComponentVariant;
        ghost: ComponentVariant;
    };

    // Input variants
    input: {
        flat: ComponentVariant;
        bordered: ComponentVariant;
        underlined: ComponentVariant;
        faded: ComponentVariant;
    };

    // Card variants
    card: {
        shadow: ComponentVariant;
        bordered: ComponentVariant;
        flat: ComponentVariant;
    };

    // Modal variants
    modal: {
        shadow: ComponentVariant;
        bordered: ComponentVariant;
        blur: ComponentVariant;
    };

    // Avatar variants
    avatar: {
        solid: ComponentVariant;
        bordered: ComponentVariant;
        light: ComponentVariant;
        flat: ComponentVariant;
        faded: ComponentVariant;
        shadow: ComponentVariant;
    };
}

// Component variant definition
export interface ComponentVariant {
    base?: string;
    colors?: {
        default?: ComponentColorVariant;
        primary?: ComponentColorVariant;
        secondary?: ComponentColorVariant;
        success?: ComponentColorVariant;
        warning?: ComponentColorVariant;
        danger?: ComponentColorVariant;
    };
    sizes?: {
        sm?: string;
        md?: string;
        lg?: string;
    };
}

// Component color variant
export interface ComponentColorVariant {
    background?: string;
    foreground?: string;
    border?: string;
    hover?: {
        background?: string;
        foreground?: string;
        border?: string;
    };
    focus?: {
        background?: string;
        foreground?: string;
        border?: string;
    };
    active?: {
        background?: string;
        foreground?: string;
        border?: string;
    };
    disabled?: {
        background?: string;
        foreground?: string;
        border?: string;
    };
}

// Main theme interface
export interface Theme {
    // Theme metadata
    name: string;
    mode: ThemeMode;

    // Core design tokens
    colors: ThemeColors;
    palette: ColorPalettes;
    typography: Typography;
    spacing: Spacing;
    borderRadius: BorderRadius;
    shadows: Shadows;
    animations: Animations;
    breakpoints: Breakpoints;
    zIndex: ZIndex;

    // Component variants
    components: ComponentVariants;

    // Custom CSS variables
    cssVariables?: Record<string, string>;

    // Custom properties
    custom?: JSONObject;
}

// // Theme configuration
// export interface ThemeConfig {
//     // Default theme
//     defaultTheme: string;
//
//     // Available themes
//     themes: Record<string, Theme>;
//
//     // Theme switching
//     allowThemeSwitching: boolean;
//
//     // System theme detection
//     respectSystemTheme: boolean;
//
//     // Theme persistence
//     persistTheme: boolean;
//     storageKey: string;
//
//     // Custom theme loader
//     customThemeLoader?: (themeName: string) => Promise<Theme>;
// }

// Theme context
export interface ThemeContext {
    // Current theme
    theme: Theme;

    // Theme mode
    mode: ThemeMode;

    // Theme switching functions
    setTheme: (themeName: string) => void;
    setMode: (mode: ThemeMode) => void;

    // Available themes
    availableThemes: string[];

    // System theme
    systemTheme: 'light' | 'dark';

    // Theme loading state
    isLoading: boolean;
}

// CSS-in-JS theme utilities
export interface ThemeUtilities {
    // Color utilities
    color: (colorPath: string) => string;
    alpha: (colorPath: string, alpha: number) => string;
    lighten: (colorPath: string, amount: number) => string;
    darken: (colorPath: string, amount: number) => string;

    // Spacing utilities
    space: (size: keyof Spacing) => string;

    // Typography utilities
    font: (size: keyof Typography['fontSize']) => CSSProperties;

    // Media query utilities
    media: (breakpoint: keyof Breakpoints) => string;

    // Component utilities
    variant: (component: string, variant: string, color?: string) => CSSProperties;
}

// Theme provider props
export interface ThemeProviderProps {
    children: React.ReactNode;
    theme?: string;
    mode?: ThemeMode;
    themes?: Record<string, Theme>;
    respectSystemTheme?: boolean;
    persistTheme?: boolean;
    storageKey?: string;
    customCSS?: string;
    className?: string;
}

// Built-in theme names
export type BuiltInTheme =
    | 'default'
    | 'dark'
    | 'light'
    | 'modern'
    | 'minimal'
    | 'professional'
    | 'colorful'
    | 'high-contrast';

// Theme customization
export interface ThemeCustomization {
    // Base theme to extend
    extends?: string;

    // Color overrides
    colors?: Partial<ThemeColors>;

    // Typography overrides
    typography?: Partial<Typography>;

    // Spacing overrides
    spacing?: Partial<Spacing>;

    // Component overrides
    components?: Partial<ComponentVariants>;

    // Custom CSS variables
    cssVariables?: Record<string, string>;

    // Custom properties
    custom?: JSONObject;
}

// Theme generator options
export interface ThemeGeneratorOptions {
    // Primary color
    primaryColor: string;

    // Secondary color
    secondaryColor?: string;

    // Base mode
    mode: 'light' | 'dark';

    // Color harmony
    colorHarmony: 'monochromatic' | 'analogous' | 'complementary' | 'triadic' | 'tetradic';

    // Accessibility
    contrastRatio: 'AA' | 'AAA';

    // Border radius style
    borderRadius: 'none' | 'small' | 'medium' | 'large' | 'full';

    // Shadow style
    shadows: 'none' | 'subtle' | 'medium' | 'strong';

    // Animation style
    animations: 'none' | 'reduced' | 'normal' | 'enhanced';
}

// Theme validation
export interface ThemeValidation {
    valid: boolean;
    errors: string[];
    warnings: string[];
    accessibility: {
        contrastRatios: Record<string, number>;
        wcagLevel: 'A' | 'AA' | 'AAA' | 'fail';
    };
}

// Default themes
export const DEFAULT_THEMES: Record<BuiltInTheme, Partial<Theme>> = {
    default: {
        name: 'Default',
        mode: 'light',
    },
    dark: {
        name: 'Dark',
        mode: 'dark',
    },
    light: {
        name: 'Light',
        mode: 'light',
    },
    modern: {
        name: 'Modern',
        mode: 'light',
    },
    minimal: {
        name: 'Minimal',
        mode: 'light',
    },
    professional: {
        name: 'Professional',
        mode: 'light',
    },
    colorful: {
        name: 'Colorful',
        mode: 'light',
    },
    'high-contrast': {
        name: 'High Contrast',
        mode: 'light',
    },
};