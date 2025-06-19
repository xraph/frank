import type {
    ColorPalette,
    ColorPalettes,
    ComponentVariant,
    Theme,
    ThemeColors,
    ThemeCustomization,
    ThemeGeneratorOptions,
    ThemeMode,
    ThemeValidation
} from '../types';

// Color utilities
export const hexToHsl = (hex: string): [number, number, number] => {
    const r = parseInt(hex.slice(1, 3), 16) / 255;
    const g = parseInt(hex.slice(3, 5), 16) / 255;
    const b = parseInt(hex.slice(5, 7), 16) / 255;

    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    let h = 0;
    let s = 0;
    const l = (max + min) / 2;

    if (max === min) {
        h = s = 0; // achromatic
    } else {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
            case r: h = (g - b) / d + (g < b ? 6 : 0); break;
            case g: h = (b - r) / d + 2; break;
            case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
    }

    return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
};

export const hslToHex = (h: number, s: number, l: number): string => {
    h /= 360;
    s /= 100;
    l /= 100;

    const hue2rgb = (p: number, q: number, t: number) => {
        if (t < 0) t += 1;
        if (t > 1) t -= 1;
        if (t < 1/6) return p + (q - p) * 6 * t;
        if (t < 1/2) return q;
        if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
        return p;
    };

    let r, g, b;

    if (s === 0) {
        r = g = b = l; // achromatic
    } else {
        const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        const p = 2 * l - q;
        r = hue2rgb(p, q, h + 1/3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1/3);
    }

    const toHex = (c: number) => {
        const hex = Math.round(c * 255).toString(16);
        return hex.length === 1 ? '0' + hex : hex;
    };

    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
};

export const adjustBrightness = (hex: string, amount: number): string => {
    const [h, s, l] = hexToHsl(hex);
    const newL = Math.max(0, Math.min(100, l + amount));
    return hslToHex(h, s, newL);
};

export const adjustSaturation = (hex: string, amount: number): string => {
    const [h, s, l] = hexToHsl(hex);
    const newS = Math.max(0, Math.min(100, s + amount));
    return hslToHex(h, newS, l);
};

export const adjustHue = (hex: string, amount: number): string => {
    const [h, s, l] = hexToHsl(hex);
    const newH = (h + amount + 360) % 360;
    return hslToHex(newH, s, l);
};

export const getContrastRatio = (color1: string, color2: string): number => {
    const getLuminance = (hex: string): number => {
        const r = parseInt(hex.slice(1, 3), 16) / 255;
        const g = parseInt(hex.slice(3, 5), 16) / 255;
        const b = parseInt(hex.slice(5, 7), 16) / 255;

        const gamma = (c: number) => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);

        return 0.2126 * gamma(r) + 0.7152 * gamma(g) + 0.0722 * gamma(b);
    };

    const lum1 = getLuminance(color1);
    const lum2 = getLuminance(color2);
    const brightest = Math.max(lum1, lum2);
    const darkest = Math.min(lum1, lum2);

    return (brightest + 0.05) / (darkest + 0.05);
};

export const isValidContrast = (color1: string, color2: string, level: 'AA' | 'AAA' = 'AA'): boolean => {
    const ratio = getContrastRatio(color1, color2);
    return level === 'AA' ? ratio >= 4.5 : ratio >= 7;
};

export const findAccessibleColor = (
    baseColor: string,
    backgroundColor: string,
    level: 'AA' | 'AAA' = 'AA'
): string => {
    let color = baseColor;
    let [h, s, l] = hexToHsl(color);

    // Try adjusting lightness first
    for (let adjustment = 0; adjustment <= 50; adjustment += 5) {
        // Try lighter
        const lighterL = Math.min(100, l + adjustment);
        const lighterColor = hslToHex(h, s, lighterL);
        if (isValidContrast(lighterColor, backgroundColor, level)) {
            return lighterColor;
        }

        // Try darker
        const darkerL = Math.max(0, l - adjustment);
        const darkerColor = hslToHex(h, s, darkerL);
        if (isValidContrast(darkerColor, backgroundColor, level)) {
            return darkerColor;
        }
    }

    // If lightness adjustment doesn't work, try pure black or white
    const white = '#ffffff';
    const black = '#000000';

    if (isValidContrast(white, backgroundColor, level)) {
        return white;
    }

    if (isValidContrast(black, backgroundColor, level)) {
        return black;
    }

    // Fallback to the original color
    return baseColor;
};

// Color palette generation
export const generateColorPalette = (baseColor: string): ColorPalette => {
    const [h, s, l] = hexToHsl(baseColor);

    return {
        50: hslToHex(h, Math.max(10, s - 40), Math.min(95, l + 40)),
        100: hslToHex(h, Math.max(20, s - 30), Math.min(90, l + 35)),
        200: hslToHex(h, Math.max(30, s - 20), Math.min(85, l + 25)),
        300: hslToHex(h, Math.max(40, s - 10), Math.min(75, l + 15)),
        400: hslToHex(h, s, Math.min(65, l + 5)),
        500: baseColor,
        600: hslToHex(h, Math.min(100, s + 10), Math.max(35, l - 5)),
        700: hslToHex(h, Math.min(100, s + 15), Math.max(25, l - 15)),
        800: hslToHex(h, Math.min(100, s + 20), Math.max(15, l - 25)),
        900: hslToHex(h, Math.min(100, s + 25), Math.max(10, l - 35)),
        950: hslToHex(h, Math.min(100, s + 30), Math.max(5, l - 45)),
        DEFAULT: baseColor,
        foreground: findAccessibleColor(baseColor, '#ffffff'),
    };
};

export const generateSemanticColors = (
    primary: string,
    mode: ThemeMode = 'light'
): Pick<ThemeColors, 'success' | 'warning' | 'danger' | 'info'> => {
    const colors = {
        success: mode === 'light' ? '#22c55e' : '#16a34a',
        warning: mode === 'light' ? '#f59e0b' : '#d97706',
        danger: mode === 'light' ? '#ef4444' : '#dc2626',
        info: mode === 'light' ? '#3b82f6' : '#2563eb',
    };

    return colors;
};

// Theme mode utilities
export const getSystemTheme = (): 'light' | 'dark' => {
    if (typeof window === 'undefined') return 'light';

    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

export const watchSystemTheme = (callback: (theme: 'light' | 'dark') => void): (() => void) => {
    if (typeof window === 'undefined') return () => {};

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

    const handler = (e: MediaQueryListEvent) => {
        callback(e.matches ? 'dark' : 'light');
    };

    mediaQuery.addEventListener('change', handler);

    return () => {
        mediaQuery.removeEventListener('change', handler);
    };
};

export const resolveThemeMode = (mode: ThemeMode): 'light' | 'dark' => {
    if (mode === 'system') {
        return getSystemTheme();
    }
    return mode;
};

// CSS variable utilities
export const generateCSSVariables = (theme: Theme): Record<string, string> => {
    const variables: Record<string, string> = {};

    // Colors
    Object.entries(theme.colors).forEach(([key, value]) => {
        variables[`--frank-${key.replace(/([A-Z])/g, '-$1').toLowerCase()}`] = value;
    });

    // Spacing
    Object.entries(theme.spacing).forEach(([key, value]) => {
        variables[`--frank-spacing-${key}`] = value;
    });

    // Border radius
    Object.entries(theme.borderRadius).forEach(([key, value]) => {
        variables[`--frank-radius-${key}`] = value;
    });

    // Shadows
    Object.entries(theme.shadows).forEach(([key, value]) => {
        variables[`--frank-shadow-${key}`] = value;
    });

    // Typography
    Object.entries(theme.typography.fontSize).forEach(([key, [size, config]]) => {
        variables[`--frank-text-${key}`] = size;
        variables[`--frank-text-${key}-line-height`] = config.lineHeight;
        if (config.letterSpacing) {
            variables[`--frank-text-${key}-letter-spacing`] = config.letterSpacing;
        }
    });

    // Font weights
    Object.entries(theme.typography.fontWeight).forEach(([key, value]) => {
        variables[`--frank-font-${key}`] = value;
    });

    // Custom variables
    if (theme.cssVariables) {
        Object.entries(theme.cssVariables).forEach(([key, value]) => {
            variables[key.startsWith('--') ? key : `--${key}`] = value;
        });
    }

    return variables;
};

export const applyCSSVariables = (variables: Record<string, string>, element?: HTMLElement): void => {
    const target = element || document.documentElement;

    Object.entries(variables).forEach(([key, value]) => {
        target.style.setProperty(key, value);
    });
};

export const removeCSSVariables = (keys: string[], element?: HTMLElement): void => {
    const target = element || document.documentElement;

    keys.forEach(key => {
        target.style.removeProperty(key);
    });
};

// Theme generation
export const generateTheme = (options: ThemeGeneratorOptions): Partial<Theme> => {
    const { primaryColor, secondaryColor, mode, colorHarmony } = options;

    const primaryPalette = generateColorPalette(primaryColor);
    const secondaryPalette = secondaryColor
        ? generateColorPalette(secondaryColor)
        : generateColorPalette(adjustHue(primaryColor, 30));

    // Generate neutral palette
    const neutralBase = mode === 'light' ? '#6b7280' : '#9ca3af';
    const neutralPalette = generateColorPalette(neutralBase);

    // Generate semantic colors
    const semanticColors = generateSemanticColors(primaryColor, mode);

    const colors: ThemeColors = {
        background: mode === 'light' ? '#ffffff' : '#0f172a',
        foreground: mode === 'light' ? '#0f172a' : '#f8fafc',

        content1: mode === 'light' ? '#ffffff' : '#18181b',
        content2: mode === 'light' ? '#f4f4f5' : '#27272a',
        content3: mode === 'light' ? '#e4e4e7' : '#3f3f46',
        content4: mode === 'light' ? '#d4d4d8' : '#52525b',

        primary: primaryPalette,
        primaryForeground: findAccessibleColor('#ffffff', primaryPalette[500]),

        secondary: secondaryPalette,
        secondaryForeground: findAccessibleColor('#ffffff', secondaryPalette[500]),

        accent: primaryPalette[600],
        accentForeground: findAccessibleColor('#ffffff', primaryPalette[600]),

        muted: neutralPalette[100],
        mutedForeground: neutralPalette[600],

        border: mode === 'light' ? neutralPalette[200] : neutralPalette[800],
        divider: mode === 'light' ? neutralPalette[100] : neutralPalette[800],

        input: mode === 'light' ? '#ffffff' : '#27272a',
        inputForeground: mode === 'light' ? '#0f172a' : '#f8fafc',

        focus: primaryPalette[500],
        focusVisible: primaryPalette[500],

        overlay: mode === 'light' ? 'rgba(0, 0, 0, 0.5)' : 'rgba(0, 0, 0, 0.8)',

        success: semanticColors.success,
        successForeground: findAccessibleColor('#ffffff', semanticColors.success),
        warning: semanticColors.warning,
        warningForeground: findAccessibleColor('#ffffff', semanticColors.warning),
        danger: semanticColors.danger,
        dangerForeground: findAccessibleColor('#ffffff', semanticColors.danger),
        info: semanticColors.info,
        infoForeground: findAccessibleColor('#ffffff', semanticColors.info),

        selection: primaryPalette[100],
        selectionForeground: primaryPalette[900],

        disabled: neutralPalette[300],
        disabledForeground: neutralPalette[500],
        card: '',
        cardForeground: '',
        popover: '',
        popoverForeground: '',
        ring: '',
        destructive: '',
        destructiveForeground: ''
    };

    const palette: ColorPalettes = {
        primary: primaryPalette,
        secondary: secondaryPalette,
        neutral: neutralPalette,
        success: generateColorPalette(semanticColors.success),
        warning: generateColorPalette(semanticColors.warning),
        danger: generateColorPalette(semanticColors.danger),
        info: generateColorPalette(semanticColors.info),
    };

    return {
        name: `Generated ${mode} theme`,
        mode,
        colors,
        palette,
    };
};

// Theme validation
export const validateTheme = (theme: Partial<Theme>): ThemeValidation => {
    const errors: string[] = [];
    const warnings: string[] = [];
    const contrastRatios: Record<string, number> = {};

    if (!theme.colors) {
        errors.push('Theme must have colors defined');
        return {
            valid: false,
            errors,
            warnings,
            accessibility: {
                contrastRatios,
                wcagLevel: 'fail',
            },
        };
    }

    // Check required colors
    const requiredColors = ['background', 'foreground', 'primary', 'primaryForeground'];
    for (const color of requiredColors) {
        if (!(color in theme.colors)) {
            errors.push(`Missing required color: ${color}`);
        }
    }

    // Check contrast ratios
    const checkContrast = (colorKey: string, backgroundKey: string) => {
        const color = theme.colors![colorKey as keyof ThemeColors];
        const background = theme.colors![backgroundKey as keyof ThemeColors];

        if (color && background) {
            const ratio = getContrastRatio(typeof color === 'string' ? color : color.DEFAULT, typeof background === 'string' ? background : background.DEFAULT);
            contrastRatios[`${colorKey}/${backgroundKey}`] = ratio;

            if (ratio < 4.5) {
                warnings.push(`Low contrast ratio for ${colorKey} on ${backgroundKey}: ${ratio.toFixed(2)}`);
            }
        }
    };

    checkContrast('foreground', 'background');
    checkContrast('primaryForeground', 'primary');
    checkContrast('secondaryForeground', 'secondary');
    checkContrast('successForeground', 'success');
    checkContrast('warningForeground', 'warning');
    checkContrast('dangerForeground', 'danger');
    checkContrast('infoForeground', 'info');

    // Determine WCAG level
    const minRatio = Math.min(...Object.values(contrastRatios));
    let wcagLevel: 'A' | 'AA' | 'AAA' | 'fail';

    if (minRatio >= 7) {
        wcagLevel = 'AAA';
    } else if (minRatio >= 4.5) {
        wcagLevel = 'AA';
    } else if (minRatio >= 3) {
        wcagLevel = 'A';
    } else {
        wcagLevel = 'fail';
    }

    return {
        valid: errors.length === 0,
        errors,
        warnings,
        accessibility: {
            contrastRatios,
            wcagLevel,
        },
    };
};

// Theme merging utilities
export const mergeThemes = (baseTheme: Theme, customization: ThemeCustomization): Theme => {
    const merged: Theme = { ...baseTheme };

    if (customization.colors) {
        merged.colors = { ...merged.colors, ...customization.colors };
    }

    if (customization.typography) {
        merged.typography = {
            ...merged.typography,
            ...customization.typography,
        };
    }

    if (customization.spacing) {
        merged.spacing = { ...merged.spacing, ...customization.spacing };
    }

    if (customization.components) {
        merged.components = {
            ...merged.components,
            ...customization.components,
        };
    }

    if (customization.cssVariables) {
        merged.cssVariables = {
            ...merged.cssVariables,
            ...customization.cssVariables,
        };
    }

    if (customization.custom) {
        merged.custom = {
            ...merged.custom,
            ...customization.custom,
        };
    }

    return merged;
};

// Component variant utilities
export const getComponentVariant = (
    theme: Theme,
    component: string,
    variant: string,
    color: string = 'default'
): ComponentVariant | undefined => {
    const componentVariants = theme.components[component as keyof typeof theme.components];
    if (!componentVariants) return undefined;

    const variantConfig = componentVariants[variant as keyof typeof componentVariants];
    if (!variantConfig || typeof variantConfig !== 'object') return undefined;

    return variantConfig as ComponentVariant;
};

export const getComponentStyles = (
    theme: Theme,
    component: string,
    variant: string,
    color: string = 'default',
    size: string = 'md'
): string => {
    const variantConfig = getComponentVariant(theme, component, variant, color);
    if (!variantConfig) return '';

    let styles = variantConfig.base || '';

    // Add color styles
    const colorStyles = variantConfig.colors?.[color as keyof typeof variantConfig.colors];
    if (colorStyles) {
        styles += ` ${colorStyles.background || ''} ${colorStyles.foreground || ''} ${colorStyles.border || ''}`;
    }

    // Add size styles
    const sizeStyles = variantConfig.sizes?.[size as keyof typeof variantConfig.sizes];
    if (sizeStyles) {
        styles += ` ${sizeStyles}`;
    }

    return styles.trim();
};

// Storage utilities for theme persistence
export const saveThemeToStorage = (theme: string, mode: ThemeMode): void => {
    if (typeof window === 'undefined') return;

    try {
        localStorage.setItem('frank-auth-theme', theme);
        localStorage.setItem('frank-auth-theme-mode', mode);
    } catch {
        // Ignore storage errors
    }
};

export const loadThemeFromStorage = (): { theme?: string; mode?: ThemeMode } => {
    if (typeof window === 'undefined') return {};

    try {
        const theme = localStorage.getItem('frank-auth-theme');
        const mode = localStorage.getItem('frank-auth-theme-mode') as ThemeMode;

        return {
            theme: theme || undefined,
            mode: mode || undefined,
        };
    } catch {
        return {};
    }
};

// Export utilities object
export const ThemeUtils = {
    // Color utilities
    hexToHsl,
    hslToHex,
    adjustBrightness,
    adjustSaturation,
    adjustHue,
    getContrastRatio,
    isValidContrast,
    findAccessibleColor,

    // Palette generation
    generateColorPalette,
    generateSemanticColors,

    // Theme mode
    getSystemTheme,
    watchSystemTheme,
    resolveThemeMode,

    // CSS variables
    generateCSSVariables,
    applyCSSVariables,
    removeCSSVariables,

    // Theme generation
    generateTheme,
    validateTheme,
    mergeThemes,

    // Component utilities
    getComponentVariant,
    getComponentStyles,

    // Storage
    saveThemeToStorage,
    loadThemeFromStorage,
};