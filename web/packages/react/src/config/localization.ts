/**
 * @frank-auth/react - Localization Configuration
 *
 * Comprehensive internationalization system with support for multiple locales,
 * dynamic loading, pluralization, and context-aware translations.
 */

import type {Locale, LocaleDirection, LocalizationConfig,} from './types';

import {DEFAULT_LOCALE_MESSAGES, DEFAULT_LOCALIZATION_CONFIG} from './defaults';
import {LOCALE_INFO, LocaleMessages} from "@/locales";

// ============================================================================
// Translation Keys and Type Safety
// ============================================================================

/**
 * Deep key paths for type-safe translations
 */
type DeepKeyOf<T> = T extends object ? {
    [K in keyof T]: K extends string ? T[K] extends object
            ? `${K}.${DeepKeyOf<T[K]>}`
            : K
        : never
}[keyof T] : never;

export type TranslationKey = DeepKeyOf<LocaleMessages>;

/**
 * Interpolation values for translations
 */
export interface InterpolationValues {
    [key: string]: string | number | boolean | Date;
}

/**
 * Pluralization options
 */
export interface PluralOptions {
    count: number;
    zero?: string;
    one?: string;
    two?: string;
    few?: string;
    many?: string;
    other: string;
}


// ============================================================================
// Localization Manager Class
// ============================================================================

export class LocalizationManager {
    private config: LocalizationConfig;
    private currentLocale: Locale;
    private loadedMessages: Map<Locale, LocaleMessages> = new Map();
    private listeners: Set<(locale: Locale) => void> = new Set();

    constructor(initialConfig?: Partial<LocalizationConfig>) {
        this.config = { ...DEFAULT_LOCALIZATION_CONFIG, ...initialConfig };
        this.currentLocale = this.config.defaultLocale;

        // Load default locale messages
        this.loadedMessages.set(this.currentLocale, {
            ...LOCALE_INFO[this.currentLocale],
            ...this.config.messages,
        });
    }

    /**
     * Get current locale
     */
    getCurrentLocale(): Locale {
        return this.currentLocale;
    }

    /**
     * Get current locale metadata
     */
    getCurrentLocaleMetadata() {
        return LOCALE_INFO[this.currentLocale];
    }

    /**
     * Set current locale
     */
    async setLocale(locale: Locale): Promise<void> {
        if (!this.config.supportedLocales.includes(locale)) {
            console.warn(`Locale ${locale} is not supported. Falling back to ${this.config.fallbackLocale}`);
            locale = this.config.fallbackLocale;
        }

        this.currentLocale = locale;

        // Load messages if not already loaded
        if (!this.loadedMessages.has(locale)) {
            await this.loadLocaleMessages(locale);
        }

        this.notifyListeners();
    }

    /**
     * Get translation for a key
     */
    t(key: TranslationKey, interpolation?: InterpolationValues): string {
        const messages = this.getCurrentMessages();
        const value = this.getNestedValue(messages, key);

        if (typeof value !== 'string') {
            console.warn(`Translation key "${key}" not found for locale "${this.currentLocale}"`);
            return key;
        }

        return this.interpolate(value, interpolation);
    }

    /**
     * Get plural translation
     */
    plural(key: string, options: PluralOptions): string {
        const { count } = options;
        const metadata = LOCALE_INFO[this.currentLocale];
        const rule = metadata.pluralRules.select(count);

        let pluralKey: string;

        // Handle different plural forms
        if (count === 0 && options.zero) {
            return this.interpolate(options.zero, { count });
        }

        switch (rule) {
            case 'one':
                pluralKey = options.one || options.other;
                break;
            case 'two':
                pluralKey = options.two || options.other;
                break;
            case 'few':
                pluralKey = options.few || options.other;
                break;
            case 'many':
                pluralKey = options.many || options.other;
                break;
            default:
                pluralKey = options.other;
        }

        return this.interpolate(pluralKey, { count });
    }

    /**
     * Format date according to current locale
     */
    formatDate(date: Date, options?: Intl.DateTimeFormatOptions): string {
        const metadata = LOCALE_INFO[this.currentLocale];
        return new Intl.DateTimeFormat(this.currentLocale, {
            ...options,
            ...(options || {}),
        }).format(date);
    }

    /**
     * Format time according to current locale
     */
    formatTime(date: Date, options?: Intl.DateTimeFormatOptions): string {
        return new Intl.DateTimeFormat(this.currentLocale, {
            timeStyle: 'short',
            ...options,
        }).format(date);
    }

    /**
     * Format number according to current locale
     */
    formatNumber(number: number, options?: Intl.NumberFormatOptions): string {
        const metadata = LOCALE_INFO[this.currentLocale];
        return new Intl.NumberFormat(this.currentLocale, {
            ...metadata.numberFormat,
            ...options,
        }).format(number);
    }

    /**
     * Format currency according to current locale
     */
    formatCurrency(amount: number, currency: string, options?: Intl.NumberFormatOptions): string {
        return new Intl.NumberFormat(this.currentLocale, {
            style: 'currency',
            currency,
            ...options,
        }).format(amount);
    }

    /**
     * Format relative time (e.g., "2 hours ago")
     */
    formatRelativeTime(date: Date, options?: Intl.RelativeTimeFormatOptions): string {
        const rtf = new Intl.RelativeTimeFormat(this.currentLocale, {
            numeric: 'auto',
            ...options,
        });

        const now = new Date();
        const diffMs = date.getTime() - now.getTime();
        const diffSec = Math.round(diffMs / 1000);
        const diffMin = Math.round(diffSec / 60);
        const diffHour = Math.round(diffMin / 60);
        const diffDay = Math.round(diffHour / 24);

        if (Math.abs(diffSec) < 60) {
            return rtf.format(diffSec, 'second');
        } else if (Math.abs(diffMin) < 60) {
            return rtf.format(diffMin, 'minute');
        } else if (Math.abs(diffHour) < 24) {
            return rtf.format(diffHour, 'hour');
        } else {
            return rtf.format(diffDay, 'day');
        }
    }

    /**
     * Get available locales
     */
    getAvailableLocales(): Array<{ code: Locale; name: string; nativeName: string }> {
        return this.config.supportedLocales.map(locale => ({
            code: locale,
            name: LOCALE_INFO[locale].name,
            nativeName: LOCALE_INFO[locale].nativeName,
        }));
    }

    /**
     * Subscribe to locale changes
     */
    subscribe(callback: (locale: Locale) => void): () => void {
        this.listeners.add(callback);
        return () => {
            this.listeners.delete(callback);
        };
    }

    /**
     * Update localization configuration
     */
    updateConfig(updates: Partial<LocalizationConfig>): void {
        this.config = { ...this.config, ...updates };

        // Reload messages if custom messages were updated
        if (updates.messages) {
            this.loadedMessages.set(this.currentLocale, {
                ...LOCALE_INFO[this.currentLocale],
                ...this.config.messages,
            });
        }
    }

    // Private methods

    private getCurrentMessages(): LocaleMessages {
        return this.loadedMessages.get(this.currentLocale) || LOCALE_INFO[this.currentLocale];
    }

    private getNestedValue(obj: any, path: string): any {
        return path.split('.').reduce((current, key) => current?.[key], obj);
    }

    private interpolate(template: string, values?: InterpolationValues): string {
        if (!values) return template;

        return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            const value = values[key];
            if (value === undefined) return match;

            if (value instanceof Date) {
                return this.formatDate(value);
            }

            return String(value);
        });
    }

    private async loadLocaleMessages(locale: Locale): Promise<void> {
        try {
            // In a real implementation, you might load from a remote source
            const messages = LOCALE_INFO[locale] || LOCALE_INFO[this.config.fallbackLocale];

            this.loadedMessages.set(locale, {
                ...messages,
                ...this.config.messages,
            });
        } catch (error) {
            console.error(`Failed to load messages for locale ${locale}:`, error);
            // Fallback to default locale
            const fallbackMessages = LOCALE_INFO[this.config.fallbackLocale];
            this.loadedMessages.set(locale, fallbackMessages);
        }
    }

    private notifyListeners(): void {
        this.listeners.forEach(callback => callback(this.currentLocale));
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a localization manager instance
 */
export function createLocalizationManager(config?: Partial<LocalizationConfig>): LocalizationManager {
    return new LocalizationManager(config);
}

/**
 * Detect browser locale
 */
export function detectBrowserLocale(supportedLocales: Locale[]): Locale {
    if (typeof navigator === 'undefined') return 'en';

    const browserLocales = [
        navigator.language,
        ...(navigator.languages || []),
    ];

    for (const browserLocale of browserLocales) {
        // Extract language code (e.g., 'en' from 'en-US')
        const languageCode = browserLocale.split('-')[0] as Locale;

        if (supportedLocales.includes(languageCode)) {
            return languageCode;
        }
    }

    return 'en'; // Default fallback
}

/**
 * Get text direction for a locale
 */
export function getLocaleDirection(locale: Locale): LocaleDirection {
    return LOCALE_INFO[locale]?.direction || 'ltr';
}

/**
 * Check if locale is RTL
 */
export function isRTL(locale: Locale): boolean {
    return getLocaleDirection(locale) === 'rtl';
}

/**
 * Create namespace for translations (useful for component libraries)
 */
export function createTranslationNamespace(
    manager: LocalizationManager,
    namespace: string
) {
    return {
        t: (key: string, interpolation?: InterpolationValues) =>
            manager.t(`${namespace}.${key}` as TranslationKey, interpolation),
        plural: (key: string, options: PluralOptions) =>
            manager.plural(`${namespace}.${key}`, options),
    };
}

// ============================================================================
// Export localization utilities
// ============================================================================

export {
    DEFAULT_LOCALIZATION_CONFIG,
    DEFAULT_LOCALE_MESSAGES,
};