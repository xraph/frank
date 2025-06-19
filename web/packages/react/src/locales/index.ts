export * from './types';
export * from './en';
export * from './es';
export * from './fr';
export * from './de';
export * from './pt';
export * from './it';
export * from './ja';
export * from './ko';
export * from './zh';

import type {Locale, LocaleDirection, LocaleMessages} from './types';
import {en} from './en';
import {es} from './es';
import {fr} from './fr';
import {de} from './de';
import {pt} from './pt';
import {it} from './it';
import {ja} from './ja';
import {ko} from './ko';
import {zh} from './zh';

export type {Locale, LocaleMessages};

// Available locales
export const AVAILABLE_LOCALES: Locale[] = [
    'en',
    'es',
    'fr',
    'de',
    'pt',
    'it',
    'ja',
    'ko',
    'zh',
];

// Locale registry
export const LOCALE_REGISTRY: Record<Locale, LocaleMessages> = {
    en,
    es,
    fr,
    de,
    pt,
    it,
    ja,
    ko,
    zh,
};

// Default locale
export const DEFAULT_LOCALE: Locale = 'en';

// Locale information
export const LOCALE_INFO: Record<Locale, {
    name: string;
    nativeName: string;
    region: string;
    direction: LocaleDirection;
    dateFormat: string;
    timeFormat: string;
    numberFormat: Intl.NumberFormatOptions;
    pluralRules: Intl.PluralRules;
}> = {
    en: {
        name: 'English',
        nativeName: 'English',
        region: 'US',
        direction: 'ltr',
        dateFormat: 'MM/dd/yyyy',
        timeFormat: 'h:mm a',
        numberFormat: {
            style: 'decimal',
            currency: 'USD',
        },
        pluralRules: new Intl.PluralRules('en'),
    },
    es: {
        name: 'Spanish',
        nativeName: 'Español',
        region: 'ES',
        direction: 'ltr',
        dateFormat: 'dd/MM/yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'EUR',
        },
        pluralRules: new Intl.PluralRules('es'),
    },
    fr: {
        name: 'French',
        nativeName: 'Français',
        region: 'FR',
        direction: 'ltr',
        dateFormat: 'dd/MM/yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'EUR',
        },
        pluralRules: new Intl.PluralRules('fr'),
    },
    de: {
        name: 'German',
        nativeName: 'Deutsch',
        region: 'DE',
        direction: 'ltr',
        dateFormat: 'dd.MM.yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'EUR',
        },
        pluralRules: new Intl.PluralRules('de'),
    },
    pt: {
        name: 'Portuguese',
        nativeName: 'Português',
        region: 'PT',
        direction: 'ltr',
        dateFormat: 'dd/MM/yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'EUR',
        },
        pluralRules: new Intl.PluralRules('pt'),
    },
    it: {
        name: 'Italian',
        nativeName: 'Italiano',
        region: 'IT',
        direction: 'ltr',
        dateFormat: 'dd/MM/yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'EUR',
        },
        pluralRules: new Intl.PluralRules('it'),
    },
    ja: {
        name: 'Japanese',
        nativeName: '日本語',
        region: 'JP',
        direction: 'ltr',
        dateFormat: 'yyyy/MM/dd',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'JPY',
        },
        pluralRules: new Intl.PluralRules('pt'),
    },
    ko: {
        name: 'Korean',
        nativeName: '한국어',
        region: 'KR',
        direction: 'ltr',
        dateFormat: 'yyyy. MM. dd.',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'KRW',
        },
        pluralRules: new Intl.PluralRules('ko'),
    },
    zh: {
        name: 'Chinese',
        nativeName: '中文',
        region: 'CN',
        direction: 'ltr',
        dateFormat: 'yyyy/MM/dd',
        timeFormat: 'HH:mm',
        numberFormat: {
            style: 'decimal',
            currency: 'CNY',
        },
        pluralRules: new Intl.PluralRules('zh'),
    },
};

// Utility functions
export const getLocale = (locale: Locale): LocaleMessages => {
    return LOCALE_REGISTRY[locale] || LOCALE_REGISTRY[DEFAULT_LOCALE];
};

export const getLocaleInfo = (locale: Locale) => {
    return LOCALE_INFO[locale] || LOCALE_INFO[DEFAULT_LOCALE];
};

export const isValidLocale = (locale: string): locale is Locale => {
    return AVAILABLE_LOCALES.includes(locale as Locale);
};

export const detectBrowserLocale = (): Locale => {
    if (typeof window === 'undefined') return DEFAULT_LOCALE;

    const browserLocale = navigator.language.toLowerCase();

    // Check for exact match first
    if (isValidLocale(browserLocale)) {
        return browserLocale;
    }

    // Check for language code match (e.g., 'en-US' -> 'en')
    const languageCode = browserLocale.split('-')[0];
    if (isValidLocale(languageCode)) {
        return languageCode;
    }

    return DEFAULT_LOCALE;
};

export const formatMessage = (
    message: string,
    values: Record<string, string | number> = {}
): string => {
    return message.replace(/\{(\w+)\}/g, (match, key) => {
        return values[key]?.toString() || match;
    });
};

export const pluralize = (
    count: number,
    messages: {
        zero?: string;
        one: string;
        other: string;
    },
    locale: Locale = DEFAULT_LOCALE
): string => {
    if (count === 0 && messages.zero) {
        return messages.zero;
    }

    if (count === 1) {
        return messages.one;
    }

    return messages.other;
};

// Translation helper function
export const t = (
    locale: Locale,
    key: string,
    values?: Record<string, string | number>
): string => {
    const messages = getLocale(locale);
    const keys = key.split('.');

    let message: any = messages;
    for (const k of keys) {
        message = message?.[k];
        if (message === undefined) break;
    }

    if (typeof message !== 'string') {
        return key; // Return key if translation not found
    }

    return values ? formatMessage(message, values) : message;
};

// RTL support
export const isRTL = (locale: Locale): boolean => {
    return getLocaleInfo(locale).direction === 'rtl';
};

// Number formatting
export const formatNumber = (
    value: number,
    locale: Locale,
    options?: Intl.NumberFormatOptions
): string => {
    try {
        const localeInfo = getLocaleInfo(locale);
        const localeString = `${locale}-${localeInfo.region}`;
        return new Intl.NumberFormat(localeString, options).format(value);
    } catch {
        return value.toString();
    }
};

// Date formatting
export const formatDate = (
    date: Date,
    locale: Locale,
    options?: Intl.DateTimeFormatOptions
): string => {
    try {
        const localeInfo = getLocaleInfo(locale);
        const localeString = `${locale}-${localeInfo.region}`;
        return new Intl.DateTimeFormat(localeString, options).format(date);
    } catch {
        return date.toISOString();
    }
};

// Relative time formatting
export const formatRelativeTime = (
    date: Date,
    locale: Locale
): string => {
    try {
        const now = new Date();
        const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

        const localeInfo = getLocaleInfo(locale);
        const localeString = `${locale}-${localeInfo.region}`;

        if (typeof Intl.RelativeTimeFormat !== 'undefined') {
            const rtf = new Intl.RelativeTimeFormat(localeString, { numeric: 'auto' });

            if (diffInSeconds < 60) {
                return rtf.format(-diffInSeconds, 'second');
            } else if (diffInSeconds < 3600) {
                return rtf.format(-Math.floor(diffInSeconds / 60), 'minute');
            } else if (diffInSeconds < 86400) {
                return rtf.format(-Math.floor(diffInSeconds / 3600), 'hour');
            } else {
                return rtf.format(-Math.floor(diffInSeconds / 86400), 'day');
            }
        }

        // Fallback for browsers without RelativeTimeFormat
        const messages = getLocale(locale);

        if (diffInSeconds < 60) {
            return messages.common.timeAgo.justNow;
        } else if (diffInSeconds < 3600) {
            const minutes = Math.floor(diffInSeconds / 60);
            return formatMessage(messages.common.timeAgo.minutesAgo, { count: minutes });
        } else if (diffInSeconds < 86400) {
            const hours = Math.floor(diffInSeconds / 3600);
            return formatMessage(messages.common.timeAgo.hoursAgo, { count: hours });
        } else {
            const days = Math.floor(diffInSeconds / 86400);
            return formatMessage(messages.common.timeAgo.daysAgo, { count: days });
        }
    } catch {
        return date.toISOString();
    }
};

// Validation message formatting
export const getValidationMessage = (
    locale: Locale,
    rule: string,
    field: string,
    value?: any
): string => {
    const messages = getLocale(locale);
    const validationMessages = messages.validation;

    const fieldName = field.charAt(0).toUpperCase() + field.slice(1);

    switch (rule) {
        case 'required':
            return formatMessage(validationMessages.required, { field: fieldName });
        case 'email':
            return formatMessage(validationMessages.email, { field: fieldName });
        case 'minLength':
            return formatMessage(validationMessages.minLength, { field: fieldName, min: value });
        case 'maxLength':
            return formatMessage(validationMessages.maxLength, { field: fieldName, max: value });
        case 'pattern':
            return formatMessage(validationMessages.pattern, { field: fieldName });
        case 'min':
            return formatMessage(validationMessages.min, { field: fieldName, min: value });
        case 'max':
            return formatMessage(validationMessages.max, { field: fieldName, max: value });
        default:
            return formatMessage(validationMessages.invalid, { field: fieldName });
    }
};

// Locale persistence
export const saveLocaleToStorage = (locale: Locale): void => {
    if (typeof window === 'undefined') return;

    try {
        localStorage.setItem('frank-auth-locale', locale);
    } catch {
        // Ignore storage errors
    }
};

export const loadLocaleFromStorage = (): Locale | null => {
    if (typeof window === 'undefined') return null;

    try {
        const saved = localStorage.getItem('frank-auth-locale');
        return saved && isValidLocale(saved) ? saved : null;
    } catch {
        return null;
    }
};

// Auto-detect locale with fallback
export const detectLocale = (): Locale => {
    // Try to load from storage first
    const savedLocale = loadLocaleFromStorage();
    if (savedLocale) return savedLocale;

    // Try to detect from browser
    return detectBrowserLocale();
};