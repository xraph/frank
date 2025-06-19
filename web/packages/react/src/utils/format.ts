import type {XID} from '../types';

// Date formatting utilities
export const formatDate = (
    date: Date | string | number,
    options: Intl.DateTimeFormatOptions = {},
    locale: string = 'en'
): string => {
    try {
        const dateObj = typeof date === 'string' || typeof date === 'number'
            ? new Date(date)
            : date;

        if (isNaN(dateObj.getTime())) {
            return 'Invalid Date';
        }

        const defaultOptions: Intl.DateTimeFormatOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            ...options,
        };

        return new Intl.DateTimeFormat(locale, defaultOptions).format(dateObj);
    } catch {
        return 'Invalid Date';
    }
};

export const formatDateTime = (
    date: Date | string | number,
    options: Intl.DateTimeFormatOptions = {},
    locale: string = 'en'
): string => {
    const defaultOptions: Intl.DateTimeFormatOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        ...options,
    };

    return formatDate(date, defaultOptions, locale);
};

export const formatTime = (
    date: Date | string | number,
    options: Intl.DateTimeFormatOptions = {},
    locale: string = 'en'
): string => {
    const defaultOptions: Intl.DateTimeFormatOptions = {
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        ...options,
    };

    return formatDate(date, defaultOptions, locale);
};

export const formatRelativeTime = (
    date: Date | string | number,
    locale: string = 'en'
): string => {
    try {
        const dateObj = typeof date === 'string' || typeof date === 'number'
            ? new Date(date)
            : date;

        if (isNaN(dateObj.getTime())) {
            return 'Invalid Date';
        }

        const now = new Date();
        const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);

        if (diffInSeconds < 60) {
            return 'just now';
        }

        const diffInMinutes = Math.floor(diffInSeconds / 60);
        if (diffInMinutes < 60) {
            return `${diffInMinutes} minute${diffInMinutes === 1 ? '' : 's'} ago`;
        }

        const diffInHours = Math.floor(diffInMinutes / 60);
        if (diffInHours < 24) {
            return `${diffInHours} hour${diffInHours === 1 ? '' : 's'} ago`;
        }

        const diffInDays = Math.floor(diffInHours / 24);
        if (diffInDays < 7) {
            return `${diffInDays} day${diffInDays === 1 ? '' : 's'} ago`;
        }

        const diffInWeeks = Math.floor(diffInDays / 7);
        if (diffInWeeks < 4) {
            return `${diffInWeeks} week${diffInWeeks === 1 ? '' : 's'} ago`;
        }

        const diffInMonths = Math.floor(diffInDays / 30);
        if (diffInMonths < 12) {
            return `${diffInMonths} month${diffInMonths === 1 ? '' : 's'} ago`;
        }

        const diffInYears = Math.floor(diffInDays / 365);
        return `${diffInYears} year${diffInYears === 1 ? '' : 's'} ago`;
    } catch {
        return 'Invalid Date';
    }
};

export const formatDuration = (milliseconds: number): string => {
    if (milliseconds < 0) return '0s';

    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
        return `${days}d ${hours % 24}h`;
    }

    if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
    }

    if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    }

    return `${seconds}s`;
};

export const formatTimeAgo = (date: Date | string | number): string => {
    return formatRelativeTime(date);
};

// Number formatting utilities
export const formatNumber = (
    value: number,
    options: Intl.NumberFormatOptions = {},
    locale: string = 'en'
): string => {
    try {
        return new Intl.NumberFormat(locale, options).format(value);
    } catch {
        return value.toString();
    }
};

export const formatCurrency = (
    amount: number,
    currency: string = 'USD',
    locale: string = 'en'
): string => {
    return formatNumber(amount, {
        style: 'currency',
        currency,
    }, locale);
};

export const formatPercentage = (
    value: number,
    decimals: number = 1,
    locale: string = 'en'
): string => {
    return formatNumber(value / 100, {
        style: 'percent',
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals,
    }, locale);
};

export const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

export const formatCompactNumber = (
    value: number,
    locale: string = 'en'
): string => {
    if (Math.abs(value) < 1000) {
        return value.toString();
    }

    try {
        return new Intl.NumberFormat(locale, {
            notation: 'compact',
            compactDisplay: 'short',
        }).format(value);
    } catch {
        // Fallback for browsers that don't support compact notation
        const k = 1000;
        const sizes = ['', 'K', 'M', 'B', 'T'];
        const i = Math.floor(Math.log(Math.abs(value)) / Math.log(k));

        return `${parseFloat((value / Math.pow(k, i)).toFixed(1))}${sizes[i]}`;
    }
};

// String formatting utilities
export const formatName = (firstName?: string, lastName?: string): string => {
    const parts = [firstName, lastName].filter(Boolean);
    return parts.join(' ');
};

export const formatInitials = (name: string): string => {
    return name
        .split(' ')
        .map(word => word.charAt(0).toUpperCase())
        .slice(0, 2)
        .join('');
};

export const formatDisplayName = (user: {
    firstName?: string;
    lastName?: string;
    username?: string;
    emailAddress?: string;
}): string => {
    if (user.firstName || user.lastName) {
        return formatName(user.firstName, user.lastName);
    }

    if (user.username) {
        return user.username;
    }

    if (user.emailAddress) {
        return user.emailAddress.split('@')[0];
    }

    return 'Unknown User';
};

export const formatEmail = (email: string): string => {
    return email.trim().toLowerCase();
};

export const formatPhoneNumber = (
    phone: string,
    format: 'international' | 'national' | 'e164' = 'national'
): string => {
    // Remove all non-digit characters except +
    const cleaned = phone.replace(/[^\d+]/g, '');

    // Basic formatting for US numbers (extend as needed)
    if (cleaned.length === 10) {
        // US domestic number
        const match = cleaned.match(/^(\d{3})(\d{3})(\d{4})$/);
        if (match) {
            switch (format) {
                case 'international':
                    return `+1 ${match[1]} ${match[2]} ${match[3]}`;
                case 'e164':
                    return `+1${cleaned}`;
                case 'national':
                default:
                    return `(${match[1]}) ${match[2]}-${match[3]}`;
            }
        }
    }

    if (cleaned.length === 11 && cleaned.startsWith('1')) {
        // US number with country code
        const number = cleaned.substring(1);
        const match = number.match(/^(\d{3})(\d{3})(\d{4})$/);
        if (match) {
            switch (format) {
                case 'international':
                    return `+1 ${match[1]} ${match[2]} ${match[3]}`;
                case 'e164':
                    return `+${cleaned}`;
                case 'national':
                default:
                    return `(${match[1]}) ${match[2]}-${match[3]}`;
            }
        }
    }

    // For international numbers or unrecognized formats
    if (cleaned.startsWith('+')) {
        return cleaned;
    }

    return phone; // Return original if we can't format it
};

export const maskEmail = (email: string): string => {
    const [localPart, domain] = email.split('@');
    if (!domain) return email;

    if (localPart.length <= 3) {
        return `${localPart[0]}***@${domain}`;
    }

    const firstChar = localPart[0];
    const lastChar = localPart[localPart.length - 1];
    const middleLength = Math.max(3, localPart.length - 2);

    return `${firstChar}${'*'.repeat(middleLength)}${lastChar}@${domain}`;
};

export const maskPhoneNumber = (phone: string): string => {
    const cleaned = phone.replace(/[^\d]/g, '');

    if (cleaned.length >= 10) {
        const lastFour = cleaned.slice(-4);
        const masked = '*'.repeat(cleaned.length - 4);
        return `${masked}${lastFour}`;
    }

    return phone;
};

export const truncateText = (
    text: string,
    maxLength: number,
    suffix: string = '...'
): string => {
    if (text.length <= maxLength) return text;

    const truncated = text.substring(0, maxLength - suffix.length);
    return truncated + suffix;
};

export const truncateMiddle = (
    text: string,
    maxLength: number,
    separator: string = '...'
): string => {
    if (text.length <= maxLength) return text;

    const sepLen = separator.length;
    const charsToShow = maxLength - sepLen;
    const frontChars = Math.ceil(charsToShow / 2);
    const backChars = Math.floor(charsToShow / 2);

    return text.substring(0, frontChars) +
        separator +
        text.substring(text.length - backChars);
};

export const formatTextCase = (
    text: string,
    format: 'camel' | 'pascal' | 'snake' | 'kebab' | 'sentence' | 'title' | 'upper' | 'lower'
): string => {
    switch (format) {
        case 'camel':
            return text.replace(/(?:^\w|[A-Z]|\b\w)/g, (word, index) => {
                return index === 0 ? word.toLowerCase() : word.toUpperCase();
            }).replace(/\s+/g, '');

        case 'pascal':
            return text.replace(/(?:^\w|[A-Z]|\b\w)/g, (word) => {
                return word.toUpperCase();
            }).replace(/\s+/g, '');

        case 'snake':
            return text.replace(/\W+/g, ' ')
                .split(/ |\B(?=[A-Z])/)
                .map(word => word.toLowerCase())
                .join('_');

        case 'kebab':
            return text.replace(/\W+/g, ' ')
                .split(/ |\B(?=[A-Z])/)
                .map(word => word.toLowerCase())
                .join('-');

        case 'sentence':
            return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();

        case 'title':
            return text.replace(/\w\S*/g, (txt) => {
                return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
            });

        case 'upper':
            return text.toUpperCase();

        case 'lower':
            return text.toLowerCase();

        default:
            return text;
    }
};

// ID and token formatting utilities
export const formatId = (id: XID): string => {
    // Truncate long IDs for display
    if (id.length > 12) {
        return truncateMiddle(id, 12);
    }
    return id;
};

export const formatTokenPreview = (token: string): string => {
    if (token.length <= 8) return token;

    const start = token.substring(0, 4);
    const end = token.substring(token.length - 4);
    return `${start}...${end}`;
};

// Address formatting utilities
export const formatAddress = (address: {
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
}): string => {
    const parts = [
        address.street,
        address.city,
        address.state && address.postalCode
            ? `${address.state} ${address.postalCode}`
            : address.state || address.postalCode,
        address.country,
    ].filter(Boolean);

    return parts.join(', ');
};

// List formatting utilities
export const formatList = (
    items: string[],
    options: {
        style?: 'long' | 'short' | 'narrow';
        type?: 'conjunction' | 'disjunction';
        locale?: string;
    } = {}
): string => {
    const { style = 'long', type = 'conjunction', locale = 'en' } = options;

    if (items.length === 0) return '';
    if (items.length === 1) return items[0];

    try {
        return new Intl.DateTimeFormat(locale, { style, type }).format(items);
    } catch {
        // Fallback for browsers that don't support Intl.ListFormat
        if (items.length === 2) {
            return `${items[0]} ${type === 'conjunction' ? 'and' : 'or'} ${items[1]}`;
        }

        const lastItem = items[items.length - 1];
        const otherItems = items.slice(0, -1);
        const connector = type === 'conjunction' ? 'and' : 'or';

        return `${otherItems.join(', ')}, ${connector} ${lastItem}`;
    }
};

// JSON formatting utilities
export const formatJSON = (
    obj: any,
    indent: number = 2,
    maxDepth: number = 10
): string => {
    try {
        return JSON.stringify(obj, null, indent);
    } catch {
        return '[Circular Reference]';
    }
};

export const formatJSONCompact = (obj: any): string => {
    try {
        return JSON.stringify(obj);
    } catch {
        return '[Circular Reference]';
    }
};

// URL formatting utilities
export const formatDomain = (url: string): string => {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return url;
    }
};

export const formatURL = (url: string): string => {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return `https://${url}`;
    }
    return url;
};

// Color formatting utilities
export const formatHexColor = (color: string): string => {
    const hex = color.replace('#', '');

    // Expand short hex to full hex
    if (hex.length === 3) {
        return `#${hex.split('').map(char => char + char).join('')}`;
    }

    if (hex.length === 6) {
        return `#${hex}`;
    }

    return color;
};

export const formatRGBColor = (r: number, g: number, b: number): string => {
    return `rgb(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)})`;
};

export const formatRGBAColor = (r: number, g: number, b: number, a: number): string => {
    return `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${a})`;
};

// Validation message formatting
export const formatValidationError = (
    field: string,
    rule: string,
    value?: any
): string => {
    const fieldName = formatTextCase(field, 'sentence');

    switch (rule) {
        case 'required':
            return `${fieldName} is required`;
        case 'email':
            return `${fieldName} must be a valid email address`;
        case 'minLength':
            return `${fieldName} must be at least ${value} characters`;
        case 'maxLength':
            return `${fieldName} must be no more than ${value} characters`;
        case 'pattern':
            return `${fieldName} format is invalid`;
        case 'number':
            return `${fieldName} must be a number`;
        case 'min':
            return `${fieldName} must be at least ${value}`;
        case 'max':
            return `${fieldName} must be no more than ${value}`;
        default:
            return `${fieldName} is invalid`;
    }
};

export function getTitleAlignment(align: 'left' | 'center' | 'right'): string {
    switch (align) {
        case 'left':
            return 'text-left';
        case 'center':
            return 'text-center';
        case 'right':
            return 'text-right';
        default:
            return 'text-left';
    }
}

// Export utilities object
export const FormatUtils = {
    // Date and time
    formatDate,
    formatDateTime,
    formatTime,
    formatRelativeTime,
    formatDuration,
    formatTimeAgo,

    // Numbers
    formatNumber,
    formatCurrency,
    formatPercentage,
    formatFileSize,
    formatCompactNumber,

    // Strings
    formatName,
    formatInitials,
    formatDisplayName,
    formatEmail,
    formatPhoneNumber,
    maskEmail,
    maskPhoneNumber,
    truncateText,
    truncateMiddle,
    formatTextCase,

    // IDs and tokens
    formatId,
    formatTokenPreview,

    // Addresses
    formatAddress,

    // Lists
    formatList,

    // JSON
    formatJSON,
    formatJSONCompact,

    // URLs
    formatDomain,
    formatURL,

    // Colors
    formatHexColor,
    formatRGBColor,
    formatRGBAColor,

    // Validation
    formatValidationError,
};