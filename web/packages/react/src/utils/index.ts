// Utility Functions Export
// Re-export all utility functions for easy consumption

export * from './api';
export * from './auth';
export * from './validation';
export * from './storage';
export * from './crypto';
export * from './url';
export * from './format';
export * from './error';
export * from './theme';

// Common utility functions
export const sleep = (ms: number): Promise<void> =>
    new Promise(resolve => setTimeout(resolve, ms));

export const debounce = <T extends (...args: any[]) => any>(
    func: T,
    wait: number,
    immediate?: boolean
): ((...args: Parameters<T>) => void) => {
    let timeout: NodeJS.Timeout | null = null;

    return (...args: Parameters<T>) => {
        const later = () => {
            timeout = null;
            if (!immediate) func(...args);
        };

        const callNow = immediate && !timeout;

        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(later, wait);

        if (callNow) func(...args);
    };
};

export const throttle = <T extends (...args: any[]) => any>(
    func: T,
    limit: number
): ((...args: Parameters<T>) => void) => {
    let inThrottle: boolean;

    return (...args: Parameters<T>) => {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
};

export const omit = <T extends Record<string, any>, K extends keyof T>(
    obj: T,
    keys: K[]
): Omit<T, K> => {
    const result = { ...obj };
    for (const key of keys) {
        delete result[key];
    }
    return result;
};

export const pick = <T extends Record<string, any>, K extends keyof T>(
    obj: T,
    keys: K[]
): Pick<T, K> => {
    const result = {} as Pick<T, K>;
    for (const key of keys) {
        if (key in obj) {
            result[key] = obj[key];
        }
    }
    return result;
};

export const isEmpty = (value: any): boolean => {
    if (value == null) return true;
    if (typeof value === 'string') return value.length === 0;
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === 'object') return Object.keys(value).length === 0;
    return false;
};

export const isEqual = (a: any, b: any): boolean => {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (typeof a !== typeof b) return false;

    if (Array.isArray(a)) {
        if (!Array.isArray(b) || a.length !== b.length) return false;
        return a.every((val, index) => isEqual(val, b[index]));
    }

    if (typeof a === 'object') {
        const keysA = Object.keys(a);
        const keysB = Object.keys(b);
        if (keysA.length !== keysB.length) return false;
        return keysA.every(key => isEqual(a[key], b[key]));
    }

    return false;
};

export const generateId = (): string => {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

export const clamp = (value: number, min: number, max: number): number => {
    return Math.min(Math.max(value, min), max);
};

export const arrayToObject = <T>(
    array: T[],
    keyFn: (item: T) => string
): Record<string, T> => {
    return array.reduce((acc, item) => {
        acc[keyFn(item)] = item;
        return acc;
    }, {} as Record<string, T>);
};

export const groupBy = <T>(
    array: T[],
    keyFn: (item: T) => string
): Record<string, T[]> => {
    return array.reduce((acc, item) => {
        const key = keyFn(item);
        if (!acc[key]) acc[key] = [];
        acc[key].push(item);
        return acc;
    }, {} as Record<string, T[]>);
};

export const unique = <T>(array: T[]): T[] => {
    return [...new Set(array)];
};

export const uniqueBy = <T>(array: T[], keyFn: (item: T) => any): T[] => {
    const seen = new Set();
    return array.filter(item => {
        const key = keyFn(item);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
};

export const capitalize = (str: string): string => {
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const camelCase = (str: string): string => {
    return str
        .replace(/(?:^\w|[A-Z]|\b\w)/g, (word, index) => {
            return index === 0 ? word.toLowerCase() : word.toUpperCase();
        })
        .replace(/\s+/g, '');
};

export const kebabCase = (str: string): string => {
    return str
        .replace(/([a-z])([A-Z])/g, '$1-$2')
        .replace(/[\s_]+/g, '-')
        .toLowerCase();
};

export const snakeCase = (str: string): string => {
    return str
        .replace(/([a-z])([A-Z])/g, '$1_$2')
        .replace(/[\s-]+/g, '_')
        .toLowerCase();
};

export const truncate = (str: string, length: number, suffix = '...'): string => {
    if (str.length <= length) return str;
    return str.substring(0, length - suffix.length) + suffix;
};

export const randomInt = (min: number, max: number): number => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
};

export const randomChoice = <T>(array: T[]): T => {
    return array[randomInt(0, array.length - 1)];
};

export const retry = async <T>(
    fn: () => Promise<T>,
    maxAttempts: number = 3,
    delay: number = 1000
): Promise<T> => {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error as Error;
            if (attempt === maxAttempts) break;
            await sleep(delay * attempt);
        }
    }

    throw lastError!;
};

export const withTimeout = <T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorMessage = 'Operation timed out'
): Promise<T> => {
    return Promise.race([
        promise,
        new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
        ),
    ]);
};

export const memoize = <T extends (...args: any[]) => any>(
    fn: T,
    keyFn?: (...args: Parameters<T>) => string
): T => {
    const cache = new Map();

    return ((...args: Parameters<T>) => {
        const key = keyFn ? keyFn(...args) : JSON.stringify(args);

        if (cache.has(key)) {
            return cache.get(key);
        }

        const result = fn(...args);
        cache.set(key, result);
        return result;
    }) as T;
};