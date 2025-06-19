import type {XID} from '../types';

// URL parsing and manipulation utilities
export interface ParsedURL {
    protocol: string;
    hostname: string;
    port?: string;
    pathname: string;
    search: string;
    hash: string;
    query: Record<string, string | string[]>;
    origin: string;
    href: string;
}

export const parseURL = (url: string): ParsedURL | null => {
    try {
        const urlObj = new URL(url);
        const query = parseQueryString(urlObj.search);

        return {
            protocol: urlObj.protocol,
            hostname: urlObj.hostname,
            port: urlObj.port || undefined,
            pathname: urlObj.pathname,
            search: urlObj.search,
            hash: urlObj.hash,
            query,
            origin: urlObj.origin,
            href: urlObj.href,
        };
    } catch {
        return null;
    }
};

export const buildURL = (
    base: string,
    params?: Record<string, string | number | boolean | undefined | null>
): string => {
    try {
        const url = new URL(base);

        if (params) {
            for (const [key, value] of Object.entries(params)) {
                if (value !== undefined && value !== null) {
                    url.searchParams.set(key, String(value));
                }
            }
        }

        return url.toString();
    } catch {
        return base;
    }
};

export const addQueryParams = (
    url: string,
    params: Record<string, string | number | boolean | undefined | null>
): string => {
    return buildURL(url, params);
};

export const parseQueryString = (queryString: string): Record<string, string | string[]> => {
    const params = new URLSearchParams(queryString);
    const result: Record<string, string | string[]> = {};

    for (const [key, value] of params.entries()) {
        if (key in result) {
            if (Array.isArray(result[key])) {
                (result[key] as string[]).push(value);
            } else {
                result[key] = [result[key] as string, value];
            }
        } else {
            result[key] = value;
        }
    }

    return result;
};

export const buildQueryString = (params: Record<string, any>): string => {
    const searchParams = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
            if (Array.isArray(value)) {
                for (const item of value) {
                    searchParams.append(key, String(item));
                }
            } else {
                searchParams.set(key, String(value));
            }
        }
    }

    return searchParams.toString();
};

export const removeQueryParams = (url: string, keys: string[]): string => {
    try {
        const urlObj = new URL(url);

        for (const key of keys) {
            urlObj.searchParams.delete(key);
        }

        return urlObj.toString();
    } catch {
        return url;
    }
};

export const getQueryParam = (url: string, key: string): string | null => {
    try {
        const urlObj = new URL(url);
        return urlObj.searchParams.get(key);
    } catch {
        return null;
    }
};

export const hasQueryParam = (url: string, key: string): boolean => {
    try {
        const urlObj = new URL(url);
        return urlObj.searchParams.has(key);
    } catch {
        return false;
    }
};

// Auth-specific URL utilities
export const buildAuthURL = (
    baseUrl: string,
    type: 'signin' | 'signup' | 'reset' | 'verify',
    params?: {
        organizationId?: XID;
        redirectUrl?: string;
        invitationToken?: string;
        emailAddress?: string;
        mode?: string;
        [key: string]: any;
    }
): string => {
    const paths = {
        signin: '/sign-in',
        signup: '/sign-up',
        reset: '/reset-password',
        verify: '/verify',
    };

    const url = new URL(paths[type], baseUrl);

    if (params) {
        for (const [key, value] of Object.entries(params)) {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, String(value));
            }
        }
    }

    return url.toString();
};

export const buildOAuthURL = (
    provider: string,
    clientId: string,
    redirectUri: string,
    options?: {
        state?: string;
        scope?: string | string[];
        responseType?: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
        organizationId?: XID;
        [key: string]: any;
    }
): string => {
    const baseUrls: Record<string, string> = {
        google: 'https://accounts.google.com/o/oauth2/v2/auth',
        github: 'https://github.com/login/oauth/authorize',
        microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        facebook: 'https://www.facebook.com/v18.0/dialog/oauth',
        apple: 'https://appleid.apple.com/auth/authorize',
        twitter: 'https://twitter.com/i/oauth2/authorize',
        linkedin: 'https://www.linkedin.com/oauth/v2/authorization',
        discord: 'https://discord.com/api/oauth2/authorize',
        slack: 'https://slack.com/oauth/v2/authorize',
        spotify: 'https://accounts.spotify.com/authorize',
    };

    const baseUrl = baseUrls[provider.toLowerCase()];
    if (!baseUrl) {
        throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    const params: Record<string, string> = {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: options?.responseType || 'code',
    };

    if (options?.state) {
        params.state = options.state;
    }

    if (options?.scope) {
        params.scope = Array.isArray(options.scope)
            ? options.scope.join(' ')
            : options.scope;
    }

    if (options?.codeChallenge && options?.codeChallengeMethod) {
        params.code_challenge = options.codeChallenge;
        params.code_challenge_method = options.codeChallengeMethod;
    }

    // Add provider-specific parameters
    if (options?.organizationId) {
        params.organization_id = options.organizationId;
    }

    // Add any additional parameters
    if (options) {
        for (const [key, value] of Object.entries(options)) {
            if (value !== undefined && value !== null &&
                !['state', 'scope', 'responseType', 'codeChallenge', 'codeChallengeMethod', 'organizationId'].includes(key)) {
                params[key] = String(value);
            }
        }
    }

    return buildURL(baseUrl, params);
};

export const parseOAuthCallback = (url: string): {
    code?: string;
    state?: string;
    error?: string;
    errorDescription?: string;
    organizationId?: XID;
} => {
    const parsed = parseURL(url);
    if (!parsed) return {};

    return {
        code: typeof parsed.query.code === 'string' ? parsed.query.code : undefined,
        state: typeof parsed.query.state === 'string' ? parsed.query.state : undefined,
        error: typeof parsed.query.error === 'string' ? parsed.query.error : undefined,
        errorDescription: typeof parsed.query.error_description === 'string'
            ? parsed.query.error_description
            : undefined,
        organizationId: typeof parsed.query.organization_id === 'string'
            ? parsed.query.organization_id as XID
            : undefined,
    };
};

export const buildMagicLinkURL = (
    baseUrl: string,
    token: string,
    options?: {
        redirectUrl?: string;
        organizationId?: XID;
        mode?: string;
    }
): string => {
    const url = new URL('/auth/magic-link', baseUrl);
    url.searchParams.set('token', token);

    if (options?.redirectUrl) {
        url.searchParams.set('redirect_url', options.redirectUrl);
    }

    if (options?.organizationId) {
        url.searchParams.set('organization_id', options.organizationId);
    }

    if (options?.mode) {
        url.searchParams.set('mode', options.mode);
    }

    return url.toString();
};

export const buildVerificationURL = (
    baseUrl: string,
    token: string,
    type: 'email' | 'phone',
    options?: {
        redirectUrl?: string;
        organizationId?: XID;
    }
): string => {
    const url = new URL(`/auth/verify-${type}`, baseUrl);
    url.searchParams.set('token', token);

    if (options?.redirectUrl) {
        url.searchParams.set('redirect_url', options.redirectUrl);
    }

    if (options?.organizationId) {
        url.searchParams.set('organization_id', options.organizationId);
    }

    return url.toString();
};

export const buildPasswordResetURL = (
    baseUrl: string,
    token: string,
    options?: {
        redirectUrl?: string;
        organizationId?: XID;
    }
): string => {
    const url = new URL('/auth/reset-password', baseUrl);
    url.searchParams.set('token', token);

    if (options?.redirectUrl) {
        url.searchParams.set('redirect_url', options.redirectUrl);
    }

    if (options?.organizationId) {
        url.searchParams.set('organization_id', options.organizationId);
    }

    return url.toString();
};

export const buildInvitationURL = (
    baseUrl: string,
    token: string,
    options?: {
        redirectUrl?: string;
        organizationId?: XID;
    }
): string => {
    const url = new URL('/auth/invitation', baseUrl);
    url.searchParams.set('token', token);

    if (options?.redirectUrl) {
        url.searchParams.set('redirect_url', options.redirectUrl);
    }

    if (options?.organizationId) {
        url.searchParams.set('organization_id', options.organizationId);
    }

    return url.toString();
};

// URL validation utilities
export const isValidURL = (url: string): boolean => {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
};

export const isValidHttpURL = (url: string): boolean => {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
        return false;
    }
};

export const isValidHttpsURL = (url: string): boolean => {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'https:';
    } catch {
        return false;
    }
};

export const isDomainAllowed = (url: string, allowedDomains: string[]): boolean => {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();

        return allowedDomains.some(domain => {
            const normalizedDomain = domain.toLowerCase();
            return hostname === normalizedDomain ||
                hostname.endsWith(`.${normalizedDomain}`);
        });
    } catch {
        return false;
    }
};

export const isSubdomain = (url: string, parentDomain: string): boolean => {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        const parent = parentDomain.toLowerCase();

        return hostname === parent || hostname.endsWith(`.${parent}`);
    } catch {
        return false;
    }
};

// URL manipulation utilities
export const extractDomain = (url: string): string | null => {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return null;
    }
};

export const extractRootDomain = (url: string): string | null => {
    const domain = extractDomain(url);
    if (!domain) return null;

    const parts = domain.split('.');
    if (parts.length >= 2) {
        return parts.slice(-2).join('.');
    }

    return domain;
};

export const normalizeURL = (url: string): string => {
    try {
        const urlObj = new URL(url);

        // Remove default ports
        if ((urlObj.protocol === 'http:' && urlObj.port === '80') ||
            (urlObj.protocol === 'https:' && urlObj.port === '443')) {
            urlObj.port = '';
        }

        // Remove trailing slash from pathname
        if (urlObj.pathname !== '/' && urlObj.pathname.endsWith('/')) {
            urlObj.pathname = urlObj.pathname.slice(0, -1);
        }

        // Sort query parameters
        const params = Array.from(urlObj.searchParams.entries())
            .sort(([a], [b]) => a.localeCompare(b));

        urlObj.search = '';
        for (const [key, value] of params) {
            urlObj.searchParams.append(key, value);
        }

        return urlObj.toString();
    } catch {
        return url;
    }
};

export const joinURL = (...parts: string[]): string => {
    if (parts.length === 0) return '';

    const [base, ...rest] = parts;
    let result = base.replace(/\/+$/, '');

    for (const part of rest) {
        const cleanPart = part.replace(/^\/+|\/+$/g, '');
        if (cleanPart) {
            result += '/' + cleanPart;
        }
    }

    return result;
};

export const getURLPath = (url: string): string => {
    try {
        const urlObj = new URL(url);
        return urlObj.pathname;
    } catch {
        return '';
    }
};

export const getURLParams = (url: string): Record<string, string | string[]> => {
    try {
        const urlObj = new URL(url);
        return parseQueryString(urlObj.search);
    } catch {
        return {};
    }
};

// Redirect utilities
export const isSafeRedirectURL = (
    url: string,
    allowedDomains: string[],
    allowRelative: boolean = true
): boolean => {
    if (!url) return false;

    // Allow relative URLs if enabled
    if (allowRelative && url.startsWith('/')) {
        return true;
    }

    // Check if it's a valid absolute URL
    if (!isValidHttpURL(url)) {
        return false;
    }

    // Check if domain is allowed
    return isDomainAllowed(url, allowedDomains);
};

export const sanitizeRedirectURL = (
    url: string,
    allowedDomains: string[],
    fallbackURL: string = '/'
): string => {
    if (isSafeRedirectURL(url, allowedDomains)) {
        return url;
    }

    return fallbackURL;
};

// Browser utilities
export const getCurrentURL = (): string => {
    return typeof window !== 'undefined' ? window.location.href : '';
};

export const getCurrentPath = (): string => {
    return typeof window !== 'undefined' ? window.location.pathname : '';
};

export const getCurrentDomain = (): string => {
    return typeof window !== 'undefined' ? window.location.hostname : '';
};

export const getCurrentOrigin = (): string => {
    return typeof window !== 'undefined' ? window.location.origin : '';
};

export const getCurrentParams = (): Record<string, string | string[]> => {
    return typeof window !== 'undefined'
        ? parseQueryString(window.location.search)
        : {};
};

export const redirectTo = (url: string, replace: boolean = false): void => {
    if (typeof window !== 'undefined') {
        if (replace) {
            window.location.replace(url);
        } else {
            window.location.href = url;
        }
    }
};

export const openInNewTab = (url: string): void => {
    if (typeof window !== 'undefined') {
        window.open(url, '_blank', 'noopener,noreferrer');
    }
};

// Hash utilities
export const getHash = (): string => {
    return typeof window !== 'undefined' ? window.location.hash : '';
};

export const setHash = (hash: string): void => {
    if (typeof window !== 'undefined') {
        window.location.hash = hash;
    }
};

export const removeHash = (): void => {
    if (typeof window !== 'undefined') {
        window.history.replaceState('', document.title, window.location.pathname + window.location.search);
    }
};

// URL encoding utilities
export const encodeURIComponentSafe = (str: string): string => {
    return encodeURIComponent(str)
        .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
};

export const decodeURIComponentSafe = (str: string): string => {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
};

// Export utilities object
export const URLUtils = {
    // Parsing
    parseURL,
    parseQueryString,
    parseOAuthCallback,

    // Building
    buildURL,
    buildQueryString,
    buildAuthURL,
    buildOAuthURL,
    buildMagicLinkURL,
    buildVerificationURL,
    buildPasswordResetURL,
    buildInvitationURL,

    // Manipulation
    addQueryParams,
    removeQueryParams,
    getQueryParam,
    hasQueryParam,
    joinURL,
    normalizeURL,

    // Validation
    isValidURL,
    isValidHttpURL,
    isValidHttpsURL,
    isDomainAllowed,
    isSubdomain,
    isSafeRedirectURL,

    // Extraction
    extractDomain,
    extractRootDomain,
    getURLPath,
    getURLParams,

    // Browser
    getCurrentURL,
    getCurrentPath,
    getCurrentDomain,
    getCurrentOrigin,
    getCurrentParams,
    redirectTo,
    openInNewTab,

    // Hash
    getHash,
    setHash,
    removeHash,

    // Encoding
    encodeURIComponentSafe,
    decodeURIComponentSafe,

    // Security
    sanitizeRedirectURL,
};