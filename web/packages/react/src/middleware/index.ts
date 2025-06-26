// packages/react/src/middleware/index.ts
/**
 * @frank-auth/react - Next.js Middleware Plugin
 *
 * Comprehensive middleware solution for Next.js applications using Frank Auth.
 * Provides authentication routing, session management, and path protection.
 *
 * @example Basic Usage
 * ```typescript
 * // middleware.ts
 * import { createFrankAuthMiddleware } from '@frank-auth/react/middleware';
 *
 * export default createFrankAuthMiddleware({
 *   publishableKey: process.env.NEXT_PUBLIC_FRANK_AUTH_PUBLISHABLE_KEY!,
 *   publicPaths: ['/'],
 *   signInPath: '/sign-in',
 *   signUpPath: '/sign-up',
 * });
 *
 * export const config = {
 *   matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)']
 * };
 * ```
 */

import {NextRequest, NextResponse} from 'next/server';
import {Session, User} from '@frank-auth/client';
import {FrankAuthConfig} from '../types';
import {FrankAuth} from "@frank-auth/sdk";

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface MiddlewareConfig extends Omit<FrankAuthConfig, 'enableDevMode'> {
    storageKeyPrefix?: string
    sessionCookieName?: string

    /**
     * Paths that are publicly accessible without authentication
     * @default ['/sign-in', '/sign-up', '/forgot-password']
     */
    publicPaths?: string[];

    /**
     * Paths that require authentication (when allPathsPrivate is false)
     * @default []
     */
    privatePaths?: string[];

    /**
     * Whether all paths are private by default (recommended)
     * @default true
     */
    allPathsPrivate?: boolean;

    /**
     * Path to redirect to for sign in
     * @default '/sign-in'
     */
    signInPath?: string;

    /**
     * Path to redirect to for sign up
     * @default '/sign-up'
     */
    signUpPath?: string;

    /**
     * Path to redirect to after successful sign in
     * @default '/dashboard'
     */
    afterSignInPath?: string;

    /**
     * Path to redirect to after successful sign up
     * @default '/dashboard'
     */
    afterSignUpPath?: string;

    /**
     * Path to redirect to after sign out
     * @default '/'
     */
    afterSignOutPath?: string;

    /**
     * Organization selection path for multi-tenant apps
     * @default '/select-organization'
     */
    orgSelectionPath?: string;

    /**
     * Custom matcher function for protected routes
     */
    matcher?: (path: string) => boolean;

    /**
     * Enable debug logging
     * @default false
     */
    debug?: boolean;

    /**
     * Custom domain for organization detection
     */
    customDomain?: string;

    /**
     * Enable organization-based routing
     * @default false
     */
    enableOrgRouting?: boolean;

    /**
     * Ignore paths (will not be processed by middleware)
     * @default ['/api', '/_next', '/favicon.ico']
     */
    ignorePaths?: string[];

    /**
     * Cookie options for session management
     */
    cookieOptions?: {
        secure?: boolean;
        httpOnly?: boolean;
        sameSite?: 'strict' | 'lax' | 'none';
        domain?: string;
        maxAge?: number;
    };

    /**
     * Custom hooks for middleware lifecycle
     */
    hooks?: MiddlewareHooks;
}

export interface MiddlewareHooks {
    /**
     * Called before authentication check
     */
    beforeAuth?: (req: NextRequest) => Promise<NextRequest | NextResponse | void>;

    /**
     * Called after authentication check
     */
    afterAuth?: (req: NextRequest, res: NextResponse, auth: AuthResult) => Promise<NextRequest | NextResponse | void>;

    /**
     * Called when user is authenticated
     */
    onAuthenticated?: (req: NextRequest, user: User, session: Session) => Promise<NextRequest | NextResponse | void>;

    /**
     * Called when user is not authenticated
     */
    onUnauthenticated?: (req: NextRequest) => Promise<NextRequest | NextResponse | void>;

    /**
     * Called when organization is required but not selected
     */
    onOrganizationRequired?: (req: NextRequest, user: User) => Promise<NextRequest | NextResponse | void>;

    /**
     * Called on authentication error
     */
    onError?: (req: NextRequest, error: Error) => Promise<NextRequest | NextResponse | void>;
}

export interface AuthResult {
    isAuthenticated: boolean;
    user: User | null;
    session: Session | null;
    organizationId: string | null;
    error: Error | null;
}

export interface MiddlewareContext {
    req: NextRequest;
    config: Required<MiddlewareConfig>;
    auth: AuthResult;
    path: string;
    isPublicPath: boolean;
    isPrivatePath: boolean;
    isAuthPath: boolean;
}

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_MIDDLEWARE_CONFIG: Partial<MiddlewareConfig> = {
    apiUrl: 'http://localhost:8990',
    sessionCookieName: 'frank_sid',
    storageKeyPrefix: 'frank_auth_',
    publicPaths: ['/sign-in', '/sign-up', '/forgot-password', '/verify-email', '/reset-password'],
    privatePaths: [],
    allPathsPrivate: true, // Default to all paths being private
    signInPath: '/sign-in',
    signUpPath: '/sign-up',
    afterSignInPath: '/dashboard',
    afterSignUpPath: '/dashboard',
    afterSignOutPath: '/',
    orgSelectionPath: '/select-organization',
    debug: false,
    enableOrgRouting: false,
    ignorePaths: ['/api', '/_next', '/favicon.ico', '/images', '/static', '/_vercel'],
    cookieOptions: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 7, // 7 days
    },
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if a path matches any of the patterns
 */
function matchesPath(path: string, patterns: string[]): boolean {
    return patterns.some(pattern => {
        // Exact match
        if (pattern === path) return true;

        // Wildcard match
        if (pattern.endsWith('*')) {
            const prefix = pattern.slice(0, -1);
            return path.startsWith(prefix);
        }

        // Regex pattern
        if (pattern.startsWith('/') && pattern.endsWith('/')) {
            const regex = new RegExp(pattern.slice(1, -1));
            return regex.test(path);
        }

        return false;
    });
}

/**
 * Extract session token from request
 */
function getSessionToken(req: NextRequest, config: Required<MiddlewareConfig>): string | null {
    // Try cookies first
    const cookieToken = req.cookies.get(config.sessionCookieName)?.value;
    if (cookieToken) return cookieToken;

    // Try Authorization header
    const authHeader = req.headers.get('authorization');
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }

    return null;
}

/**
 * Validate session token with Frank Auth API
 */
async function validateSession(
    token: string,
    config: Required<MiddlewareConfig>,
    req: NextRequest
): Promise<AuthResult> {
    const authApi = new FrankAuth({
        apiUrl: config.apiUrl,
        publishableKey: config.publishableKey,
        sessionCookieName: config.sessionCookieName,
        storageKeyPrefix: config.storageKeyPrefix,
        enableDevMode: config.debug,
//        userType: userType ?? 'end_user',
    })

    try {
        // Forward important headers from the original request
        const headers: Record<string, string> = {
            'Authorization': `Bearer ${token}`,
            'X-Publishable-Key': config.publishableKey,
            'Content-Type': 'application/json',
        };

        // Forward cookies if they exist
        const cookieHeader = req.headers.get('cookie');
        if (cookieHeader) {
            headers['Cookie'] = cookieHeader;
        }

        // Forward user agent
        const userAgent = req.headers.get('user-agent');
        if (userAgent) {
            headers['User-Agent'] = userAgent;
        }

        // Forward real IP for security
        const forwardedFor = req.headers.get('x-forwarded-for');
        const realIp = req.headers.get('x-real-ip');
        if (forwardedFor) {
            headers['X-Forwarded-For'] = forwardedFor;
        }
        if (realIp) {
            headers['X-Real-IP'] = realIp;
        }

        debugLog(config, 'Validating session token:', {token, headers});

        const authStatus = await authApi.getAuthStatus({
            credentials: 'include',
            headers,
        });

        return {
            isAuthenticated: authStatus.isAuthenticated,
            user: authStatus.user || null,
            session: authStatus.session || null,
            organizationId: authStatus.organizationId || null,
            error: null,
        };
    } catch (error) {
        return {
            isAuthenticated: false,
            user: null,
            session: null,
            organizationId: null,
            error: error as Error,
        };
    }
}

/**
 * Attempt to refresh session token
 */
async function refreshSession(
    refreshToken: string,
    config: Required<MiddlewareConfig>,
    req: NextRequest
): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
        const headers: Record<string, string> = {
            'X-Publishable-Key': config.publishableKey,
            'Content-Type': 'application/json',
        };

        // Forward cookies for refresh
        const cookieHeader = req.headers.get('cookie');
        if (cookieHeader) {
            headers['Cookie'] = cookieHeader;
        }

        const response = await fetch(`${config.apiUrl}/api/v1/public/auth/refresh`, {
            method: 'POST',
            credentials: 'include',
            headers,
            body: JSON.stringify({refreshToken}),
        });

        if (!response.ok) return null;

        const result = await response.json();
        return {
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
        };
    } catch {
        return null;
    }
}

/**
 * Extract organization from subdomain or custom domain
 */
function extractOrganization(req: NextRequest, config: Required<MiddlewareConfig>): string | null {
    if (!config.enableOrgRouting) return null;

    const hostname = req.nextUrl.hostname;

    // Custom domain mapping
    if (config.customDomain && hostname === config.customDomain) {
        return req.nextUrl.searchParams.get('org') || null;
    }

    // Subdomain extraction
    const parts = hostname.split('.');
    if (parts.length > 2) {
        return parts[0]; // First part is the organization slug
    }

    return null;
}

/**
 * Debug logger
 */
function debugLog(config: Required<MiddlewareConfig>, message: string, data?: any) {
    if (config.debug) {
        console.log(`[FrankAuth Middleware] ${message}`, data ? data : '');
    }
}

// ============================================================================
// Core Middleware Logic
// ============================================================================

/**
 * Process authentication and routing
 */
async function processRequest(
    req: NextRequest,
    config: Required<MiddlewareConfig>
): Promise<NextResponse> {
    const path = req.nextUrl.pathname;

    debugLog(config, `Processing request: ${path}`);

    // Check if path should be ignored
    if (matchesPath(path, config.ignorePaths)) {
        debugLog(config, `Ignoring path: ${path}`);
        return NextResponse.next();
    }

    // Execute beforeAuth hook
    if (config.hooks?.beforeAuth) {
        const hookResult = await config.hooks.beforeAuth(req);
        if (hookResult instanceof NextResponse) return hookResult;
        if (hookResult instanceof NextRequest) req = hookResult;
    }

    // Determine path types
    const isPublicPath = matchesPath(path, config.publicPaths);
    const isAuthPath = path === config.signInPath || path === config.signUpPath;

    // Determine if path is private based on configuration
    let isPrivatePath: boolean;
    if (config.allPathsPrivate) {
        // All paths are private except public paths
        isPrivatePath = !isPublicPath && !isAuthPath;
    } else {
        // Only specified paths are private
        isPrivatePath = matchesPath(path, config.privatePaths);
    }

    debugLog(config, `Path analysis:`, {
        isPublicPath,
        isPrivatePath,
        isAuthPath,
        allPathsPrivate: config.allPathsPrivate
    });

    // Get session token
    const sessionToken = getSessionToken(req, config);
    let auth: AuthResult = {
        isAuthenticated: false,
        user: null,
        session: null,
        organizationId: null,
        error: null,
    };

    debugLog(config, `Session Cookie:`, {sessionToken});

    // Validate session if token exists
    if (sessionToken) {

        auth = await validateSession(sessionToken, config, req);

        // Try to refresh if validation failed
        if (!auth.isAuthenticated && auth.error) {
            const refreshToken = req.cookies.get(`${config.storageKeyPrefix}refresh_token`)?.value;
            if (refreshToken) {
                const refreshResult = await refreshSession(refreshToken, config, req);
                if (refreshResult) {
                    auth = await validateSession(refreshResult.accessToken, config, req);

                    // Set new tokens in response
                    if (auth.isAuthenticated) {
                        const response = NextResponse.next();
                        response.cookies.set(config.sessionCookieName, refreshResult.accessToken, config.cookieOptions);
                        response.cookies.set(`${config.storageKeyPrefix}refresh_token`, refreshResult.refreshToken, config.cookieOptions);
                        return response;
                    }
                }
            }
        }
    }

    debugLog(config, `Auth result:`, {
        isAuthenticated: auth.isAuthenticated,
        hasUser: !!auth.user,
        organizationId: auth.organizationId
    });

    // Create middleware context
    const context: MiddlewareContext = {
        req,
        config,
        auth,
        path,
        isPublicPath,
        isPrivatePath,
        isAuthPath,
    };

    // Execute authentication logic
    const response = await handleAuthentication(context);

    // Execute afterAuth hook
    if (config.hooks?.afterAuth) {
        const hookResult = await config.hooks.afterAuth(req, response, auth);
        if (hookResult instanceof NextResponse) return hookResult;
    }

    return response;
}

/**
 * Handle authentication logic based on context
 */
async function handleAuthentication(context: MiddlewareContext): Promise<NextResponse> {
    const {req, config, auth, path, isPublicPath, isPrivatePath, isAuthPath} = context;

    try {
        // Handle authenticated users
        if (auth.isAuthenticated && auth.user) {
            debugLog(config, 'User is authenticated');

            // Execute onAuthenticated hook
            if (config.hooks?.onAuthenticated && auth.session) {
                const hookResult = await config.hooks.onAuthenticated(req, auth.user, auth.session);
                if (hookResult instanceof NextResponse) return hookResult;
            }

            // Redirect away from auth pages
            if (isAuthPath) {
                const redirectTo = req.nextUrl.searchParams.get('redirect_url') || config.afterSignInPath;
                debugLog(config, `Redirecting authenticated user from auth page to: ${redirectTo}`);
                return NextResponse.redirect(new URL(redirectTo, req.url));
            }

            // Check organization requirement
            if (config.enableOrgRouting && !auth.organizationId && path !== config.orgSelectionPath) {
                debugLog(config, 'Organization required but not selected');

                if (config.hooks?.onOrganizationRequired) {
                    const hookResult = await config.hooks.onOrganizationRequired(req, auth.user);
                    if (hookResult instanceof NextResponse) return hookResult;
                }

                return NextResponse.redirect(new URL(config.orgSelectionPath, req.url));
            }

            // Allow access to all paths for authenticated users
            return NextResponse.next();
        }

        // Handle unauthenticated users
        debugLog(config, 'User is not authenticated');

        // Execute onUnauthenticated hook
        if (config.hooks?.onUnauthenticated) {
            const hookResult = await config.hooks.onUnauthenticated(req);
            if (hookResult instanceof NextResponse) return hookResult;
        }

        // Allow access to public paths and auth pages
        if (isPublicPath || isAuthPath) {
            debugLog(config, 'Allowing access to public/auth path');
            return NextResponse.next();
        }

        // Redirect to sign in for private paths
        if (isPrivatePath) {
            const signInUrl = new URL(config.signInPath, req.url);
            signInUrl.searchParams.set('redirect_url', req.nextUrl.pathname + req.nextUrl.search);

            debugLog(config, `Redirecting to sign in: ${signInUrl.toString()}`);
            return NextResponse.redirect(signInUrl);
        }

        return NextResponse.next();

    } catch (error) {
        debugLog(config, 'Error in authentication handling:', error);

        // Execute onError hook
        if (config.hooks?.onError) {
            const hookResult = await config.hooks.onError(req, error as Error);
            if (hookResult instanceof NextResponse) return hookResult;
        }

        // Default error handling - redirect to sign in
        const signInUrl = new URL(config.signInPath, req.url);
        signInUrl.searchParams.set('error', 'auth_error');
        return NextResponse.redirect(signInUrl);
    }
}

// ============================================================================
// Main Middleware Factory
// ============================================================================

/**
 * Create Frank Auth middleware for Next.js
 */
export function createFrankAuthMiddleware(userConfig: MiddlewareConfig) {
    const config = {...DEFAULT_MIDDLEWARE_CONFIG, ...userConfig} as Required<MiddlewareConfig>;

    // Validate required configuration
    if (!config.publishableKey) {
        throw new Error('publishableKey is required for Frank Auth middleware');
    }

    debugLog(config, 'Frank Auth middleware initialized with config:', {
        publicPaths: config.publicPaths,
        privatePaths: config.privatePaths,
        allPathsPrivate: config.allPathsPrivate,
        signInPath: config.signInPath,
        enableOrgRouting: config.enableOrgRouting,
    });

    return async function middleware(req: NextRequest): Promise<NextResponse> {
        return processRequest(req, config);
    };
}

// ============================================================================
// Middleware Utilities
// ============================================================================

/**
 * Create a custom matcher function for complex routing logic
 */
export function createMatcher(patterns: {
    include?: string[];
    exclude?: string[];
    custom?: (path: string) => boolean;
}) {
    return function matcher(path: string): boolean {
        // Check custom matcher first
        if (patterns.custom) {
            return patterns.custom(path);
        }

        // Check exclude patterns
        if (patterns.exclude && matchesPath(path, patterns.exclude)) {
            return false;
        }

        // Check include patterns
        if (patterns.include && matchesPath(path, patterns.include)) {
            return true;
        }

        return false;
    };
}

/**
 * Utility to check if user has specific permission in middleware
 */
export async function checkPermission(
    req: NextRequest,
    permission: string,
    config: MiddlewareConfig
): Promise<boolean> {
    const token = getSessionToken(req, config as Required<MiddlewareConfig>);
    if (!token) return false;

    try {
        const response = await fetch(`${config.apiUrl}/api/v1/auth/permissions/check`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-Publishable-Key': config.publishableKey,
                'Content-Type': 'application/json',
                'Cookie': req.headers.get('cookie') || '',
            },
            body: JSON.stringify({permission}),
        });

        if (!response.ok) return false;

        const result = await response.json();
        return result.hasPermission === true;
    } catch {
        return false;
    }
}

/**
 * Utility to get organization from request
 */
export function getOrganizationFromRequest(
    req: NextRequest,
    config: MiddlewareConfig
): string | null {
    return extractOrganization(req, config as Required<MiddlewareConfig>);
}