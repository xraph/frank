import {NextRequest, NextResponse} from 'next/server';
import {getTokenData, isTokenExpired} from '../utils/token';
import {getConfig} from '../config';

export interface NextAuthMiddlewareOptions {
    authPages?: string[];  // Pages related to auth (login, register, etc.)
    protectedPages?: string[]; // Pages that require authentication
    publicPages?: string[]; // Pages accessible without authentication
    loginPage?: string; // Page to redirect to when auth fails
    orgRequired?: boolean; // Whether organization context is required
}

const defaultOptions: NextAuthMiddlewareOptions = {
    authPages: ['/login', '/register', '/forgot-password', '/reset-password'],
    protectedPages: ['/dashboard', '/profile', '/settings'],
    publicPages: ['/', '/about', '/contact'],
    loginPage: '/login',
    orgRequired: false
};

// Helper to match path patterns
const matchPath = (path: string, patterns: string[]): boolean => {
    return patterns.some(pattern => {
        if (pattern.endsWith('*')) {
            return path.startsWith(pattern.slice(0, -1));
        }
        return path === pattern;
    });
};

export function createNextAuthMiddleware(customOptions: NextAuthMiddlewareOptions = {}) {
    const options = { ...defaultOptions, ...customOptions };

    return async function middleware(request: NextRequest) {
        const { pathname } = request.nextUrl;

        // Initialize with config from cookies if available
        const baseUrl = request.cookies.get('frank_auth_baseUrl')?.value;
        if (baseUrl) {
            getConfig().baseUrl = baseUrl;
        }

        // Skip middleware for public assets
        if (
            pathname.startsWith('/_next') ||
            pathname.startsWith('/api') ||
            pathname.startsWith('/static') ||
            pathname.includes('.')
        ) {
            return NextResponse.next();
        }

        // Check if the page is public
        if (matchPath(pathname, options.publicPages || [])) {
            return NextResponse.next();
        }

        // Check authentication
        const tokenData = getTokenData();
        const isAuthenticated = !!tokenData && !isTokenExpired();

        // If on an auth page and already authenticated, redirect to dashboard
        if (isAuthenticated && matchPath(pathname, options.authPages || [])) {
            return NextResponse.redirect(new URL('/dashboard', request.url));
        }

        // If on a protected page and not authenticated, redirect to login
        if (!isAuthenticated && matchPath(pathname, options.protectedPages || [])) {
            const loginUrl = new URL(options.loginPage || '/login', request.url);
            loginUrl.searchParams.set('redirect', pathname);
            return NextResponse.redirect(loginUrl);
        }

        // Check organization context if required
        if (options.orgRequired && isAuthenticated) {
            const orgId = request.cookies.get('frank_auth_organizationId')?.value;
            if (!orgId && !pathname.includes('/organization-select')) {
                return NextResponse.redirect(new URL('/organization-select', request.url));
            }
        }

        // Continue to the requested page
        return NextResponse.next();
    };
}

// Helper function to get client-side Next.js auth config
export function getNextAuthConfig() {
    // This can be used in _app.js or app layout to initialize the auth provider
    return {
        baseUrl: typeof window !== 'undefined'
            ? window.localStorage.getItem('frank_auth_baseUrl') || ''
            : '',
        organizationId: typeof window !== 'undefined'
            ? window.localStorage.getItem('frank_auth_organizationId') || ''
            : ''
    };
}