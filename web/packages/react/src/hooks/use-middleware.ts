/**
 * @frank-auth/react - Middleware Integration Hooks
 *
 * React hooks that work seamlessly with the Next.js middleware
 * for client-side authentication state management.
 */

import {createContext, useCallback, useContext, useEffect, useState} from 'react';
import {useRouter} from 'next/router';
import {AuthStatus, Session, User} from '@frank-auth/client';
import {FrankAuthConfig} from '../types';

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface MiddlewareAuthState {
    isLoaded: boolean;
    isAuthenticated: boolean;
    user: User | null;
    session: Session | null;
    organizationId: string | null;
    error: Error | null;
}

export interface MiddlewareHookConfig extends FrankAuthConfig {
    /**
     * Enable automatic token refresh
     * @default true
     */
    enableAutoRefresh?: boolean;

    /**
     * Refresh token interval in milliseconds
     * @default 300000 (5 minutes)
     */
    refreshInterval?: number;

    /**
     * Redirect to sign in when unauthenticated
     * @default true
     */
    redirectToSignIn?: boolean;

    /**
     * Sign in path for redirects
     * @default '/sign-in'
     */
    signInPath?: string;

    /**
     * Enable debug logging
     * @default false
     */
    debug?: boolean;
}

export interface AuthActions {
    /**
     * Manually refresh authentication state
     */
    refresh: () => Promise<void>;

    /**
     * Sign out the current user
     */
    signOut: () => Promise<void>;

    /**
     * Switch to a different organization
     */
    switchOrganization: (organizationId: string) => Promise<void>;

    /**
     * Check if user has specific permission
     */
    hasPermission: (permission: string) => Promise<boolean>;

    /**
     * Get fresh auth status from server
     */
    getAuthStatus: () => Promise<AuthStatus>;
}

// ============================================================================
// Context Setup
// ============================================================================

const MiddlewareAuthContext = createContext<{
    state: MiddlewareAuthState;
    actions: AuthActions;
    config: MiddlewareHookConfig;
} | null>(null);

// ============================================================================
// Main Hook
// ============================================================================

/**
 * Main authentication hook that works with middleware
 */
export function useAuth(): MiddlewareAuthState & AuthActions {
    const context = useContext(MiddlewareAuthContext);

    if (!context) {
        throw new Error('useAuth must be used within a MiddlewareAuthProvider');
    }

    return {
        ...context.state,
        ...context.actions,
    };
}

// ============================================================================
// Specific Hooks
// ============================================================================

/**
 * Hook for authentication state only
 */
export function useAuthState(): MiddlewareAuthState {
    const { isLoaded, isAuthenticated, user, session, organizationId, error } = useAuth();

    return {
        isLoaded,
        isAuthenticated,
        user,
        session,
        organizationId,
        error,
    };
}

/**
 * Hook for current user information
 */
export function useUser(): {
    user: User | null;
    isLoaded: boolean;
    error: Error | null;
} {
    const { user, isLoaded, error } = useAuth();

    return { user, isLoaded, error };
}

/**
 * Hook for session management
 */
export function useSession(): {
    session: Session | null;
    isLoaded: boolean;
    refresh: () => Promise<void>;
    signOut: () => Promise<void>;
} {
    const { session, isLoaded, refresh, signOut } = useAuth();

    return { session, isLoaded, refresh, signOut };
}

/**
 * Hook for organization management
 */
export function useOrganization(): {
    organizationId: string | null;
    switchOrganization: (organizationId: string) => Promise<void>;
    isLoaded: boolean;
} {
    const { organizationId, switchOrganization, isLoaded } = useAuth();

    return { organizationId, switchOrganization, isLoaded };
}

/**
 * Hook for permission checking
 */
export function usePermissions(): {
    hasPermission: (permission: string) => Promise<boolean>;
    checkPermissions: (permissions: string[]) => Promise<Record<string, boolean>>;
} {
    const { hasPermission } = useAuth();

    const checkPermissions = useCallback(async (permissions: string[]) => {
        const results = await Promise.all(
            permissions.map(async (permission) => [permission, await hasPermission(permission)])
        );
        return Object.fromEntries(results);
    }, [hasPermission]);

    return { hasPermission, checkPermissions };
}

/**
 * Hook for protected routes
 */
export function useProtectedRoute(options: {
    redirectTo?: string;
    requiredPermission?: string;
    requiredOrganization?: boolean;
} = {}) {
    const router = useRouter();
    const { isLoaded, isAuthenticated, organizationId, hasPermission } = useAuth();
    const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null);

    useEffect(() => {
        async function checkAuthorization() {
            if (!isLoaded) return;

            // Check authentication
            if (!isAuthenticated) {
                const redirectTo = options.redirectTo || '/sign-in';
                const currentPath = router.asPath;
                await router.replace(`${redirectTo}?redirect_url=${encodeURIComponent(currentPath)}`);
                return;
            }

            // Check organization requirement
            if (options.requiredOrganization && !organizationId) {
                await router.replace('/select-organization');
                return;
            }

            // Check permission requirement
            if (options.requiredPermission) {
                const hasRequiredPermission = await hasPermission(options.requiredPermission);
                if (!hasRequiredPermission) {
                    await router.replace('/unauthorized');
                    return;
                }
            }

            setIsAuthorized(true);
        }

        checkAuthorization();
    }, [isLoaded, isAuthenticated, organizationId, options, router, hasPermission]);

    return {
        isLoaded,
        isAuthorized,
    };
}