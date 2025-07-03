'use client'

/**
 * @frank-auth/react - useAuth Hook
 *
 * Main authentication hook that provides access to authentication state,
 * methods, and organization context. This is the primary hook for most
 * authentication operations.
 */

import {useCallback, useMemo} from 'react';

import type {
    Organization,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetResponse,
    ResendVerificationRequest,
    ResendVerificationResponse,
    Session,
    User,
    ValidateTokenInputBody,
    ValidateTokenResponse, VerificationRequest, VerificationResponse,
} from '@frank-auth/client';

import {useAuth as useAuthProvider} from '../provider/auth-provider';
import {useConfig} from '../provider/config-provider';

import type {
    AuthError,
    OrganizationMembership,
    SetActiveParams,
    SignInParams,
    SignInResult,
    SignUpParams,
    SignUpResult,
    UpdateUserParams,
} from '../provider/types';
import type {PasswordResetRequest} from "@frank-auth/sdk";

// ============================================================================
// Auth Hook Interface
// ============================================================================

export interface UseAuthReturn {
    // Authentication state
    isLoaded: boolean;
    isLoading: boolean;
    isSignedIn: boolean;
    user: User | null;
    session: Session | null;

    // Organization context
    organization: Organization | null;
    organizationMemberships: OrganizationMembership[];
    activeOrganization: Organization | null;

    // Error handling
    error: AuthError | null;

    // Authentication methods
    signIn: (params: SignInParams) => Promise<SignInResult>;
    signUp: (params: SignUpParams) => Promise<SignUpResult>;
    signOut: () => Promise<void>;
    resendVerification: (request: ResendVerificationRequest) => Promise<ResendVerificationResponse>
    verifyIdentity: (type: "email" | "phone", request: VerificationRequest) => Promise<VerificationResponse>

    // Session management
    createSession: (token: string) => Promise<Session>;
    setActive: (params: SetActiveParams) => Promise<void>;

    // Organization management
    setActiveOrganization: (organizationId: string) => Promise<void>;
    switchOrganization: (organizationId: string) => Promise<void>;

    // User management
    updateUser: (params: UpdateUserParams) => Promise<User>;
    deleteUser: () => Promise<void>;

    // Utility methods
    reload: () => Promise<void>;

    // Recovery
    resetPassword: (params: PasswordResetConfirmRequest) => Promise<PasswordResetConfirmResponse>
    requestPasswordReset: (request: PasswordResetRequest) => Promise<PasswordResetResponse>

    extractEmailFromUrl: (url?: string) => (string | null)
    extractTokenFromUrl: (url?: string) => (string | null)
    validateToken: (request: ValidateTokenInputBody) => Promise<ValidateTokenResponse>

    // Convenience properties
    userId: string | null;
    userEmail: string | null;
    userName: string | null;
    organizationId: string | null;
    organizationName: string | null;
    userType: string | null;

    // Permission helpers
    hasOrganization: boolean;
    isOrganizationMember: boolean;
    isOrganizationAdmin: boolean;

    // Status helpers
    isAuthenticated: boolean;
    requiresVerification: boolean;
    requiresMFA: boolean;
}

// ============================================================================
// Main useAuth Hook
// ============================================================================

/**
 * Main authentication hook providing access to all authentication functionality
 *
 * @example Basic usage
 * ```tsx
 * import { useAuth } from '@frank-auth/react';
 *
 * function MyComponent() {
 *   const { user, signIn, signOut, isLoaded } = useAuth();
 *
 *   if (!isLoaded) return <div>Loading...</div>;
 *
 *   if (!user) {
 *     return <button onClick={() => signIn({ strategy: 'password', identifier: 'user@example.com', password: 'password' })}>
 *       Sign In
 *     </button>;
 *   }
 *
 *   return (
 *     <div>
 *       <p>Welcome, {user.firstName}!</p>
 *       <button onClick={signOut}>Sign Out</button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Organization management
 * ```tsx
 * function OrganizationSwitcher() {
 *   const { organizationMemberships, activeOrganization, switchOrganization } = useAuth();
 *
 *   return (
 *     <select
 *       value={activeOrganization?.id || ''}
 *       onChange={(e) => switchOrganization(e.target.value)}
 *     >
 *       {organizationMemberships.map((membership) => (
 *         <option key={membership.organization.id} value={membership.organization.id}>
 *           {membership.organization.name}
 *         </option>
 *       ))}
 *     </select>
 *   );
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
    const authContext = useAuthProvider();
    const { userType, features } = useConfig();

    // Convenience properties
    const userId = useMemo(() => authContext.user?.id || null, [authContext.user]);
    const userEmail = useMemo(() => authContext.user?.primaryEmailAddress || null, [authContext.user]);
    const userName = useMemo(() => {
        if (!authContext.user) return null;
        return authContext.user.username ||
            `${authContext.user.firstName || ''} ${authContext.user.lastName || ''}`.trim() ||
            authContext.user.primaryEmailAddress ||
            null;
    }, [authContext.user]);

    const organizationId = useMemo(() =>
            authContext.activeOrganization?.id || null,
        [authContext.activeOrganization]
    );

    const organizationName = useMemo(() =>
            authContext.activeOrganization?.name || null,
        [authContext.activeOrganization]
    );

    // Permission helpers
    const hasOrganization = useMemo(() =>
            !!authContext.activeOrganization,
        [authContext.activeOrganization]
    );

    const isOrganizationMember = useMemo(() => {
        if (!authContext.activeOrganization || !authContext.user) return false;
        return authContext.organizationMemberships.some(
            membership => membership.organization.id === authContext.activeOrganization?.id
        );
    }, [authContext.activeOrganization, authContext.user, authContext.organizationMemberships]);

    const isOrganizationAdmin = useMemo(() => {
        if (!authContext.activeOrganization || !authContext.user) return false;
        const membership = authContext.organizationMemberships.find(
            membership => membership.organization.id === authContext.activeOrganization?.id
        );
        return membership?.role === 'admin' || membership?.role === 'owner';
    }, [authContext.activeOrganization, authContext.user, authContext.organizationMemberships]);

    // Status helpers
    const isAuthenticated = useMemo(() =>
            authContext.isLoaded && authContext.isSignedIn,
        [authContext.isLoaded, authContext.isSignedIn]
    );

    const requiresVerification = useMemo(() => {
        if (!authContext.user) return false;
        return !authContext.user.emailVerified ||
            (features.mfa && !authContext.user.mfaEnabled);
    }, [authContext.user, features.mfa]);

    const requiresMFA = useMemo(() => {
        if (!authContext.user) return false;
        return features.mfa && !authContext.user.mfaEnabled;
    }, [authContext.user, features.mfa]);

    // Enhanced sign in with validation
    const signIn = useCallback(async (params: SignInParams): Promise<SignInResult> => {
        // Validate required features
        if (params.strategy === 'oauth' && !features.oauth) {
            throw new Error('OAuth authentication is not enabled for this organization');
        }

        if (params.strategy === 'passkey' && !features.passkeys) {
            throw new Error('Passkey authentication is not enabled for this organization');
        }

        if (params.strategy === 'sso' && !features.sso) {
            throw new Error('SSO authentication is not enabled for this organization');
        }

        if (params.strategy === 'magic_link' && !features.magicLink) {
            throw new Error('Magic link authentication is not enabled for this organization');
        }

        return authContext.signIn(params);
    }, [authContext.signIn, features]);

    // Enhanced sign up with validation
    const signUp = useCallback(async (params: SignUpParams): Promise<SignUpResult> => {
        // Validate sign up is enabled
        if (!features.signUp) {
            throw new Error('User registration is not enabled for this organization');
        }

        return authContext.signUp(params);
    }, [authContext.signUp, features]);


    // Extract token from URL
    const extractEmailFromUrl = useCallback((url?: string): string | null => {
        const urlToCheck = url || window.location.href;

        try {
            const urlObj = new URL(urlToCheck);
            return urlObj.searchParams.get('email');
        } catch {
            return null;
        }
    }, []);

    // Extract token from URL
    const extractTokenFromUrl = useCallback((url?: string): string | null => {
        const urlToCheck = url || window.location.href;

        try {
            const urlObj = new URL(urlToCheck);
            return urlObj.searchParams.get('token');
        } catch {
            return null;
        }
    }, []);

    return {
        // Core authentication state
        isLoaded: authContext.isLoaded,
        isLoading: authContext.isLoading,
        isSignedIn: authContext.isSignedIn,
        user: authContext.user,
        session: authContext.session,

        // Organization context
        organization: authContext.organization,
        organizationMemberships: authContext.organizationMemberships,
        activeOrganization: authContext.activeOrganization,

        // Error state
        error: authContext.error,

        // Authentication methods
        signIn,
        signUp,
        signOut: authContext.signOut,
        resendVerification: authContext.resendVerification,
        verifyIdentity: authContext.verifyIdentity,

        // Recovery methods
        requestPasswordReset: authContext.requestPasswordReset,
        resetPassword: authContext.resetPassword,
        validateToken: authContext.validateToken,
        extractEmailFromUrl,
        extractTokenFromUrl,

        // Session management
        createSession: authContext.createSession,
        setActive: authContext.setActive,

        // Organization management
        setActiveOrganization: authContext.setActiveOrganization,
        switchOrganization: authContext.switchOrganization,

        // User management
        updateUser: authContext.updateUser,
        deleteUser: authContext.deleteUser,

        // Utility methods
        reload: authContext.reload,

        // Convenience properties
        userId,
        userEmail,
        userName,
        organizationId,
        organizationName,
        userType,

        // Permission helpers
        hasOrganization,
        isOrganizationMember,
        isOrganizationAdmin,

        // Status helpers
        isAuthenticated,
        requiresVerification,
        requiresMFA,
    };
}

// ============================================================================
// Specialized Auth Hooks
// ============================================================================

/**
 * Hook for authentication state only (no methods)
 * Useful for components that only need to display auth state
 */
export function useAuthState() {
    const {
        isLoaded,
        isLoading,
        isSignedIn,
        user,
        session,
        organization,
        activeOrganization,
        error,
        userId,
        userEmail,
        userName,
        organizationId,
        organizationName,
        userType,
        hasOrganization,
        isOrganizationMember,
        isOrganizationAdmin,
        isAuthenticated,
        requiresVerification,
        requiresMFA,
    } = useAuth();

    return {
        isLoaded,
        isLoading,
        isSignedIn,
        user,
        session,
        organization,
        activeOrganization,
        error,
        userId,
        userEmail,
        userName,
        organizationId,
        organizationName,
        userType,
        hasOrganization,
        isOrganizationMember,
        isOrganizationAdmin,
        isAuthenticated,
        requiresVerification,
        requiresMFA,
    };
}

/**
 * Hook for authentication methods only
 * Useful for forms and action components
 */
export function useAuthActions() {
    const {
        signIn,
        signUp,
        signOut,
        createSession,
        setActive,
        setActiveOrganization,
        switchOrganization,
        updateUser,
        deleteUser,
        reload,
    } = useAuth();

    return {
        signIn,
        signUp,
        signOut,
        createSession,
        setActive,
        setActiveOrganization,
        switchOrganization,
        updateUser,
        deleteUser,
        reload,
    };
}

/**
 * Hook for organization-specific authentication data
 * Useful for multi-tenant applications
 */
export function useAuthOrganization() {
    const {
        organization,
        organizationMemberships,
        activeOrganization,
        organizationId,
        organizationName,
        hasOrganization,
        isOrganizationMember,
        isOrganizationAdmin,
        setActiveOrganization,
        switchOrganization,
    } = useAuth();

    return {
        organization,
        organizationMemberships,
        activeOrganization,
        organizationId,
        organizationName,
        hasOrganization,
        isOrganizationMember,
        isOrganizationAdmin,
        setActiveOrganization,
        switchOrganization,
    };
}

/**
 * Authentication status hook with loading states
 * Useful for conditional rendering based on auth status
 */
export function useAuthStatus() {
    const {
        isLoaded,
        isLoading,
        isSignedIn,
        isAuthenticated,
        requiresVerification,
        requiresMFA,
        error,
    } = useAuth();

    return {
        isLoaded,
        isLoading,
        isSignedIn,
        isAuthenticated,
        requiresVerification,
        requiresMFA,
        hasError: !!error,
        error,
        status: isLoading ? 'loading' :
            isSignedIn ? 'signed-in' :
                'signed-out',
    };
}