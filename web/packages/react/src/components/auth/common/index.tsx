/**
 * @frank-auth/react - Common Auth Components Index
 *
 * Main entry point for common authentication components shared across
 * different auth flows. Exports all utilities and shared components.
 */

import ErrorBoundary, {
    ApiErrorBoundary,
    AuthErrorBoundary,
    ErrorBoundaryProps,
    FormErrorBoundary,
    withErrorBoundary
} from './error-boundary';
import LoadingSpinner, {LoadingButton, LoadingProvider, LoadingSpinnerProps} from './loading-spinner';
import MagicLink, {MagicLinkVerification} from './magic-link';
import OAuthButtons, {OAuthDivider} from './oauth-buttons';
import RedirectHandler from './redirect-handler';

// ============================================================================
// Loading Components
// ============================================================================

export {
    LoadingSpinner,
    LoadingButton,
    LoadingProvider,
    useLoading,
    LoadingStates,
    type LoadingSpinnerProps,
    type LoadingButtonProps,
} from './loading-spinner';

// ============================================================================
// Error Handling Components
// ============================================================================

export {
    ErrorBoundary,
    AuthErrorBoundary,
    FormErrorBoundary,
    ApiErrorBoundary,
    withErrorBoundary,
    useAsyncError,
    type ErrorBoundaryProps,
    type ErrorFallbackProps,
} from './error-boundary';

// ============================================================================
// Redirect Handling Components
// ============================================================================

export {
    RedirectHandler,
    useRedirectHandler,
    type RedirectHandlerProps,
} from './redirect-handler';

// ============================================================================
// OAuth Components
// ============================================================================

export {
    OAuthButtons,
    OAuthDivider,
    type OAuthButtonsProps,
} from './oauth-buttons';

// ============================================================================
// Magic Link Components
// ============================================================================

export {
    MagicLink,
    MagicLinkVerification,
    type MagicLinkProps,
    type MagicLinkVerificationProps,
} from './magic-link';

// ============================================================================
// Verification Components
// ============================================================================

export * from './verification';

// ============================================================================
// Component Collections
// ============================================================================

/**
 * Collection of all common authentication components
 */
export const CommonAuthComponents = {
    LoadingSpinner,
    LoadingButton,
    ErrorBoundary,
    RedirectHandler,
    OAuthButtons,
    OAuthDivider,
    MagicLink,
    MagicLinkVerification,
} as const;

/**
 * Collection of loading-related components
 */
export const LoadingComponents = {
    LoadingSpinner,
    LoadingButton,
    LoadingProvider,
} as const;

/**
 * Collection of error handling components
 */
export const ErrorComponents = {
    ErrorBoundary,
    AuthErrorBoundary,
    FormErrorBoundary,
    ApiErrorBoundary,
} as const;

/**
 * Collection of OAuth-related components
 */
export const OAuthComponents = {
    OAuthButtons,
    OAuthDivider,
} as const;

/**
 * Collection of magic link components
 */
export const MagicLinkComponents = {
    MagicLink,
    MagicLinkVerification,
} as const;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Common authentication states
 */
export const AuthStates = {
    LOADING: 'loading',
    SUCCESS: 'success',
    ERROR: 'error',
    IDLE: 'idle',
    PROCESSING: 'processing',
    VERIFYING: 'verifying',
    REDIRECTING: 'redirecting',
} as const;

/**
 * Authentication error types
 */
export const AuthErrorTypes = {
    NETWORK_ERROR: 'network_error',
    AUTHENTICATION_ERROR: 'authentication_error',
    AUTHORIZATION_ERROR: 'authorization_error',
    VALIDATION_ERROR: 'validation_error',
    TIMEOUT_ERROR: 'timeout_error',
    UNKNOWN_ERROR: 'unknown_error',
} as const;

/**
 * Redirect types for authentication flows
 */
export const RedirectTypes = {
    OAUTH: 'oauth',
    MAGIC_LINK: 'magic-link',
    INVITATION: 'invitation',
    VERIFICATION: 'verification',
    ERROR: 'error',
} as const;

// ============================================================================
// Higher-Order Components
// ============================================================================

/**
 * HOC to wrap components with loading state
 */
export function withLoading<P extends object>(
    Component: React.ComponentType<P>,
    loadingProps?: Partial<LoadingSpinnerProps>
) {
    const WithLoadingComponent = (props: P & { isLoading?: boolean }) => {
        const { isLoading, ...componentProps } = props;

        if (isLoading) {
            return <LoadingSpinner {...loadingProps} />;
        }

        return <Component {...(componentProps as P)} />;
    };

    WithLoadingComponent.displayName = `withLoading(${Component.displayName || Component.name})`;

    return WithLoadingComponent;
}

/**
 * HOC to wrap components with auth error boundary
 */
export function withAuthErrorBoundary<P extends object>(
    Component: React.ComponentType<P>,
    errorBoundaryProps?: Partial<ErrorBoundaryProps>
) {
    return withErrorBoundary(Component, {
        title: 'Authentication Error',
        subtitle: 'There was a problem with the authentication process.',
        showDetails: process.env.NODE_ENV === 'development',
        ...errorBoundaryProps,
    });
}

// ============================================================================
// Auth Flow Utilities
// ============================================================================

/**
 * Utility to determine if current page is an auth redirect
 */
export function isAuthRedirect(): boolean {
    if (typeof window === 'undefined') return false;

    const params = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(window.location.hash.slice(1));

    // Check for OAuth callback parameters
    if (params.has('code') || hash.has('code')) return true;

    // Check for magic link parameters
    if (params.has('token') || hash.has('token')) return true;

    // Check for invitation parameters
    if (params.has('invitation_token') || params.has('invite')) return true;

    // Check for error parameters
    if (params.has('error') || hash.has('error')) return true;

    return false;
}

/**
 * Utility to extract auth parameters from URL
 */
export function getAuthParams(): Record<string, string> {
    if (typeof window === 'undefined') return {};

    const params = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(window.location.hash.slice(1));

    const authParams: Record<string, string> = {};

    // Merge query params and hash params
    [...params.entries(), ...hash.entries()].forEach(([key, value]) => {
        authParams[key] = value;
    });

    return authParams;
}

/**
 * Utility to clean auth parameters from URL
 */
export function cleanAuthParams(): void {
    if (typeof window === 'undefined') return;

    const authParamKeys = [
        'code', 'state', 'error', 'error_description', 'token', 'type',
        'invitation_token', 'invite', 'verification_token', 'verify'
    ];

    const params = new URLSearchParams(window.location.search);
    let hasAuthParams = false;

    authParamKeys.forEach(key => {
        if (params.has(key)) {
            params.delete(key);
            hasAuthParams = true;
        }
    });

    if (hasAuthParams) {
        const newUrl = params.toString()
            ? `${window.location.pathname}?${params.toString()}`
            : window.location.pathname;

        window.history.replaceState({}, document.title, newUrl);
    }

    // Clean hash parameters
    if (window.location.hash) {
        const hashParams = new URLSearchParams(window.location.hash.slice(1));
        let hasHashAuthParams = false;

        authParamKeys.forEach(key => {
            if (hashParams.has(key)) {
                hashParams.delete(key);
                hasHashAuthParams = true;
            }
        });

        if (hasHashAuthParams) {
            const newHash = hashParams.toString() ? `#${hashParams.toString()}` : '';
            window.history.replaceState({}, document.title, window.location.pathname + window.location.search + newHash);
        }
    }
}

// ============================================================================
// Default Export
// ============================================================================

export default CommonAuthComponents;