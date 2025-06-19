/**
 * @frank-auth/react - Redirect Handler Component
 *
 * Handles authentication redirects for OAuth, magic links, invitations,
 * and other authentication flows with proper state management.
 */

'use client';

import React from 'react';
import {motion} from 'framer-motion';
import {useOAuth} from '../../../hooks/use-oauth';
import {useMagicLink} from '../../../hooks/use-magic-link';
import {useOrganization} from '../../../hooks/use-organization';
import {LoadingSpinner} from './loading-spinner';
import {ErrorBoundary} from './error-boundary';

// ============================================================================
// Redirect Handler Types
// ============================================================================

export interface RedirectHandlerProps {
    /**
     * Redirect type to handle
     */
    type?: 'oauth' | 'magic-link' | 'invitation' | 'verification' | 'auto';

    /**
     * Success redirect URL
     */
    successUrl?: string;

    /**
     * Error redirect URL
     */
    errorUrl?: string;

    /**
     * Callback after successful redirect
     */
    onSuccess?: (result: any) => void;

    /**
     * Callback after failed redirect
     */
    onError?: (error: Error) => void;

    /**
     * Custom loading component
     */
    loadingComponent?: React.ReactNode;

    /**
     * Custom error component
     */
    errorComponent?: React.ComponentType<{ error: Error; retry: () => void }>;

    /**
     * Whether to show loading state
     */
    showLoading?: boolean;

    /**
     * Loading text
     */
    loadingText?: string;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Children to render instead of default handling
     */
    children?: React.ReactNode;
}

// ============================================================================
// URL Parameter Extraction
// ============================================================================

function getUrlParams(): URLSearchParams {
    if (typeof window === 'undefined') return new URLSearchParams();
    return new URLSearchParams(window.location.search);
}

function getUrlHash(): URLSearchParams {
    if (typeof window === 'undefined') return new URLSearchParams();
    const hash = window.location.hash;
    return new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
}

function getAllParams(): URLSearchParams {
    const params = getUrlParams();
    const hashParams = getUrlHash();

    // Merge hash params into query params
    hashParams.forEach((value, key) => {
        if (!params.has(key)) {
            params.set(key, value);
        }
    });

    return params;
}

// ============================================================================
// Redirect Type Detection
// ============================================================================

function detectRedirectType(): string | null {
    const params = getAllParams();

    // OAuth callback detection
    if (params.has('code') && params.has('state')) {
        return 'oauth';
    }

    // Magic link detection
    if (params.has('token') && params.has('type')) {
        const type = params.get('type');
        if (type === 'magic_link' || type === 'email_verification') {
            return 'magic-link';
        }
    }

    // Invitation detection
    if (params.has('invitation_token') || params.has('invite')) {
        return 'invitation';
    }

    // Verification detection
    if (params.has('verification_token') || params.has('verify')) {
        return 'verification';
    }

    // Error detection
    if (params.has('error') || params.has('error_description')) {
        return 'error';
    }

    return null;
}

// ============================================================================
// OAuth Redirect Handler
// ============================================================================

function OAuthRedirectHandler({
                                  onSuccess,
                                  onError,
                                  successUrl,
                                  errorUrl
                              }: {
    onSuccess?: (result: any) => void;
    onError?: (error: Error) => void;
    successUrl?: string;
    errorUrl?: string;
}) {
    const { handleCallback } = useOAuth();
    const [isProcessing, setIsProcessing] = React.useState(true);
    const [error, setError] = React.useState<Error | null>(null);

    React.useEffect(() => {
        const processOAuthCallback = async () => {
            try {
                const params = getAllParams();
                const code = params.get('code');
                const state = params.get('state');
                const provider = params.get('provider') || 'google';
                const errorParam = params.get('error');

                if (errorParam) {
                    const errorDescription = params.get('error_description') || 'OAuth authentication failed';
                    throw new Error(`OAuth Error: ${errorParam} - ${errorDescription}`);
                }

                if (!code) {
                    throw new Error('No authorization code received from OAuth provider');
                }

                const result = await handleCallback(provider, code, state);

                if (result.success) {
                    onSuccess?.(result);

                    // Redirect to success URL
                    if (successUrl) {
                        window.location.href = successUrl;
                    } else {
                        // Clean up URL and redirect to dashboard
                        window.history.replaceState({}, document.title, window.location.pathname);
                        window.location.href = '/dashboard';
                    }
                } else {
                    throw new Error(result.error || 'OAuth authentication failed');
                }
            } catch (err) {
                const error = err instanceof Error ? err : new Error('OAuth processing failed');
                setError(error);
                onError?.(error);

                // Redirect to error URL
                if (errorUrl) {
                    setTimeout(() => {
                        window.location.href = errorUrl;
                    }, 3000);
                }
            } finally {
                setIsProcessing(false);
            }
        };

        processOAuthCallback();
    }, [handleCallback, onSuccess, onError, successUrl, errorUrl]);

    if (error) {
        return (
            <div className="text-center">
                <div className="text-danger-600 mb-4">
                    <svg className="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <h3 className="text-lg font-semibold">Authentication Failed</h3>
                    <p className="text-sm text-default-500 mt-2">{error.message}</p>
                </div>
                {errorUrl && (
                    <p className="text-xs text-default-400">
                        Redirecting to sign in page...
                    </p>
                )}
            </div>
        );
    }

    return (
        <LoadingSpinner
            variant="spinner"
            size="lg"
            showText
            text="Completing sign in..."
            centered
        />
    );
}

// ============================================================================
// Magic Link Redirect Handler
// ============================================================================

function MagicLinkRedirectHandler({
                                      onSuccess,
                                      onError,
                                      successUrl,
                                      errorUrl
                                  }: {
    onSuccess?: (result: any) => void;
    onError?: (error: Error) => void;
    successUrl?: string;
    errorUrl?: string;
}) {
    const { verifyFromUrl } = useMagicLink();
    const [isProcessing, setIsProcessing] = React.useState(true);
    const [error, setError] = React.useState<Error | null>(null);

    React.useEffect(() => {
        const processMagicLink = async () => {
            try {
                const result = await verifyFromUrl();

                if (result.success) {
                    onSuccess?.(result);

                    // Handle MFA requirement
                    if (result.requiresAdditionalVerification) {
                        const params = new URLSearchParams();
                        params.set('mfa_token', result.mfaToken || '');
                        window.location.href = `/auth/mfa?${params.toString()}`;
                        return;
                    }

                    // Redirect to success URL
                    if (successUrl) {
                        window.location.href = successUrl;
                    } else {
                        // Clean up URL and redirect
                        window.history.replaceState({}, document.title, window.location.pathname);
                        window.location.href = '/dashboard';
                    }
                } else {
                    throw new Error(result.error || 'Magic link verification failed');
                }
            } catch (err) {
                const error = err instanceof Error ? err : new Error('Magic link processing failed');
                setError(error);
                onError?.(error);

                // Redirect to error URL
                if (errorUrl) {
                    setTimeout(() => {
                        window.location.href = errorUrl;
                    }, 3000);
                }
            } finally {
                setIsProcessing(false);
            }
        };

        processMagicLink();
    }, [verifyFromUrl, onSuccess, onError, successUrl, errorUrl]);

    if (error) {
        return (
            <div className="text-center">
                <div className="text-danger-600 mb-4">
                    <svg className="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <h3 className="text-lg font-semibold">Verification Failed</h3>
                    <p className="text-sm text-default-500 mt-2">{error.message}</p>
                </div>
                {errorUrl && (
                    <p className="text-xs text-default-400">
                        Redirecting to sign in page...
                    </p>
                )}
            </div>
        );
    }

    return (
        <LoadingSpinner
            variant="pulse"
            size="lg"
            showText
            text="Verifying magic link..."
            centered
        />
    );
}

// ============================================================================
// Invitation Redirect Handler
// ============================================================================

function InvitationRedirectHandler({
                                       onSuccess,
                                       onError,
                                       successUrl,
                                       errorUrl
                                   }: {
    onSuccess?: (result: any) => void;
    onError?: (error: Error) => void;
    successUrl?: string;
    errorUrl?: string;
}) {
    const { acceptInvitation } = useOrganization();
    const [isProcessing, setIsProcessing] = React.useState(true);
    const [error, setError] = React.useState<Error | null>(null);

    React.useEffect(() => {
        const processInvitation = async () => {
            try {
                const params = getAllParams();
                const invitationToken = params.get('invitation_token') || params.get('invite');

                if (!invitationToken) {
                    throw new Error('No invitation token found');
                }

                await acceptInvitation(invitationToken);

                onSuccess?.({ invitationToken });

                // Redirect to success URL
                if (successUrl) {
                    window.location.href = successUrl;
                } else {
                    // Clean up URL and redirect
                    window.history.replaceState({}, document.title, window.location.pathname);
                    window.location.href = '/dashboard';
                }
            } catch (err) {
                const error = err instanceof Error ? err : new Error('Invitation processing failed');
                setError(error);
                onError?.(error);

                // Redirect to error URL
                if (errorUrl) {
                    setTimeout(() => {
                        window.location.href = errorUrl;
                    }, 3000);
                }
            } finally {
                setIsProcessing(false);
            }
        };

        processInvitation();
    }, [acceptInvitation, onSuccess, onError, successUrl, errorUrl]);

    if (error) {
        return (
            <div className="text-center">
                <div className="text-danger-600 mb-4">
                    <svg className="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <h3 className="text-lg font-semibold">Invitation Failed</h3>
                    <p className="text-sm text-default-500 mt-2">{error.message}</p>
                </div>
                {errorUrl && (
                    <p className="text-xs text-default-400">
                        Redirecting to sign in page...
                    </p>
                )}
            </div>
        );
    }

    return (
        <LoadingSpinner
            variant="dots"
            size="lg"
            showText
            text="Processing invitation..."
            centered
        />
    );
}

// ============================================================================
// Main Redirect Handler Component
// ============================================================================

export function RedirectHandler({
                                    type = 'auto',
                                    successUrl,
                                    errorUrl,
                                    onSuccess,
                                    onError,
                                    loadingComponent,
                                    errorComponent: ErrorComponent,
                                    showLoading = true,
                                    loadingText = 'Processing...',
                                    className = '',
                                    children,
                                }: RedirectHandlerProps) {
    // Auto-detect redirect type if not specified
    const detectedType = type === 'auto' ? detectRedirectType() : type;

    // If no redirect type detected and no children, don't render anything
    if (!detectedType && !children) {
        return null;
    }

    // Render children if provided
    if (children) {
        return <div className={className}>{children}</div>;
    }

    // Default loading component
    const defaultLoading = showLoading ? (
        loadingComponent || (
            <div className="flex items-center justify-center min-h-64">
                <LoadingSpinner
                    variant="spinner"
                    size="lg"
                    showText
                    text={loadingText}
                    centered
                />
            </div>
        )
    ) : null;

    // Render appropriate handler based on type
    const renderHandler = () => {
        switch (detectedType) {
            case 'oauth':
                return (
                    <OAuthRedirectHandler
                        onSuccess={onSuccess}
                        onError={onError}
                        successUrl={successUrl}
                        errorUrl={errorUrl}
                    />
                );

            case 'magic-link':
                return (
                    <MagicLinkRedirectHandler
                        onSuccess={onSuccess}
                        onError={onError}
                        successUrl={successUrl}
                        errorUrl={errorUrl}
                    />
                );

            case 'invitation':
                return (
                    <InvitationRedirectHandler
                        onSuccess={onSuccess}
                        onError={onError}
                        successUrl={successUrl}
                        errorUrl={errorUrl}
                    />
                );

            case 'error':
                const params = getAllParams();
                const errorMessage = params.get('error_description') || params.get('error') || 'An error occurred';
                const error = new Error(errorMessage);

                if (ErrorComponent) {
                    return <ErrorComponent error={error} retry={() => window.location.reload()} />;
                }

                return (
                    <div className="text-center">
                        <div className="text-danger-600 mb-4">
                            <svg className="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                            </svg>
                            <h3 className="text-lg font-semibold">Authentication Error</h3>
                            <p className="text-sm text-default-500 mt-2">{errorMessage}</p>
                        </div>
                        {errorUrl && (
                            <p className="text-xs text-default-400">
                                Redirecting to sign in page...
                            </p>
                        )}
                    </div>
                );

            default:
                return defaultLoading;
        }
    };

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className={`${className}`}
        >
            <ErrorBoundary
                title="Redirect Processing Error"
                subtitle="There was a problem processing the authentication redirect."
                onError={onError}
                showDetails={process.env.NODE_ENV === 'development'}
            >
                {renderHandler()}
            </ErrorBoundary>
        </motion.div>
    );
}

// ============================================================================
// Redirect Handler Hook
// ============================================================================

export function useRedirectHandler() {
    const [redirectType, setRedirectType] = React.useState<string | null>(null);
    const [isProcessing, setIsProcessing] = React.useState(false);
    const [error, setError] = React.useState<Error | null>(null);

    React.useEffect(() => {
        const type = detectRedirectType();
        setRedirectType(type);
        setIsProcessing(!!type);
    }, []);

    const handleSuccess = React.useCallback((result: any) => {
        setIsProcessing(false);
        setError(null);
    }, []);

    const handleError = React.useCallback((error: Error) => {
        setIsProcessing(false);
        setError(error);
    }, []);

    return {
        redirectType,
        isProcessing,
        error,
        handleSuccess,
        handleError,
        hasRedirect: !!redirectType,
    };
}

// ============================================================================
// Export
// ============================================================================

export default RedirectHandler;