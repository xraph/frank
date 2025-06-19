/**
 * @frank-auth/react - useMagicLink Hook
 *
 * Magic link authentication hook that provides passwordless email-based
 * authentication with customizable email templates and verification flow.
 */

import {useCallback, useEffect, useMemo, useState} from 'react';

import type {MagicLinkRequest,} from '@frank-auth/client';

import {FrankAuth} from '@frank-auth/sdk';
import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';

// ============================================================================
// Magic Link Hook Interface
// ============================================================================

export interface UseMagicLinkReturn {
    // Magic link state
    isLoading: boolean;
    error: AuthError | null;
    lastSentEmail: string | null;
    lastSentAt: Date | null;
    canResend: boolean;
    timeUntilResend: number; // seconds

    // Magic link operations
    sendMagicLink: (email: string, options?: MagicLinkOptions) => Promise<MagicLinkSendResult>;
    verifyMagicLink: (token: string) => Promise<MagicLinkVerifyResult>;
    resendMagicLink: () => Promise<MagicLinkSendResult>;

    // Magic link verification (for URL-based verification)
    verifyFromUrl: (url?: string) => Promise<MagicLinkVerifyResult>;
    extractTokenFromUrl: (url?: string) => string | null;

    // Utility methods
    isValidEmail: (email: string) => boolean;
    clearState: () => void;
}

export interface MagicLinkOptions {
    redirectUrl?: string;
    organizationId?: string;
    customData?: Record<string, any>;
    template?: string;
    expiresIn?: number; // seconds
    locale?: string;
}

export interface MagicLinkSendResult {
    success: boolean;
    email: string;
    message: string;
    expiresAt: Date;
    error?: string;
}

export interface MagicLinkVerifyResult {
    success: boolean;
    user?: any;
    session?: any;
    error?: string;
    requiresAdditionalVerification?: boolean;
    mfaToken?: string;
}

// ============================================================================
// Magic Link Configurations
// ============================================================================

export const MAGIC_LINK_CONFIG = {
    // Default expiration time (15 minutes)
    DEFAULT_EXPIRES_IN: 15 * 60,

    // Minimum time between sends (60 seconds)
    RESEND_COOLDOWN: 60,

    // Email validation regex
    EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,

    // Default templates
    TEMPLATES: {
        SIGN_IN: 'magic-link-sign-in',
        SIGN_UP: 'magic-link-sign-up',
        VERIFY_EMAIL: 'magic-link-verify-email',
        PASSWORD_RESET: 'magic-link-password-reset',
    },

    // URL parameter names
    URL_PARAMS: {
        TOKEN: 'token',
        EMAIL: 'email',
        TYPE: 'type',
        REDIRECT: 'redirect_to',
    },
} as const;

// ============================================================================
// Main useMagicLink Hook
// ============================================================================

/**
 * Magic link authentication hook for passwordless email authentication
 *
 * @example Basic magic link sign-in
 * ```tsx
 * import { useMagicLink } from '@frank-auth/react';
 *
 * function MagicLinkSignIn() {
 *   const {
 *     sendMagicLink,
 *     isLoading,
 *     error,
 *     lastSentEmail,
 *     canResend,
 *     resendMagicLink,
 *     isValidEmail
 *   } = useMagicLink();
 *
 *   const [email, setEmail] = useState('');
 *   const [sent, setSent] = useState(false);
 *
 *   const handleSend = async () => {
 *     if (!isValidEmail(email)) {
 *       alert('Please enter a valid email address');
 *       return;
 *     }
 *
 *     try {
 *       const result = await sendMagicLink(email, {
 *         redirectUrl: '/dashboard',
 *         template: 'sign-in'
 *       });
 *
 *       if (result.success) {
 *         setSent(true);
 *       }
 *     } catch (error) {
 *       console.error('Failed to send magic link:', error);
 *     }
 *   };
 *
 *   const handleResend = async () => {
 *     try {
 *       await resendMagicLink();
 *     } catch (error) {
 *       console.error('Failed to resend magic link:', error);
 *     }
 *   };
 *
 *   if (sent) {
 *     return (
 *       <div>
 *         <h3>Check your email</h3>
 *         <p>We sent a magic link to {lastSentEmail}</p>
 *         <p>Click the link in your email to sign in.</p>
 *
 *         {canResend ? (
 *           <button onClick={handleResend} disabled={isLoading}>
 *             Resend magic link
 *           </button>
 *         ) : (
 *           <p>You can resend the link in a few seconds</p>
 *         )}
 *
 *         {error && <p style={{color: 'red'}}>{error.message}</p>}
 *       </div>
 *     );
 *   }
 *
 *   return (
 *     <div>
 *       <h3>Sign in with magic link</h3>
 *       <input
 *         type="email"
 *         value={email}
 *         onChange={(e) => setEmail(e.target.value)}
 *         placeholder="Enter your email address"
 *         disabled={isLoading}
 *       />
 *       <button onClick={handleSend} disabled={isLoading || !email}>
 *         {isLoading ? 'Sending...' : 'Send magic link'}
 *       </button>
 *
 *       {error && <p style={{color: 'red'}}>{error.message}</p>}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Magic link verification page
 * ```tsx
 * import { useEffect, useState } from 'react';
 * import { useMagicLink } from '@frank-auth/react';
 * import { useSearchParams, useNavigate } from 'react-router-dom';
 *
 * function MagicLinkVerify() {
 *   const { verifyFromUrl, isLoading } = useMagicLink();
 *   const [searchParams] = useSearchParams();
 *   const navigate = useNavigate();
 *   const [status, setStatus] = useState('verifying');
 *
 *   useEffect(() => {
 *     const verify = async () => {
 *       try {
 *         const result = await verifyFromUrl();
 *
 *         if (result.success) {
 *           setStatus('success');
 *
 *           // Check for MFA requirement
 *           if (result.requiresAdditionalVerification) {
 *             navigate('/mfa', { state: { mfaToken: result.mfaToken } });
 *           } else {
 *             // Redirect to dashboard or intended page
 *             const redirectTo = searchParams.get('redirect_to') || '/dashboard';
 *             navigate(redirectTo);
 *           }
 *         } else {
 *           setStatus('error');
 *         }
 *       } catch (error) {
 *         console.error('Magic link verification failed:', error);
 *         setStatus('error');
 *       }
 *     };
 *
 *     verify();
 *   }, [verifyFromUrl, navigate, searchParams]);
 *
 *   if (isLoading || status === 'verifying') {
 *     return <div>Verifying magic link...</div>;
 *   }
 *
 *   if (status === 'success') {
 *     return <div>Success! Redirecting...</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <h3>Invalid or expired magic link</h3>
 *       <p>The magic link you clicked is invalid or has expired.</p>
 *       <button onClick={() => navigate('/sign-in')}>
 *         Try again
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Magic link with organization invitation
 * ```tsx
 * function OrganizationInvite({ invitationToken, organizationId }) {
 *   const { sendMagicLink } = useMagicLink();
 *   const [email, setEmail] = useState('');
 *
 *   const handleAcceptInvite = async () => {
 *     try {
 *       await sendMagicLink(email, {
 *         organizationId,
 *         customData: {
 *           invitationToken,
 *           action: 'accept_invitation'
 *         },
 *         template: 'organization-invite',
 *         redirectUrl: `/organizations/${organizationId}/welcome`
 *       });
 *     } catch (error) {
 *       console.error('Failed to send invitation magic link:', error);
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       <h3>Join Organization</h3>
 *       <p>Enter your email to receive a secure link to join the organization.</p>
 *       <input
 *         type="email"
 *         value={email}
 *         onChange={(e) => setEmail(e.target.value)}
 *         placeholder="Enter your email address"
 *       />
 *       <button onClick={handleAcceptInvite}>
 *         Send invitation link
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useMagicLink(): UseMagicLinkReturn {
    const { activeOrganization, reload } = useAuth();
    const { apiUrl, publishableKey, features, linksPath, frontendUrl } = useConfig();

    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);
    const [lastSentEmail, setLastSentEmail] = useState<string | null>(null);
    const [lastSentAt, setLastSentAt] = useState<Date | null>(null);

    // Initialize Frank Auth SDK
    const frankAuth = useMemo(() => {
        return new FrankAuth({
            publishableKey,
            apiUrl,
        });
    }, [publishableKey, apiUrl]);

    // Check if magic links are available
    const isMagicLinkAvailable = useMemo(() => features.magicLink, [features.magicLink]);

    // Calculate resend availability
    const canResend = useMemo(() => {
        if (!lastSentAt) return false;
        const timeSinceLastSend = (Date.now() - lastSentAt.getTime()) / 1000;
        return timeSinceLastSend >= MAGIC_LINK_CONFIG.RESEND_COOLDOWN;
    }, [lastSentAt]);

    const timeUntilResend = useMemo(() => {
        if (!lastSentAt || canResend) return 0;
        const timeSinceLastSend = (Date.now() - lastSentAt.getTime()) / 1000;
        return Math.max(0, MAGIC_LINK_CONFIG.RESEND_COOLDOWN - timeSinceLastSend);
    }, [lastSentAt, canResend]);

    // Update countdown timer
    useEffect(() => {
        if (!lastSentAt || canResend) return;

        const interval = setInterval(() => {
            // This will trigger the useMemo recalculation
        }, 1000);

        return () => clearInterval(interval);
    }, [lastSentAt, canResend]);

    // Error handler
    const handleError = useCallback((err: any) => {
        const authError: AuthError = {
            code: err.code || 'UNKNOWN_ERROR',
            message: err.message || 'An unknown error occurred',
            details: err.details,
            field: err.field,
        };
        setError(authError);
        throw authError;
    }, []);

    // Email validation
    const isValidEmail = useCallback((email: string): boolean => {
        return MAGIC_LINK_CONFIG.EMAIL_REGEX.test(email);
    }, []);

    // Extract token from URL
    const extractTokenFromUrl = useCallback((url?: string): string | null => {
        const urlToCheck = url || window.location.href;

        try {
            const urlObj = new URL(urlToCheck);
            return urlObj.searchParams.get(MAGIC_LINK_CONFIG.URL_PARAMS.TOKEN);
        } catch {
            return null;
        }
    }, []);

    // Send magic link
    const sendMagicLink = useCallback(async (
        email: string,
        options?: MagicLinkOptions
    ): Promise<MagicLinkSendResult> => {
        if (!isMagicLinkAvailable) throw new Error('Magic links not available');
        if (!isValidEmail(email)) throw new Error('Invalid email address');

        try {
            setIsLoading(true);
            setError(null);

            const magicLinkRequest: MagicLinkRequest = {
                email,
                redirectUrl: options?.redirectUrl || `${frontendUrl ?? window.location.origin}${linksPath?.magicLink}`,
                // organizationId: options?.organizationId || activeOrganization?.id,
                // customData: options?.customData,
                expiresIn: options?.expiresIn || MAGIC_LINK_CONFIG.DEFAULT_EXPIRES_IN,
                // locale: options?.locale,
            };

            const response = await frankAuth.sendMagicLink(magicLinkRequest);

            // Update state
            setLastSentEmail(email);
            setLastSentAt(new Date());

            return {
                success: response.success,
                email,
                message: response.message,
                expiresAt: new Date(Date.now() + (magicLinkRequest.expiresIn! * 1000)),
            };
        } catch (err) {
            return {
                success: false,
                email,
                expiresAt: new Date(),
                error: err.message || 'Failed to send magic link',
            };
        } finally {
            setIsLoading(false);
        }
    }, [frankAuth, isMagicLinkAvailable, isValidEmail, activeOrganization]);

    // Verify magic link
    const verifyMagicLink = useCallback(async (token: string): Promise<MagicLinkVerifyResult> => {
        if (!isMagicLinkAvailable) throw new Error('Magic links not available');
        if (!token) throw new Error('Verification token is required');

        try {
            setIsLoading(true);
            setError(null);

            const response = await frankAuth.verifyMagicLink(token);

            if (response.session) {
                // Reload auth state with new user session
                await reload();

                return {
                    success: true,
                    user: response.user,
                    session: response.session,
                    requiresAdditionalVerification: response.mfaRequired,
                    mfaToken: response.mfaToken,
                };
            } else {
                return {
                    success: false,
                    error: response.error || 'Magic link verification failed',
                };
            }
        } catch (err) {
            return {
                success: false,
                error: err.message || 'Magic link verification failed',
            };
        } finally {
            setIsLoading(false);
        }
    }, [frankAuth, isMagicLinkAvailable, reload]);

    // Verify magic link from URL
    const verifyFromUrl = useCallback(async (url?: string): Promise<MagicLinkVerifyResult> => {
        const token = extractTokenFromUrl(url);

        if (!token) {
            return {
                success: false,
                error: 'No verification token found in URL',
            };
        }

        return verifyMagicLink(token);
    }, [extractTokenFromUrl, verifyMagicLink]);

    // Resend magic link
    const resendMagicLink = useCallback(async (): Promise<MagicLinkSendResult> => {
        if (!lastSentEmail) {
            throw new Error('No previous magic link to resend');
        }

        if (!canResend) {
            throw new Error(`Please wait ${Math.ceil(timeUntilResend)} seconds before resending`);
        }

        return sendMagicLink(lastSentEmail);
    }, [lastSentEmail, canResend, timeUntilResend, sendMagicLink]);

    // Clear state
    const clearState = useCallback(() => {
        setError(null);
        setLastSentEmail(null);
        setLastSentAt(null);
    }, []);

    return {
        // Magic link state
        isLoading,
        error,
        lastSentEmail,
        lastSentAt,
        canResend,
        timeUntilResend,

        // Magic link operations
        sendMagicLink,
        verifyMagicLink,
        resendMagicLink,

        // Magic link verification
        verifyFromUrl,
        extractTokenFromUrl,

        // Utility methods
        isValidEmail,
        clearState,
    };
}

// ============================================================================
// Specialized Magic Link Hooks
// ============================================================================

/**
 * Hook for magic link sign-in flow
 */
export function useMagicLinkSignIn() {
    const {
        sendMagicLink,
        isLoading,
        error,
        lastSentEmail,
        canResend,
        resendMagicLink,
        isValidEmail,
        clearState,
    } = useMagicLink();

    const [signInState, setSignInState] = useState<'idle' | 'email_sent' | 'verified'>('idle');

    const signIn = useCallback(async (email: string, redirectUrl?: string) => {
        if (!isValidEmail(email)) {
            throw new Error('Please enter a valid email address');
        }

        try {
            const result = await sendMagicLink(email, {
                redirectUrl: redirectUrl || '/dashboard',
                template: MAGIC_LINK_CONFIG.TEMPLATES.SIGN_IN,
            });

            if (result.success) {
                setSignInState('email_sent');
            }

            return result;
        } catch (error) {
            setSignInState('idle');
            throw error;
        }
    }, [sendMagicLink, isValidEmail]);

    const reset = useCallback(() => {
        setSignInState('idle');
        clearState();
    }, [clearState]);

    return {
        signIn,
        resend: resendMagicLink,
        reset,
        state: signInState,
        sentTo: lastSentEmail,
        canResend,
        isLoading,
        error,
        isValidEmail,
    };
}

/**
 * Hook for magic link verification flow
 */
export function useMagicLinkVerification() {
    const {
        verifyFromUrl,
        verifyMagicLink,
        extractTokenFromUrl,
        isLoading,
        error,
    } = useMagicLink();

    const [verificationState, setVerificationState] = useState<'idle' | 'verifying' | 'success' | 'error'>('idle');
    const [verificationResult, setVerificationResult] = useState<MagicLinkVerifyResult | null>(null);

    // Auto-verify if token is in URL
    useEffect(() => {
        const token = extractTokenFromUrl();
        if (token && verificationState === 'idle') {
            verify(token);
        }
    }, [extractTokenFromUrl, verificationState]);

    const verify = useCallback(async (token?: string) => {
        try {
            setVerificationState('verifying');

            const result = token
                ? await verifyMagicLink(token)
                : await verifyFromUrl();

            setVerificationResult(result);
            setVerificationState(result.success ? 'success' : 'error');

            return result;
        } catch (error) {
            setVerificationState('error');
            setVerificationResult({
                success: false,
                error: error.message,
            });
            throw error;
        }
    }, [verifyMagicLink, verifyFromUrl]);

    return {
        verify,
        state: verificationState,
        result: verificationResult,
        isVerifying: verificationState === 'verifying' || isLoading,
        isSuccess: verificationState === 'success',
        isError: verificationState === 'error',
        error: error || verificationResult?.error,
        requiresMFA: verificationResult?.requiresAdditionalVerification,
        mfaToken: verificationResult?.mfaToken,
    };
}

/**
 * Hook for magic link password reset flow
 */
export function useMagicLinkPasswordReset() {
    const { sendMagicLink, isValidEmail } = useMagicLink();

    const sendResetLink = useCallback(async (email: string) => {
        if (!isValidEmail(email)) {
            throw new Error('Please enter a valid email address');
        }

        return sendMagicLink(email, {
            template: MAGIC_LINK_CONFIG.TEMPLATES.PASSWORD_RESET,
            redirectUrl: `${window.location.origin}/auth/reset-password`,
        });
    }, [sendMagicLink, isValidEmail]);

    return {
        sendResetLink,
        isValidEmail,
    };
}