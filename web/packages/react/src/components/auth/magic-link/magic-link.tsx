
/**
 * @frank-auth/react - Magic Link Verification Components
 *
 * Components for handling magic link verification from email links,
 * with support for different verification types and redirect handling.
 */

'use client';

import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {Button as HButton, Divider, Link} from '@heroui/react';
import {motion} from 'framer-motion';
import {ArrowPathIcon, CheckCircleIcon, EnvelopeIcon, ExclamationTriangleIcon} from '@heroicons/react/24/outline';

import {useMagicLink} from '../../../hooks/use-magic-link';
import {useAuth} from '../../../hooks/use-auth';
import {useConfig} from '../../../hooks/use-config';
import FormWrapper from '../../forms/form-wrapper';
import {RadiusT, SizeT} from "@/types";

// ============================================================================
// Magic Link Verification Types
// ============================================================================

export interface MagicLinkVerifyProps {
    /**
     * Magic link token (if not in URL)
     */
    token?: string;

    /**
     * Verification type
     */
    type?: 'sign-in' | 'sign-up' | 'email-verification' | 'password-reset' | 'organization-invite';

    /**
     * Success callback
     */
    onSuccess?: (result: any) => void;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Custom title
     */
    title?: string;

    /**
     * Custom subtitle
     */
    subtitle?: string;

    /**
     * Redirect URL after success
     */
    redirectUrl?: string;

    /**
     * Show resend option
     */
    showResend?: boolean;

    /**
     * Email for resend
     */
    email?: string;

    /**
     * Component variant
     */
    variant?: 'default' | 'card' | 'modal';

    /**
     * Size
     */
    size?: SizeT;

    radius?: RadiusT;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Auto-verify on mount
     */
    autoVerify?: boolean;
}

// ============================================================================
// Magic Link Verification Status Component
// ============================================================================

const VerificationStatus = React.memo(({
                                           status,
                                           type,
                                           error,
                                           onRetry,
                                           onResend,
    size = 'md',
    radius = 'md',
                                       }: {
    status: 'verifying' | 'success' | 'error' | 'expired';
    type: string;
    error?: string;
    onRetry?: () => void;
    onResend?: () => void;
    size?: SizeT;
    radius?: RadiusT;
}) => {
    const { components } = useConfig();
    const Button = components.Button ?? HButton;

    const getStatusContent = () => {
        switch (status) {
            case 'verifying':
                return {
                    icon: <ArrowPathIcon className="w-8 h-8 text-primary-600 animate-spin" />,
                    title: 'Verifying...',
                    subtitle: 'Please wait while we verify your magic link.',
                    bgColor: 'bg-primary-100 dark:bg-primary-900/30',
                };

            case 'success':
                return {
                    icon: <CheckCircleIcon className="w-8 h-8 text-success-600" />,
                    title: 'Verification Successful!',
                    subtitle: getSuccessMessage(type),
                    bgColor: 'bg-success-100 dark:bg-success-900/30',
                };

            case 'error':
                return {
                    icon: <ExclamationTriangleIcon className="w-8 h-8 text-danger-600" />,
                    title: 'Verification Failed',
                    subtitle: error || 'The magic link is invalid or has expired.',
                    bgColor: 'bg-danger-100 dark:bg-danger-900/30',
                };

            case 'expired':
                return {
                    icon: <ExclamationTriangleIcon className="w-8 h-8 text-warning-600" />,
                    title: 'Link Expired',
                    subtitle: 'This magic link has expired. Please request a new one.',
                    bgColor: 'bg-warning-100 dark:bg-warning-900/30',
                };

            default:
                return {
                    icon: <EnvelopeIcon className="w-8 h-8 text-default-500" />,
                    title: 'Magic Link',
                    subtitle: 'Click the link in your email to continue.',
                    bgColor: 'bg-default-100 dark:bg-default-900/30',
                };
        }
    };

    const getSuccessMessage = (type: string) => {
        switch (type) {
            case 'sign-in':
                return 'You have been successfully signed in.';
            case 'sign-up':
                return 'Your account has been created and verified.';
            case 'email-verification':
                return 'Your email address has been verified.';
            case 'password-reset':
                return 'You can now reset your password.';
            case 'organization-invite':
                return 'Welcome to the organization!';
            default:
                return 'Verification completed successfully.';
        }
    };

    const content = getStatusContent();

    return (
        <div className="text-center space-y-4">
            <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center ${content.bgColor}`}
            >
                {content.icon}
            </motion.div>

            <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">
                    {content.title}
                </h3>
                <p className="text-default-500 text-sm">
                    {content.subtitle}
                </p>
            </div>

            {status === 'error' && (
                <div className="space-y-2">
                    {onRetry && (
                        <Button
                            variant="bordered"
                            size={size}
                            radius={radius}
                            onPress={onRetry}
                        >
                            Try Again
                        </Button>
                    )}
                    {onResend && (
                        <Button
                            variant="light"
                            size={size}
                            radius={radius}
                            onPress={onResend}
                            startContent={<EnvelopeIcon className="w-4 h-4" />}
                        >
                            Resend Magic Link
                        </Button>
                    )}
                </div>
            )}

            {status === 'expired' && onResend && (
                <Button
                    color="primary"
                    onPress={onResend}
                    size={size}
                    radius={radius}
                    startContent={<EnvelopeIcon className="w-4 h-4" />}
                >
                    Send New Magic Link
                </Button>
            )}
        </div>
    );
});

VerificationStatus.displayName = 'VerificationStatus';

// ============================================================================
// Main Magic Link Verification Component
// ============================================================================

export function MagicLinkVerify({
                                    token,
                                    type = 'sign-in',
                                    onSuccess,
                                    onError,
                                    title,
                                    subtitle,
                                    redirectUrl,
                                    showResend = true,
                                    email,
                                    variant = 'default',
                                    size = 'md',
                                    className = '',
                                    autoVerify = true,
                                }: MagicLinkVerifyProps) {
    const {
        verifyMagicLink,
        verifyFromUrl,
        sendMagicLink,
        extractTokenFromUrl,
        isLoading,
        error,
    } = useMagicLink();

    const { components, linksPath } = useConfig();
    const { reload } = useAuth();

    const Button = components.Button ?? HButton;

    const [verificationStatus, setVerificationStatus] = useState<'idle' | 'verifying' | 'success' | 'error' | 'expired'>('idle');
    const [verificationError, setVerificationError] = useState<string | null>(null);

    // Extract token from URL or use provided token
    const magicLinkToken = useMemo(() => {
        return token || extractTokenFromUrl();
    }, [token, extractTokenFromUrl]);

    // Auto-verify on mount if token is available
    useEffect(() => {
        if (autoVerify && magicLinkToken && verificationStatus === 'idle') {
            handleVerify();
        }
    }, [autoVerify, magicLinkToken, verificationStatus]);

    // Handle verification
    const handleVerify = useCallback(async () => {
        if (!magicLinkToken) {
            setVerificationStatus('error');
            setVerificationError('No verification token found.');
            return;
        }

        try {
            setVerificationStatus('verifying');
            setVerificationError(null);

            const result = await verifyMagicLink(magicLinkToken);

            if (result.success) {
                setVerificationStatus('success');

                // Reload auth state to get updated user
                await reload();

                onSuccess?.(result);

                // Handle redirects
                if (redirectUrl) {
                    setTimeout(() => {
                        window.location.href = redirectUrl;
                    }, 2000);
                } else if (result.user) {
                    // Default redirects based on verification type
                    const defaultRedirects = {
                        'sign-in': '/dashboard',
                        'sign-up': '/welcome',
                        'email-verification': '/dashboard',
                        'password-reset': '/auth/reset-password',
                        'organization-invite': '/organization/welcome',
                    };

                    const defaultRedirect = defaultRedirects[type as keyof typeof defaultRedirects];
                    if (defaultRedirect) {
                        setTimeout(() => {
                            window.location.href = defaultRedirect;
                        }, 2000);
                    }
                }
            } else {
                if (result.error?.includes('expired')) {
                    setVerificationStatus('expired');
                } else {
                    setVerificationStatus('error');
                }
                setVerificationError(result.error || 'Verification failed');
                onError?.(new Error(result.error || 'Verification failed'));
            }
        } catch (err) {
            setVerificationStatus('error');
            const errorMessage = err instanceof Error ? err.message : 'Verification failed';
            setVerificationError(errorMessage);
            onError?.(err instanceof Error ? err : new Error(errorMessage));
        }
    }, [magicLinkToken, verifyMagicLink, reload, onSuccess, onError, redirectUrl, type]);

    // Handle resend
    const handleResend = useCallback(async () => {
        if (!email) {
            console.warn('Cannot resend magic link: no email provided');
            return;
        }

        try {
            await sendMagicLink(email, {
                redirectUrl: redirectUrl || window.location.href,
            });

            // Reset status to show new verification UI
            setVerificationStatus('idle');
            setVerificationError(null);
        } catch (err) {
            console.error('Failed to resend magic link:', err);
        }
    }, [email, sendMagicLink, redirectUrl]);

    // Form wrapper props
    const formWrapperProps = useMemo(() => {
        const getTitle = () => {
            if (title) return title;

            switch (type) {
                case 'sign-in':
                    return 'Magic Link Sign In';
                case 'sign-up':
                    return 'Verify Your Account';
                case 'email-verification':
                    return 'Verify Email Address';
                case 'password-reset':
                    return 'Reset Password Link';
                case 'organization-invite':
                    return 'Organization Invitation';
                default:
                    return 'Magic Link Verification';
            }
        };

        const getSubtitle = () => {
            if (subtitle) return subtitle;

            if (verificationStatus === 'idle' && !magicLinkToken) {
                return 'Click the magic link in your email to continue.';
            }

            return 'Verifying your magic link...';
        };

        return {
            size,
            variant: 'flat' as const,
            className: `space-y-6 ${className}`,
            title: getTitle(),
            subtitle: getSubtitle(),
            showCard: variant === 'card',
        };
    }, [title, subtitle, type, size, className, variant, verificationStatus, magicLinkToken]);

    // Show verification status if we have a token or are in progress
    if (magicLinkToken || verificationStatus !== 'idle') {
        return (
            <FormWrapper {...formWrapperProps}>
                <VerificationStatus
                    status={verificationStatus}
                    type={type}
                    error={verificationError}
                    onRetry={handleVerify}
                    onResend={showResend && email ? handleResend : undefined}
                />

                {verificationStatus === 'success' && redirectUrl && (
                    <div className="text-center">
                        <div className="flex items-center justify-center gap-2 text-sm text-default-500">
                            <ArrowPathIcon className="w-4 h-4 animate-spin" />
                            <span>Redirecting...</span>
                        </div>
                    </div>
                )}
            </FormWrapper>
        );
    }

    // Show initial state if no token
    return (
        <FormWrapper {...formWrapperProps}>
            <div className="text-center space-y-4">
                <div className="mx-auto w-16 h-16 rounded-full bg-default-100 dark:bg-default-900/30 flex items-center justify-center">
                    <EnvelopeIcon className="w-8 h-8 text-default-500" />
                </div>

                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Check Your Email
                    </h3>
                    <p className="text-default-500 text-sm">
                        We've sent a magic link to your email address. Click the link to continue.
                    </p>
                </div>

                {showResend && email && (
                    <div className="space-y-2">
                        <p className="text-sm text-default-400">
                            Didn't receive the email?
                        </p>
                        <Button
                            variant="light"
                            size="sm"
                            onPress={handleResend}
                            isLoading={isLoading}
                            startContent={<EnvelopeIcon className="w-4 h-4" />}
                        >
                            Resend Magic Link
                        </Button>
                    </div>
                )}

                <Divider className="my-4" />

                <div className="text-center">
                    <Link href={linksPath?.signIn || '/auth/sign-in'} size="sm">
                        Back to Sign In
                    </Link>
                </div>
            </div>
        </FormWrapper>
    );
}

// ============================================================================
// Magic Link Verification Variants
// ============================================================================

/**
 * Magic Link Verification Card
 */
export function MagicLinkVerifyCard(props: Omit<MagicLinkVerifyProps, 'variant'>) {
    return <MagicLinkVerify {...props} variant="card" />;
}

/**
 * Email Verification Component
 */
export function EmailVerification(props: Omit<MagicLinkVerifyProps, 'type'>) {
    return <MagicLinkVerify {...props} type="email-verification" />;
}

/**
 * Organization Invitation Verification
 */
export function OrganizationInviteVerification(props: Omit<MagicLinkVerifyProps, 'type'>) {
    return <MagicLinkVerify {...props} type="organization-invite" />;
}

/**
 * Password Reset Link Verification
 */
export function PasswordResetLinkVerification(props: Omit<MagicLinkVerifyProps, 'type'>) {
    return <MagicLinkVerify {...props} type="password-reset" />;
}

// ============================================================================
// Export
// ============================================================================

export default MagicLinkVerify;