/**
 * @frank-auth/react - Magic Link Component
 *
 * Passwordless authentication component using magic links sent via email.
 * Supports organization customization and various UI states.
 */

'use client';

import React from 'react';
import {Button, Card, CardBody} from '@heroui/react';
import {motion} from 'framer-motion';
import {useMagicLink} from '../../../hooks/use-magic-link';
import {useConfig} from '../../../hooks/use-config';
import {EmailField} from '../../forms/email-field';
import {FormWrapper} from '../../forms/form-wrapper';
import {LoadingSpinner} from './loading-spinner';
import type {RadiusT, SizeT} from "@/types";

// ============================================================================
// Magic Link Types
// ============================================================================

export interface MagicLinkProps {
    /**
     * Component variant
     */
    variant?: 'form' | 'button' | 'card' | 'inline';

    /**
     * Magic link type
     */
    type?: 'sign-in' | 'sign-up' | 'verify-email' | 'password-reset';

    /**
     * Initial email value
     */
    email?: string;

    /**
     * Redirect URL after successful authentication
     */
    redirectUrl?: string;

    /**
     * Organization ID
     */
    organizationId?: string;

    /**
     * Success callback
     */
    onSuccess?: (result: any) => void;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Email sent callback
     */
    onEmailSent?: (email: string) => void;

    /**
     * Custom title
     */
    title?: string;

    /**
     * Custom subtitle
     */
    subtitle?: string;

    /**
     * Custom button text
     */
    buttonText?: string;

    /**
     * Whether to show form validation
     */
    showValidation?: boolean;

    /**
     * Whether to show resend functionality
     */
    showResend?: boolean;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Disabled state
     */
    disabled?: boolean;

    /**
     * Size variant
     */
    size?: SizeT;
    radius?: RadiusT;

    /**
     * Card props (for card variant)
     */
    cardProps?: any;

    /**
     * Button props (for button variant)
     */
    buttonProps?: any;
}

// ============================================================================
// Magic Link Form Component
// ============================================================================

function MagicLinkForm({
                           type = 'sign-in',
                           email: initialEmail = '',
                           redirectUrl,
                           organizationId,
                           onSuccess,
                           onError,
                           onEmailSent,
                           title,
                           subtitle,
                           buttonText,
                           showValidation = true,
                           showResend = true,
                           className = '',
                           disabled = false,
                           size = 'md',
    radius = 'md',
                       }: Omit<MagicLinkProps, 'variant'>) {
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

    const { organizationSettings } = useConfig();
    const [email, setEmail] = React.useState(initialEmail);
    const [emailSent, setEmailSent] = React.useState(false);

    // Generate default content based on type
    const getDefaultContent = () => {
        switch (type) {
            case 'sign-up':
                return {
                    title: 'Create your account',
                    subtitle: 'Enter your email to get started with a magic link',
                    buttonText: 'Send magic link',
                };
            case 'verify-email':
                return {
                    title: 'Verify your email',
                    subtitle: 'Click the link in your email to verify your account',
                    buttonText: 'Send verification link',
                };
            case 'password-reset':
                return {
                    title: 'Reset your password',
                    subtitle: 'Enter your email to receive a password reset link',
                    buttonText: 'Send reset link',
                };
            case 'sign-in':
            default:
                return {
                    title: 'Sign in with magic link',
                    subtitle: 'Enter your email to receive a secure sign-in link',
                    buttonText: 'Send magic link',
                };
        }
    };

    const defaultContent = getDefaultContent();
    const finalTitle = title || defaultContent.title;
    const finalSubtitle = subtitle || defaultContent.subtitle;
    const finalButtonText = buttonText || defaultContent.buttonText;

    // Handle form submission
    const handleSubmit = React.useCallback(async (e: React.FormEvent) => {
        e.preventDefault();

        if (!email || !isValidEmail(email)) {
            return;
        }

        try {
            const result = await sendMagicLink(email, {
                redirectUrl,
                organizationId,
                template: type,
            });

            if (result.success) {
                setEmailSent(true);
                onEmailSent?.(email);
                onSuccess?.(result);
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send magic link');
            onError?.(error);
        }
    }, [email, isValidEmail, sendMagicLink, redirectUrl, organizationId, type, onEmailSent, onSuccess, onError]);

    // Handle resend
    const handleResend = React.useCallback(async () => {
        try {
            const result = await resendMagicLink();
            if (result.success) {
                onEmailSent?.(email);
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to resend magic link');
            onError?.(error);
        }
    }, [resendMagicLink, email, onEmailSent, onError]);

    // Handle back to form
    const handleBackToForm = React.useCallback(() => {
        setEmailSent(false);
        clearState();
    }, [clearState]);

    // Email sent state
    if (emailSent) {
        return (
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className={`text-center space-y-4 ${className}`}
            >
                {/* Success Icon */}
                <div className="mx-auto w-16 h-16 bg-success-100 dark:bg-success-900/30 rounded-full flex items-center justify-center">
                    <svg className="w-8 h-8 text-success-600 dark:text-success-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                    </svg>
                </div>

                {/* Title */}
                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Check your email
                    </h3>
                    <p className="text-default-500 text-sm">
                        We sent a magic link to <strong>{lastSentEmail || email}</strong>
                    </p>
                </div>

                {/* Instructions */}
                <div className="bg-default-100 dark:bg-default-800 rounded-lg p-4">
                    <p className="text-sm text-default-600 dark:text-default-400">
                        Click the link in your email to {type === 'sign-up' ? 'create your account' : 'sign in'}.
                        The link will expire in 15 minutes.
                    </p>
                </div>

                {/* Actions */}
                <div className="space-y-3">
                    {showResend && (
                        <div>
                            {canResend ? (
                                <Button
                                    variant="light"
                                    color="primary"
                                    size={size}
                                    radius={radius}
                                    onPress={handleResend}
                                    isLoading={isLoading}
                                    isDisabled={disabled}
                                    disabled={disabled}
                                >
                                    Resend magic link
                                </Button>
                            ) : (
                                <p className="text-sm text-default-500">
                                    You can resend the link in a few seconds
                                </p>
                            )}
                        </div>
                    )}

                    <Button
                        variant="light"
                        size="sm"
                        radius={radius}
                        onPress={handleBackToForm}
                        isDisabled={isLoading}
                        disabled={isLoading}
                    >
                        Use a different email
                    </Button>
                </div>

                {/* Error Display */}
                {error && (
                    <div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
                        {error.message}
                    </div>
                )}
            </motion.div>
        );
    }

    // Form state
    return (
        <form onSubmit={handleSubmit} className={`space-y-4 ${className}`}>
            {/* Header */}
            <div className="text-center space-y-2">
                {finalTitle && (
                    <h3 className="text-xl font-semibold text-foreground">
                        {finalTitle}
                    </h3>
                )}
                {finalSubtitle && (
                    <p className="text-default-500 text-sm">
                        {finalSubtitle}
                    </p>
                )}
            </div>

            {/* Email Field */}
            <EmailField
                name="email"
                label="Email address"
                placeholder="Enter your email"
                value={email}
                onChange={setEmail}
                required
                disabled={disabled || isLoading}
                validateFormat={showValidation}
                size={size}
                radius={radius}
                autoFocus
            />

            {/* Submit Button */}
            <Button
                type="submit"
                color="primary"
                size={size}
                radius={radius}
                className="w-full"
                isLoading={isLoading}
                isDisabled={disabled || !email || (showValidation && !isValidEmail(email))}
                disabled={disabled || !email || (showValidation && !isValidEmail(email))}
            >
                {isLoading ? 'Sending...' : finalButtonText}
            </Button>

            {/* Error Display */}
            {error && (
                <div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
                    {error.message}
                </div>
            )}
        </form>
    );
}

// ============================================================================
// Magic Link Button Component
// ============================================================================

function MagicLinkButton({
                             type = 'sign-in',
                             email: initialEmail = '',
                             redirectUrl,
                             organizationId,
                             onSuccess,
                             onError,
                             onEmailSent,
                             buttonText,
                             className = '',
                             disabled = false,
                             size = 'md',
    radius = 'md',
                             buttonProps = {},
                         }: Omit<MagicLinkProps, 'variant'>) {
    const { sendMagicLink, isLoading } = useMagicLink();
    const [showEmailInput, setShowEmailInput] = React.useState(!initialEmail);
    const [email, setEmail] = React.useState(initialEmail);

    const getDefaultButtonText = () => {
        switch (type) {
            case 'sign-up': return 'Sign up with magic link';
            case 'verify-email': return 'Send verification link';
            case 'password-reset': return 'Send reset link';
            default: return 'Sign in with magic link';
        }
    };

    const finalButtonText = buttonText || getDefaultButtonText();

    const handleClick = React.useCallback(async () => {
        if (!email) {
            setShowEmailInput(true);
            return;
        }

        try {
            const result = await sendMagicLink(email, {
                redirectUrl,
                organizationId,
                template: type,
            });

            if (result.success) {
                onEmailSent?.(email);
                onSuccess?.(result);
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send magic link');
            onError?.(error);
        }
    }, [email, sendMagicLink, redirectUrl, organizationId, type, onEmailSent, onSuccess, onError]);

    if (showEmailInput && !initialEmail) {
        return (
            <div className={`space-y-3 ${className}`}>
                <EmailField
                    name="email"
                    label="Email address"
                    placeholder="Enter your email"
                    value={email}
                    onChange={setEmail}
                    required
                    disabled={disabled || isLoading}
                    size={size}
                    radius={radius}
                    autoFocus
                />
                <div className="flex gap-2">
                    <Button
                        color="primary"
                        size={size}
                        radius={radius}
                        onPress={handleClick}
                        isLoading={isLoading}
                        isDisabled={disabled || !email}
                        disabled={disabled || !email}
                        className="flex-1"
                        {...buttonProps}
                    >
                        {isLoading ? 'Sending...' : finalButtonText}
                    </Button>
                    <Button
                        variant="light"
                        size={size}
                        radius={radius}
                        onPress={() => setShowEmailInput(false)}
                        isDisabled={isLoading}
                    >
                        Cancel
                    </Button>
                </div>
            </div>
        );
    }

    return (
        <Button
            color="primary"
            size={size}
            radius={radius}
            onPress={handleClick}
            isLoading={isLoading}
            isDisabled={disabled}
            className={className}
            startContent={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
            }
            {...buttonProps}
        >
            {finalButtonText}
        </Button>
    );
}

// ============================================================================
// Main Magic Link Component
// ============================================================================

export function MagicLink({
                              variant = 'form',
                              cardProps = {},
    size = 'md',
    radius = 'md',
                              ...props
                          }: MagicLinkProps) {
    const { components } = useConfig();

    // Custom component override
    const CustomMagicLink = components.MagicLink;
    if (CustomMagicLink) {
        return <CustomMagicLink {...{ variant, cardProps, ...props }} />;
    }

    // Render based on variant
    switch (variant) {
        case 'button':
            return <MagicLinkButton {...props} />;

        case 'card':
            return (
                <Card {...cardProps}>
                    <CardBody>
                        <MagicLinkForm {...props} />
                    </CardBody>
                </Card>
            );

        case 'inline':
            return <MagicLinkForm {...props} />;

        case 'form':
        default:
            return (
                <FormWrapper
                    title={props.title}
                    subtitle={props.subtitle}
                    className={props.className}
                    showCard={false}
                    size={size}
                    radius={radius}
                >
                    <MagicLinkForm {...props} />
                </FormWrapper>
            );
    }
}

// ============================================================================
// Magic Link Verification Component
// ============================================================================

export interface MagicLinkVerificationProps {
    /**
     * Success callback
     */
    onSuccess?: (result: any) => void;

    /**
     * Error callback
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
     * Custom className
     */
    className?: string;

    size?: SizeT;
    radius?: RadiusT;
}

export function MagicLinkVerification({
                                          onSuccess,
                                          onError,
                                          loadingComponent,
                                          errorComponent: ErrorComponent,
                                          className = '',
    size = 'md',
    radius = 'md',
                                      }: MagicLinkVerificationProps) {
    const { verifyFromUrl, isLoading, error } = useMagicLink();
    const [verificationState, setVerificationState] = React.useState<'verifying' | 'success' | 'error'>('verifying');
    const [result, setResult] = React.useState<any>(null);

    React.useEffect(() => {
        const verify = async () => {
            try {
                const verificationResult = await verifyFromUrl();

                if (verificationResult.success) {
                    setVerificationState('success');
                    setResult(verificationResult);
                    onSuccess?.(verificationResult);
                } else {
                    throw new Error(verificationResult.error || 'Verification failed');
                }
            } catch (err) {
                const error = err instanceof Error ? err : new Error('Verification failed');
                setVerificationState('error');
                onError?.(error);
            }
        };

        verify();
    }, [verifyFromUrl, onSuccess, onError]);

    if (verificationState === 'verifying' || isLoading) {
        return (
            <div className={`flex items-center justify-center min-h-64 ${className}`}>
                {loadingComponent || (
                    <LoadingSpinner
                        variant="pulse"
                        size="lg"
                        showText
                        text="Verifying magic link..."
                        centered
                    />
                )}
            </div>
        );
    }

    if (verificationState === 'error' || error) {
        const verificationError = error || new Error('Verification failed');

        if (ErrorComponent) {
            return <ErrorComponent error={verificationError} retry={() => window.location.reload()} />;
        }

        return (
            <div className={`text-center space-y-4 ${className}`}>
                <div className="mx-auto w-16 h-16 bg-danger-100 dark:bg-danger-900/30 rounded-full flex items-center justify-center">
                    <svg className="w-8 h-8 text-danger-600 dark:text-danger-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                </div>

                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Verification Failed
                    </h3>
                    <p className="text-default-500 text-sm">
                        {verificationError.message}
                    </p>
                </div>

                <Button
                    color="primary"
                    size={size}
                    radius={radius}
                    onPress={() => window.location.reload()}
                >
                    Try Again
                </Button>
            </div>
        );
    }

    if (verificationState === 'success') {
        return (
            <div className={`text-center space-y-4 ${className}`}>
                <div className="mx-auto w-16 h-16 bg-success-100 dark:bg-success-900/30 rounded-full flex items-center justify-center">
                    <svg className="w-8 h-8 text-success-600 dark:text-success-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                </div>

                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Success!
                    </h3>
                    <p className="text-default-500 text-sm">
                        You have been successfully authenticated.
                    </p>
                </div>

                {result?.requiresAdditionalVerification && (
                    <div className="text-sm text-warning-600">
                        Additional verification required. Redirecting...
                    </div>
                )}
            </div>
        );
    }

    return null;
}

// ============================================================================
// Export
// ============================================================================

export default MagicLink;