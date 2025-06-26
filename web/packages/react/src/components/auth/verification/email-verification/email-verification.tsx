/**
 * @frank-auth/react - Email Verification Component
 *
 * Handles email verification flow with code sending, validation, and resending.
 * Integrates with Frank Auth API for MFA and identity verification.
 */

import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {Button as HeroButton } from '@heroui/react';
import {ArrowPathIcon, CheckCircleIcon, EnvelopeIcon, XCircleIcon} from '@heroicons/react/24/outline';

import {useAuth} from '../../../../hooks/use-auth';
import {useConfig} from '../../../../hooks/use-config';
import {VerificationError, VerificationInput} from '../../common';
import {withErrorBoundary} from '../../common/error-boundary';
import {ResendEmailButton} from "@/components/auth/verification/email-verification/resend-email-button";
import type {RadiusT, SizeT} from "@/types";
import {useMagicLink} from "@/hooks";

// ============================================================================
// Types
// ============================================================================

export interface EmailVerificationProps {
    email?: string;
    organizationId?: string;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
    onVerificationSuccess?: (result: { email: string; verified: boolean }) => void;
    onVerificationError?: (error: Error) => void;
    onCodeSent?: () => void;
    onCodeResent?: (attempt: number) => void;
    className?: string;
    style?: React.CSSProperties;
    disabled?: boolean;
    size?: SizeT;
    modalSize?: SizeT;
    radius?: RadiusT;
}

export interface EmailVerificationFormProps extends EmailVerificationProps {
    showHeader?: boolean;
    showInstructions?: boolean;
}

export interface EmailVerificationModalProps extends EmailVerificationProps {
    isOpen: boolean;
    onClose: () => void;
    isDismissable?: boolean;
}

export interface EmailVerificationCardProps extends EmailVerificationProps {
    variant?: 'flat' | 'bordered' | 'shadow';
    radius?: 'none' | 'sm' | 'md' | 'lg';
}

export interface EmailVerificationStatusProps {
    status: 'sent' | 'verified' | 'error' | 'expired';
    email: string;
    onRetry?: () => void;
    className?: string;
}

export interface ResendEmailButtonProps {
    onResend: () => void;
    disabled?: boolean;
    remainingTime?: number;
    attempt?: number;
    maxAttempts?: number;
    className?: string;
    size?: SizeT;
    radius?: RadiusT;
}

// ============================================================================
// Hook for Email Verification
// ============================================================================

interface UseEmailVerificationProps {
    organizationId?: string;
    email?: string;
    token?: string;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
    onVerificationSuccess?: (result: { email: string; verified: boolean }) => void;
    onVerificationError?: (error: Error) => void;
    onCodeSent?: () => void;
    onCodeResent?: (attempt: number) => void;
}

function useEmailVerification({
                                  organizationId,
                                  email: inputEmail,
                                  autoSubmit = true,
                                  codeLength = 6,
                                  resendDelay = 30,
                                  maxResendAttempts = 3,
                                  expirationTime = 300, // 5 minutes
                                  onVerificationSuccess,
                                  onVerificationError,
                                  onCodeSent,
                                  onCodeResent,
                                  token,
                              }: UseEmailVerificationProps) {
    const { resendVerification, verifyIdentity, extractEmailFromUrl, extractTokenFromUrl } = useAuth();
    const [code, setCode] = useState('');
    const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'verifying' | 'verified' | 'error' | 'expired'>('idle');
    const [error, setError] = useState<string | null>(null);
    const [resendAttempts, setResendAttempts] = useState(0);
    const [timeRemaining, setTimeRemaining] = useState(0);
    const [expiresAt, setExpiresAt] = useState<Date | null>(null);

    // Extract token from URL or use provided token
    const verificationToken = useMemo(() => {
        return token || extractTokenFromUrl();
    }, [token, extractTokenFromUrl]);

    // Extract token from URL or use provided token
    const email = useMemo(() => {
        return inputEmail || extractEmailFromUrl();
    }, [inputEmail, extractEmailFromUrl]);

    // Timer effect for resend delay
    useEffect(() => {
        if (timeRemaining > 0) {
            const timer = setTimeout(() => setTimeRemaining(prev => prev - 1), 1000);
            return () => clearTimeout(timer);
        }
    }, [timeRemaining]);

    // Timer effect for expiration
    useEffect(() => {
        if (expiresAt) {
            const checkExpiration = () => {
                if (new Date() > expiresAt) {
                    setStatus('expired');
                    setError('Verification code has expired');
                }
            };

            const timer = setInterval(checkExpiration, 1000);
            return () => clearInterval(timer);
        }
    }, [expiresAt]);

    // Auto-submit when code is complete
    useEffect(() => {
        if (autoSubmit && code.length === codeLength && status === 'sent') {
            handleVerify();
        }
    }, [code, codeLength, autoSubmit, status]);

    // Auto-submit token is complete
    useEffect(() => {
        if (verificationToken && verificationToken !== "") {
            handleAutoVerify();
        }
    }, [code, codeLength, autoSubmit, status]);


    // Handle verification
    const handleAutoVerify = useCallback(async () => {
        if (!verificationToken) {
            setStatus('error');
            setError('No verification token found.');
            return;
        }

        try {

            setStatus('verifying');
            setError(null);

            const response = await verifyIdentity('email', {
                token: verificationToken,
            });

            if (response.verified) {
                setStatus('verified');
                onVerificationSuccess?.({
                    email: email || '',
                    verified: true
                });
            } else {
                throw new Error(response.message ?? 'Invalid verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Verification failed');
            setStatus('error');
            setError(error.message);
            onVerificationError?.(error);
        }
    }, [verificationToken]);


    const sendCode = useCallback(async () => {
        if (!email || !organizationId) {
            setError('Missing required parameters for email verification');
            return;
        }

        try {
            setStatus('sending');
            setError(null);

            const response = await resendVerification({
                email: email,
                type: 'email',
            });

            if (response.success) {
                setStatus('sent');
                setTimeRemaining(resendDelay);
                setExpiresAt(new Date(Date.now() + expirationTime * 1000));
                onCodeSent?.();
            } else {
                throw new Error(response.message || 'Failed to send verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send verification code');
            setStatus('error');
            setError(error.message);
            onVerificationError?.(error);
        }
    }, [email, organizationId, resendVerification, resendDelay, expirationTime, onCodeSent, onVerificationError]);

    const resendCode = useCallback(async () => {
        if (resendAttempts >= maxResendAttempts) {
            setError('Maximum resend attempts reached');
            return;
        }

        try {
            setResendAttempts(prev => prev + 1);
            await sendCode();
            onCodeResent?.(resendAttempts + 1);
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to resend verification code');
            onVerificationError?.(error);
        }
    }, [resendAttempts, maxResendAttempts, sendCode, onCodeResent, onVerificationError]);

    const handleVerify = useCallback(async () => {
        if (!code || code.length !== codeLength) {
            setError('Please enter a valid verification code');
            return;
        }

        if (!email || !organizationId) {
            setError('Missing required parameters for verification');
            return;
        }

        try {
            setStatus('verifying');
            setError(null);

            const response = await verifyIdentity('email', {
                code: code,
                token: verificationToken ?? '',
            });

            if (response.verified) {
                setStatus('verified');
                onVerificationSuccess?.({
                    email: email || '',
                    verified: true
                });
            } else {
                throw new Error('Invalid verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Verification failed');
            setStatus('error');
            setError(error.message);
            onVerificationError?.(error);
        }
    }, [code, codeLength, organizationId, verifyIdentity, email, token, onVerificationSuccess, onVerificationError]);

    const reset = useCallback(() => {
        setCode('');
        setStatus('idle');
        setError(null);
        setResendAttempts(0);
        setTimeRemaining(0);
        setExpiresAt(null);
    }, []);

    return {
        code,
        setCode,
        status,
        error,
        resendAttempts,
        timeRemaining,
        expiresAt,
        canResend: timeRemaining === 0 && resendAttempts < maxResendAttempts,
        sendCode,
        resendCode,
        handleVerify,
        reset
    };
}

// ============================================================================
// Main Email Verification Component
// ============================================================================

export const EmailVerification = withErrorBoundary(function EmailVerification({
                                                                                  email,
                                                                                  organizationId,
                                                                                  autoSubmit = true,
                                                                                  codeLength = 6,
                                                                                  resendDelay = 30,
                                                                                  maxResendAttempts = 3,
                                                                                  expirationTime = 300,
                                                                                  onVerificationSuccess,
                                                                                  onVerificationError,
                                                                                  onCodeSent,
                                                                                  onCodeResent,
                                                                                  className,
                                                                                  style,
                                                                                  disabled = false,
                                                                                  size = 'md',
                                                                                  radius = 'md',
                                                                              }: EmailVerificationProps) {
    const { config, components } = useConfig();
    const {
        code,
        setCode,
        status,
        error,
        resendAttempts,
        timeRemaining,
        canResend,
        sendCode,
        resendCode,
        handleVerify
    } = useEmailVerification({
        email,
        organizationId,
        autoSubmit,
        codeLength,
        resendDelay,
        maxResendAttempts,
        expirationTime,
        onVerificationSuccess,
        onVerificationError,
        onCodeSent,
        onCodeResent
    });

    const Button = components.Button ?? HeroButton;


    const handleCodeChange = (value: string) => {
        if (value.length <= codeLength) {
            setCode(value);
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        handleVerify();
    };

    const renderContent = () => {
        if (status === 'verified') {
            return (
                <div className="text-center py-8">
                    <CheckCircleIcon className="h-16 w-16 text-success mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Email Verified!</h3>
                    <p className="text-default-500">
                        Your email address has been successfully verified.
                    </p>
                </div>
            );
        }

        if (status === 'expired') {
            return (
                <div className="text-center py-8">
                    <XCircleIcon className="h-16 w-16 text-warning mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Code Expired</h3>
                    <p className="text-default-500 mb-4">
                        The verification code has expired. Please request a new one.
                    </p>
                    <Button
                        color="primary"
                        onClick={sendCode}
                        disabled={disabled}
                        size={size}
                        radius={radius}
                        startContent={<ArrowPathIcon className="h-4 w-4" />}
                    >
                        Send New Code
                    </Button>
                </div>
            );
        }

        return (
            <form onSubmit={handleSubmit} className="space-y-4">
                <div className="text-center">
                    <EnvelopeIcon className="h-12 w-12 text-primary mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Verify Your Email</h3>
                    {email && <p className="text-default-500 mb-4">
                        We've sent a verification code to {email}
                    </p>}
                </div>

                {error && <VerificationError error={error} />}

                {email && (
                    <>
                        <div className="space-y-4">
                            <VerificationInput
                                value={code}
                                onChange={handleCodeChange}
                                length={codeLength}
                                disabled={disabled || status === 'verifying'}
                                placeholder="Enter verification code"
                                size={size}
                                radius={radius}
                            />

                            <Button
                                type="submit"
                                color="primary"
                                className="w-full"
                                size={size}
                                radius={radius}
                                isLoading={status === 'verifying'}
                                disabled={disabled || code.length !== codeLength || status === 'verifying'}
                            >
                                {status === 'verifying' ? 'Verifying...' : 'Verify Email'}
                            </Button>

                            <div className="flex items-center justify-between">
                        <span className="text-sm text-default-500">
                          Didn't receive the code?
                        </span>
                                <ResendEmailButton
                                    onResend={resendCode}
                                    disabled={disabled || !canResend}
                                    remainingTime={timeRemaining}
                                    attempt={resendAttempts}
                                    maxAttempts={maxResendAttempts}
                                    size={size}
                                    radius={radius}
                                />
                            </div>
                        </div>

                        {status === 'idle' && (
                            <Button
                                color="primary"
                                variant="flat"
                                className="w-full"
                                size={size}
                                radius={radius}
                                onClick={sendCode}
                                disabled={disabled}
                                isLoading={status === 'sending'}
                            >
                                {status === 'sending' ? 'Sending...' : 'Send Verification Code'}
                            </Button>
                        )}
                    </>
                )}
            </form>
        );
    };

    return (
        <div className={className} style={style}>
            {renderContent()}
        </div>
    );
});
