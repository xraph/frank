/**
 * @frank-auth/react - Phone Verification Component
 *
 * Handles phone verification flow with SMS code sending, validation, and resending.
 * Integrates with Frank Auth API for SMS-based identity verification.
 */

import React, {useCallback, useEffect, useState} from 'react';
import {Button, Card, CardBody, Chip, Modal, ModalBody, ModalContent, ModalHeader} from '@heroui/react';
import {ArrowPathIcon, CheckCircleIcon, DevicePhoneMobileIcon, XCircleIcon} from '@heroicons/react/24/outline';

import {useAuth} from '../../../../hooks/use-auth';
import {useConfig} from '../../../../hooks/use-config';
import {VerificationError, VerificationInput, withErrorBoundary} from '../../common';

// ============================================================================
// Types
// ============================================================================

export interface PhoneVerificationProps {
    phoneNumber?: string;
    userId?: string;
    organizationId?: string;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
    onVerificationSuccess?: (result: { phoneNumber: string; verified: boolean }) => void;
    onVerificationError?: (error: Error) => void;
    onCodeSent?: () => void;
    onCodeResent?: (attempt: number) => void;
    className?: string;
    style?: React.CSSProperties;
    disabled?: boolean;
}

export interface PhoneVerificationFormProps extends PhoneVerificationProps {
    showHeader?: boolean;
    showInstructions?: boolean;
}

export interface PhoneVerificationModalProps extends PhoneVerificationProps {
    isOpen: boolean;
    onClose: () => void;
    isDismissable?: boolean;
}

export interface PhoneVerificationCardProps extends PhoneVerificationProps {
    variant?: 'flat' | 'bordered' | 'shadow';
    radius?: 'none' | 'sm' | 'md' | 'lg';
}

export interface PhoneVerificationStatusProps {
    status: 'sent' | 'verified' | 'error' | 'expired';
    phoneNumber: string;
    onRetry?: () => void;
    className?: string;
}

export interface ResendSMSButtonProps {
    onResend: () => void;
    disabled?: boolean;
    remainingTime?: number;
    attempt?: number;
    maxAttempts?: number;
    className?: string;
}

// ============================================================================
// Hook for Phone Verification
// ============================================================================

interface UsePhoneVerificationProps {
    phoneNumber?: string;
    userId?: string;
    organizationId?: string;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
    onVerificationSuccess?: (result: { phoneNumber: string; verified: boolean }) => void;
    onVerificationError?: (error: Error) => void;
    onCodeSent?: () => void;
    onCodeResent?: (attempt: number) => void;
}

function usePhoneVerification({
                                  phoneNumber,
                                  userId,
                                  organizationId,
                                  autoSubmit = true,
                                  codeLength = 6,
                                  resendDelay = 30,
                                  maxResendAttempts = 3,
                                  expirationTime = 300, // 5 minutes
                                  onVerificationSuccess,
                                  onVerificationError,
                                  onCodeSent,
                                  onCodeResent
                              }: UsePhoneVerificationProps) {
    const { client } = useAuth();
    const [code, setCode] = useState('');
    const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'verifying' | 'verified' | 'error' | 'expired'>('idle');
    const [error, setError] = useState<string | null>(null);
    const [resendAttempts, setResendAttempts] = useState(0);
    const [timeRemaining, setTimeRemaining] = useState(0);
    const [expiresAt, setExpiresAt] = useState<Date | null>(null);

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

    const sendCode = useCallback(async () => {
        if (!phoneNumber || !userId || !organizationId) {
            setError('Missing required parameters for phone verification');
            return;
        }

        try {
            setStatus('sending');
            setError(null);

            const response = await client.mfa.sendSMSCode({
                orgId: organizationId,
                userId: userId
            });

            if (response.success) {
                setStatus('sent');
                setTimeRemaining(resendDelay);
                setExpiresAt(new Date(Date.now() + expirationTime * 1000));
                onCodeSent?.();
            } else {
                throw new Error(response.message || 'Failed to send SMS verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send SMS verification code');
            setStatus('error');
            setError(error.message);
            onVerificationError?.(error);
        }
    }, [phoneNumber, userId, organizationId, client, resendDelay, expirationTime, onCodeSent, onVerificationError]);

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
            const error = err instanceof Error ? err : new Error('Failed to resend SMS code');
            onVerificationError?.(error);
        }
    }, [resendAttempts, maxResendAttempts, sendCode, onCodeResent, onVerificationError]);

    const handleVerify = useCallback(async () => {
        if (!code || code.length !== codeLength) {
            setError('Please enter a valid verification code');
            return;
        }

        if (!phoneNumber) {
            setError('Phone number is required for verification');
            return;
        }

        try {
            setStatus('verifying');
            setError(null);

            // For phone verification, we use the public API endpoint
            const response = await client.authentication.verifyPhone({
                verificationRequest: {
                    phoneNumber: phoneNumber,
                    code: code
                }
            });

            if (response.verified) {
                setStatus('verified');
                onVerificationSuccess?.({
                    phoneNumber: phoneNumber || '',
                    verified: true
                });
            } else {
                throw new Error('Invalid verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Phone verification failed');
            setStatus('error');
            setError(error.message);
            onVerificationError?.(error);
        }
    }, [code, codeLength, phoneNumber, client, onVerificationSuccess, onVerificationError]);

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
// Utility Functions
// ============================================================================

function formatPhoneNumber(phoneNumber: string): string {
    // Basic phone number formatting
    const cleaned = phoneNumber.replace(/\D/g, '');
    if (cleaned.length === 10) {
        return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }
    if (cleaned.length === 11 && cleaned[0] === '1') {
        return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
    }
    return phoneNumber;
}

function maskPhoneNumber(phoneNumber: string): string {
    const formatted = formatPhoneNumber(phoneNumber);
    // Mask middle digits: +1 (555) 123-4567 → +1 (555) ***-4567
    return formatted.replace(/(\d{3})-(\d{4})/, '***-$2');
}

// ============================================================================
// Main Phone Verification Component
// ============================================================================

export const PhoneVerification = withErrorBoundary(function PhoneVerification({
                                                                                  phoneNumber,
                                                                                  userId,
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
                                                                                  disabled = false
                                                                              }: PhoneVerificationProps) {
    const { config } = useConfig();
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
    } = usePhoneVerification({
        phoneNumber,
        userId,
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

    const handleCodeChange = (value: string) => {
        if (value.length <= codeLength) {
            setCode(value);
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        handleVerify();
    };

    const displayPhoneNumber = phoneNumber ? maskPhoneNumber(phoneNumber) : '';

    const renderContent = () => {
        if (status === 'verified') {
            return (
                <div className="text-center py-8">
                    <CheckCircleIcon className="h-16 w-16 text-success mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Phone Verified!</h3>
                    <p className="text-default-500">
                        Your phone number has been successfully verified.
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
                        The SMS verification code has expired. Please request a new one.
                    </p>
                    <Button
                        color="primary"
                        onClick={sendCode}
                        disabled={disabled}
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
                    <DevicePhoneMobileIcon className="h-12 w-12 text-primary mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Verify Your Phone</h3>
                    <p className="text-default-500 mb-4">
                        We've sent a verification code to {displayPhoneNumber}
                    </p>
                </div>

                {error && <VerificationError error={error} />}

                <div className="space-y-4">
                    <VerificationInput
                        value={code}
                        onChange={handleCodeChange}
                        length={codeLength}
                        disabled={disabled || status === 'verifying'}
                        placeholder="Enter SMS code"
                        type="tel"
                    />

                    <Button
                        type="submit"
                        color="primary"
                        className="w-full"
                        isLoading={status === 'verifying'}
                        disabled={disabled || code.length !== codeLength || status === 'verifying'}
                    >
                        {status === 'verifying' ? 'Verifying...' : 'Verify Phone'}
                    </Button>

                    <div className="flex items-center justify-between">
            <span className="text-sm text-default-500">
              Didn't receive the code?
            </span>
                        <ResendSMSButton
                            onResend={resendCode}
                            disabled={disabled || !canResend}
                            remainingTime={timeRemaining}
                            attempt={resendAttempts}
                            maxAttempts={maxResendAttempts}
                        />
                    </div>
                </div>

                {status === 'idle' && (
                    <Button
                        color="primary"
                        variant="flat"
                        className="w-full"
                        onClick={sendCode}
                        disabled={disabled}
                        isLoading={status === 'sending'}
                    >
                        {status === 'sending' ? 'Sending...' : 'Send SMS Code'}
                    </Button>
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

// ============================================================================
// Phone Verification Form Component
// ============================================================================

export const PhoneVerificationForm = withErrorBoundary(function PhoneVerificationForm({
                                                                                          showHeader = true,
                                                                                          showInstructions = true,
                                                                                          ...props
                                                                                      }: PhoneVerificationFormProps) {
    return (
        <div className="space-y-6">
            {showHeader && (
                <div className="text-center">
                    <h2 className="text-2xl font-bold">Phone Verification</h2>
                    {showInstructions && (
                        <p className="text-default-500 mt-2">
                            Please verify your phone number to continue
                        </p>
                    )}
                </div>
            )}
            <PhoneVerification {...props} />
        </div>
    );
});

// ============================================================================
// Phone Verification Modal Component
// ============================================================================

export const PhoneVerificationModal = withErrorBoundary(function PhoneVerificationModal({
                                                                                            isOpen,
                                                                                            onClose,
                                                                                            isDismissable = true,
                                                                                            ...props
                                                                                        }: PhoneVerificationModalProps) {
    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            isDismissable={isDismissable}
            size="md"
            classNames={{
                backdrop: "bg-gradient-to-t from-zinc-900 to-zinc-900/10 backdrop-opacity-20"
            }}
        >
            <ModalContent>
                <ModalHeader className="flex flex-col gap-1">
                    Phone Verification
                </ModalHeader>
                <ModalBody>
                    <PhoneVerification {...props} />
                </ModalBody>
            </ModalContent>
        </Modal>
    );
});

// ============================================================================
// Phone Verification Card Component
// ============================================================================

export const PhoneVerificationCard = withErrorBoundary(function PhoneVerificationCard({
                                                                                          variant = 'shadow',
                                                                                          radius = 'lg',
                                                                                          ...props
                                                                                      }: PhoneVerificationCardProps) {
    return (
        <Card className={`max-w-md mx-auto ${props.className || ''}`} variant={variant} radius={radius}>
            <CardBody className="p-6">
                <PhoneVerification {...props} />
            </CardBody>
        </Card>
    );
});

// ============================================================================
// Phone Verification Status Component
// ============================================================================

export const PhoneVerificationStatus = withErrorBoundary(function PhoneVerificationStatus({
                                                                                              status,
                                                                                              phoneNumber,
                                                                                              onRetry,
                                                                                              className
                                                                                          }: PhoneVerificationStatusProps) {
    const getStatusConfig = () => {
        const maskedPhone = maskPhoneNumber(phoneNumber);

        switch (status) {
            case 'sent':
                return {
                    color: 'primary' as const,
                    icon: <DevicePhoneMobileIcon className="h-4 w-4" />,
                    message: `SMS code sent to ${maskedPhone}`
                };
            case 'verified':
                return {
                    color: 'success' as const,
                    icon: <CheckCircleIcon className="h-4 w-4" />,
                    message: `Phone ${maskedPhone} verified successfully`
                };
            case 'error':
                return {
                    color: 'danger' as const,
                    icon: <XCircleIcon className="h-4 w-4" />,
                    message: 'SMS verification failed'
                };
            case 'expired':
                return {
                    color: 'warning' as const,
                    icon: <XCircleIcon className="h-4 w-4" />,
                    message: 'SMS code expired'
                };
            default:
                return {
                    color: 'default' as const,
                    icon: <DevicePhoneMobileIcon className="h-4 w-4" />,
                    message: 'Phone verification'
                };
        }
    };

    const config = getStatusConfig();

    return (
        <div className={`flex items-center justify-between p-3 rounded-lg ${className || ''}`}>
            <div className="flex items-center gap-3">
                <Chip color={config.color} variant="flat" startContent={config.icon}>
                    {config.message}
                </Chip>
            </div>
            {(status === 'error' || status === 'expired') && onRetry && (
                <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    onClick={onRetry}
                    startContent={<ArrowPathIcon className="h-3 w-3" />}
                >
                    Retry
                </Button>
            )}
        </div>
    );
});

// ============================================================================
// Resend SMS Button Component
// ============================================================================

export const ResendSMSButton = withErrorBoundary(function ResendSMSButton({
                                                                              onResend,
                                                                              disabled = false,
                                                                              remainingTime = 0,
                                                                              attempt = 0,
                                                                              maxAttempts = 3,
                                                                              className
                                                                          }: ResendSMSButtonProps) {
    const canResend = remainingTime === 0 && attempt < maxAttempts;
    const attemptsLeft = maxAttempts - attempt;

    return (
        <Button
            size="sm"
            color="primary"
            variant="light"
            onClick={onResend}
            disabled={disabled || !canResend}
            className={className}
            startContent={!canResend ? undefined : <ArrowPathIcon className="h-3 w-3" />}
        >
            {remainingTime > 0 ? (
                `Resend in ${remainingTime}s`
            ) : attempt >= maxAttempts ? (
                'Max attempts reached'
            ) : (
                `Resend SMS${attempt > 0 ? ` (${attemptsLeft} left)` : ''}`
            )}
        </Button>
    );
});