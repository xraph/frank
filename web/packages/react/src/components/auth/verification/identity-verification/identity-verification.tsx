/**
 * @frank-auth/react - Combined Identity Verification Component
 *
 * Main identity verification component that combines email and phone verification
 * with method selection, progress tracking, and success confirmation.
 */

import React, {useEffect, useState} from 'react';
import {
    Button,
    ButtonGroup,
    Card,
    CardBody,
    CardHeader,
    Modal,
    ModalBody,
    ModalContent,
    ModalHeader,
    Progress
} from '@heroui/react';
import {
    CheckCircleIcon,
    DevicePhoneMobileIcon,
    EnvelopeIcon,
    ShieldCheckIcon,
    SparklesIcon
} from '@heroicons/react/24/outline';

import {useIdentityVerification} from '../../../../hooks/use-identity-verification';
import {EmailVerification} from '../email-verification';
import {PhoneVerification} from '../phone-verification';
import {withErrorBoundary} from '../../common/error-boundary';

// ============================================================================
// Types
// ============================================================================

export interface IdentityVerificationProps {
    email?: string;
    phoneNumber?: string;
    userId?: string;
    organizationId?: string;
    methods?: ('email' | 'phone')[];
    requireBoth?: boolean;
    allowMethodSelection?: boolean;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
    onVerificationComplete?: (result: {
        verifiedMethods: ('email' | 'phone')[];
        allVerified: boolean;
    }) => void;
    onMethodVerified?: (method: 'email' | 'phone') => void;
    onError?: (error: Error, method?: 'email' | 'phone') => void;
    className?: string;
    style?: React.CSSProperties;
}

export interface VerificationMethodsProps {
    availableMethods: ('email' | 'phone')[];
    selectedMethod: 'email' | 'phone';
    onMethodChange: (method: 'email' | 'phone') => void;
    emailStatus?: string;
    phoneStatus?: string;
    className?: string;
}

export interface VerificationProgressProps {
    steps: Array<{
        id: string;
        label: string;
        status: 'pending' | 'active' | 'completed' | 'error';
    }>;
    currentStep?: string;
    className?: string;
}

export interface VerificationSuccessProps {
    verifiedMethods: ('email' | 'phone')[];
    email?: string;
    phoneNumber?: string;
    onContinue?: () => void;
    className?: string;
}

// ============================================================================
// Verification Methods Selector
// ============================================================================

export const VerificationMethods = withErrorBoundary(function VerificationMethods({
                                                                                      availableMethods,
                                                                                      selectedMethod,
                                                                                      onMethodChange,
                                                                                      emailStatus = 'idle',
                                                                                      phoneStatus = 'idle',
                                                                                      className
                                                                                  }: VerificationMethodsProps) {
    const getMethodStatus = (method: 'email' | 'phone') => {
        const status = method === 'email' ? emailStatus : phoneStatus;

        switch (status) {
            case 'verified':
                return { color: 'success' as const, icon: CheckCircleIcon };
            case 'error':
                return { color: 'danger' as const, icon: EnvelopeIcon };
            case 'sent':
            case 'verifying':
                return { color: 'primary' as const, icon: method === 'email' ? EnvelopeIcon : DevicePhoneMobileIcon };
            default:
                return { color: 'default' as const, icon: method === 'email' ? EnvelopeIcon : DevicePhoneMobileIcon };
        }
    };

    if (availableMethods.length === 1) {
        return null; // No selection needed for single method
    }

    return (
        <div className={`space-y-4 ${className || ''}`}>
            <div className="text-center">
                <h3 className="text-lg font-semibold mb-2">Choose Verification Method</h3>
                <p className="text-default-500 text-sm">
                    Select how you'd like to verify your identity
                </p>
            </div>

            <ButtonGroup className="w-full">
                {availableMethods.includes('email') && (
                    <Button
                        color={selectedMethod === 'email' ? 'primary' : 'default'}
                        variant={selectedMethod === 'email' ? 'solid' : 'bordered'}
                        onClick={() => onMethodChange('email')}
                        startContent={
                            React.createElement(getMethodStatus('email').icon, {
                                className: `h-4 w-4 ${emailStatus === 'verified' ? 'text-success' : ''}`
                            })
                        }
                        className="flex-1"
                    >
                        Email
                        {emailStatus === 'verified' && (
                            <CheckCircleIcon className="h-4 w-4 text-success ml-2" />
                        )}
                    </Button>
                )}

                {availableMethods.includes('phone') && (
                    <Button
                        color={selectedMethod === 'phone' ? 'primary' : 'default'}
                        variant={selectedMethod === 'phone' ? 'solid' : 'bordered'}
                        onClick={() => onMethodChange('phone')}
                        startContent={
                            React.createElement(getMethodStatus('phone').icon, {
                                className: `h-4 w-4 ${phoneStatus === 'verified' ? 'text-success' : ''}`
                            })
                        }
                        className="flex-1"
                    >
                        Phone
                        {phoneStatus === 'verified' && (
                            <CheckCircleIcon className="h-4 w-4 text-success ml-2" />
                        )}
                    </Button>
                )}
            </ButtonGroup>
        </div>
    );
});

// ============================================================================
// Verification Progress Component
// ============================================================================

export const VerificationProgressComponent = withErrorBoundary(function VerificationProgressComponent({
                                                                                                          steps,
                                                                                                          currentStep,
                                                                                                          className
                                                                                                      }: VerificationProgressProps) {
    const completedSteps = steps.filter(step => step.status === 'completed').length;
    const totalSteps = steps.length;
    const progressValue = (completedSteps / totalSteps) * 100;

    return (
        <div className={`space-y-4 ${className || ''}`}>
            <div className="flex items-center justify-between text-sm">
                <span className="text-default-600">Verification Progress</span>
                <span className="text-default-700 font-medium">
          {completedSteps} of {totalSteps} completed
        </span>
            </div>

            <Progress
                value={progressValue}
                color="primary"
                size="sm"
                className="w-full"
            />

            <div className="space-y-3">
                {steps.map((step, index) => {
                    const isLast = index === steps.length - 1;
                    const isCurrent = step.id === currentStep;

                    const getStepIcon = () => {
                        switch (step.status) {
                            case 'completed':
                                return <CheckCircleIcon className="h-5 w-5 text-success" />;
                            case 'active':
                                return <div className="h-5 w-5 rounded-full bg-primary animate-pulse" />;
                            case 'error':
                                return <div className="h-5 w-5 rounded-full bg-danger" />;
                            default:
                                return <div className="h-5 w-5 rounded-full border-2 border-default-300" />;
                        }
                    };

                    const getStepColor = () => {
                        switch (step.status) {
                            case 'completed':
                                return 'text-success';
                            case 'active':
                                return 'text-primary';
                            case 'error':
                                return 'text-danger';
                            default:
                                return 'text-default-500';
                        }
                    };

                    return (
                        <div key={step.id} className="flex items-center">
                            <div className="flex items-center min-w-0 flex-1">
                                <div className="flex-shrink-0">
                                    {getStepIcon()}
                                </div>
                                <div className="ml-3 min-w-0 flex-1">
                                    <p className={`text-sm font-medium ${getStepColor()}`}>
                                        {step.label}
                                    </p>
                                </div>
                            </div>
                            {!isLast && (
                                <div className="ml-4 flex-shrink-0">
                                    <div className={`h-0.5 w-8 ${step.status === 'completed' ? 'bg-success' : 'bg-default-200'}`} />
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
});

// ============================================================================
// Verification Success Component
// ============================================================================

export const VerificationSuccess = withErrorBoundary(function VerificationSuccess({
                                                                                      verifiedMethods,
                                                                                      email,
                                                                                      phoneNumber,
                                                                                      onContinue,
                                                                                      className
                                                                                  }: VerificationSuccessProps) {
    const allMethodsText = verifiedMethods.length > 1 ?
        `${verifiedMethods.join(' and ')} verification` :
        `${verifiedMethods[0]} verification`;

    return (
        <div className={`text-center py-8 ${className || ''}`}>
            <div className="flex justify-center mb-6">
                <div className="relative">
                    <div className="h-20 w-20 bg-success/10 rounded-full flex items-center justify-center">
                        <ShieldCheckIcon className="h-10 w-10 text-success" />
                    </div>
                    <div className="absolute -top-1 -right-1 h-6 w-6 bg-success rounded-full flex items-center justify-center">
                        <CheckCircleIcon className="h-4 w-4 text-white" />
                    </div>
                </div>
            </div>

            <h2 className="text-2xl font-bold text-success mb-3">
                Identity Verified!
            </h2>

            <p className="text-default-600 mb-6">
                Your {allMethodsText} completed successfully.
            </p>

            <div className="space-y-3 mb-6">
                {verifiedMethods.includes('email') && email && (
                    <div className="flex items-center justify-center gap-2 text-sm">
                        <EnvelopeIcon className="h-4 w-4 text-success" />
                        <span className="text-default-700">{email} verified</span>
                    </div>
                )}

                {verifiedMethods.includes('phone') && phoneNumber && (
                    <div className="flex items-center justify-center gap-2 text-sm">
                        <DevicePhoneMobileIcon className="h-4 w-4 text-success" />
                        <span className="text-default-700">{phoneNumber} verified</span>
                    </div>
                )}
            </div>

            {onContinue && (
                <Button
                    color="primary"
                    size="lg"
                    onClick={onContinue}
                    startContent={<SparklesIcon className="h-5 w-5" />}
                >
                    Continue
                </Button>
            )}
        </div>
    );
});

// ============================================================================
// Main Identity Verification Component
// ============================================================================

export const IdentityVerification = withErrorBoundary(function IdentityVerification({
                                                                                        email,
                                                                                        phoneNumber,
                                                                                        userId,
                                                                                        organizationId,
                                                                                        methods = ['email', 'phone'],
                                                                                        requireBoth = false,
                                                                                        allowMethodSelection = true,
                                                                                        autoSubmit = true,
                                                                                        codeLength = 6,
                                                                                        resendDelay = 30,
                                                                                        maxResendAttempts = 3,
                                                                                        expirationTime = 300,
                                                                                        onVerificationComplete,
                                                                                        onMethodVerified,
                                                                                        onError,
                                                                                        className,
                                                                                        style
                                                                                    }: IdentityVerificationProps) {
    const [selectedMethod, setSelectedMethod] = useState<'email' | 'phone'>(methods[0]);
    const [completedMethods, setCompletedMethods] = useState<('email' | 'phone')[]>([]);

    const verification = useIdentityVerification({
        email,
        phoneNumber,
        userId,
        organizationId,
        methods,
        autoSubmit,
        codeLength,
        resendDelay,
        maxResendAttempts,
        expirationTime
    });

    // Track completed methods
    useEffect(() => {
        const newCompleted: ('email' | 'phone')[] = [];

        if (verification.emailStatus === 'verified') {
            newCompleted.push('email');
        }
        if (verification.phoneStatus === 'verified') {
            newCompleted.push('phone');
        }

        if (newCompleted.length !== completedMethods.length) {
            setCompletedMethods(newCompleted);

            // Notify of individual method completion
            newCompleted.forEach(method => {
                if (!completedMethods.includes(method)) {
                    onMethodVerified?.(method);
                }
            });
        }
    }, [verification.emailStatus, verification.phoneStatus, completedMethods, onMethodVerified]);

    // Check if verification is complete
    useEffect(() => {
        const isComplete = requireBoth ?
            methods.every(method => completedMethods.includes(method)) :
            completedMethods.length > 0;

        if (isComplete && completedMethods.length > 0) {
            onVerificationComplete?.({
                verifiedMethods: completedMethods,
                allVerified: isComplete
            });
        }
    }, [completedMethods, methods, requireBoth, onVerificationComplete]);

    // Handle errors
    useEffect(() => {
        if (verification.emailError) {
            onError?.(new Error(verification.emailError), 'email');
        }
    }, [verification.emailError, onError]);

    useEffect(() => {
        if (verification.phoneError) {
            onError?.(new Error(verification.phoneError), 'phone');
        }
    }, [verification.phoneError, onError]);

    const getVerificationSteps = () => {
        return methods.map(method => ({
            id: method,
            label: `Verify ${method === 'email' ? 'Email' : 'Phone Number'}`,
            status: completedMethods.includes(method) ? 'completed' as const :
                verification.activeMethod === method ? 'active' as const :
                    (method === 'email' ? verification.emailStatus : verification.phoneStatus) === 'error' ? 'error' as const :
                        'pending' as const
        }));
    };

    const isAllVerified = requireBoth ?
        methods.every(method => completedMethods.includes(method)) :
        completedMethods.length > 0;

    const renderContent = () => {
        if (isAllVerified) {
            return (
                <VerificationSuccess
                    verifiedMethods={completedMethods}
                    email={email}
                    phoneNumber={phoneNumber}
                    onContinue={() => {
                        onVerificationComplete?.({
                            verifiedMethods: completedMethods,
                            allVerified: true
                        });
                    }}
                />
            );
        }

        return (
            <div className="space-y-6">
                {/* Progress indicator */}
                {methods.length > 1 && (
                    <VerificationProgressComponent
                        steps={getVerificationSteps()}
                        currentStep={verification.activeMethod || undefined}
                    />
                )}

                {/* Method selection */}
                {allowMethodSelection && methods.length > 1 && !requireBoth && (
                    <VerificationMethods
                        availableMethods={methods}
                        selectedMethod={selectedMethod}
                        onMethodChange={setSelectedMethod}
                        emailStatus={verification.emailStatus}
                        phoneStatus={verification.phoneStatus}
                    />
                )}

                {/* Verification forms */}
                <div className="space-y-6">
                    {/* Email verification */}
                    {(selectedMethod === 'email' || requireBoth) && methods.includes('email') && !completedMethods.includes('email') && (
                        <div className={requireBoth ? '' : selectedMethod === 'email' ? '' : 'hidden'}>
                            <EmailVerification
                                email={email}
                                userId={userId}
                                organizationId={organizationId}
                                autoSubmit={autoSubmit}
                                codeLength={codeLength}
                                resendDelay={resendDelay}
                                maxResendAttempts={maxResendAttempts}
                                expirationTime={expirationTime}
                                onVerificationSuccess={() => {
                                    // Handled by useEffect
                                }}
                                onVerificationError={(error) => onError?.(error, 'email')}
                            />
                        </div>
                    )}

                    {/* Phone verification */}
                    {(selectedMethod === 'phone' || requireBoth) && methods.includes('phone') && !completedMethods.includes('phone') && (
                        <div className={requireBoth ? '' : selectedMethod === 'phone' ? '' : 'hidden'}>
                            <PhoneVerification
                                phoneNumber={phoneNumber}
                                userId={userId}
                                organizationId={organizationId}
                                autoSubmit={autoSubmit}
                                codeLength={codeLength}
                                resendDelay={resendDelay}
                                maxResendAttempts={maxResendAttempts}
                                expirationTime={expirationTime}
                                onVerificationSuccess={() => {
                                    // Handled by useEffect
                                }}
                                onVerificationError={(error) => onError?.(error, 'phone')}
                            />
                        </div>
                    )}
                </div>

                {/* Continue to next method for requireBoth mode */}
                {requireBoth && completedMethods.length > 0 && completedMethods.length < methods.length && (
                    <div className="text-center py-4">
                        <div className="flex items-center justify-center gap-2 mb-4">
                            <CheckCircleIcon className="h-5 w-5 text-success" />
                            <span className="text-success font-medium">
                {completedMethods[0]} verification completed
              </span>
                        </div>
                        <p className="text-default-600 text-sm">
                            Please complete the remaining verification step
                        </p>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className={className} style={style}>
            {renderContent()}
        </div>
    );
});

// ============================================================================
// Identity Verification Card Wrapper
// ============================================================================

export const IdentityVerificationCard = withErrorBoundary(function IdentityVerificationCard({
                                                                                                variant = 'shadow',
                                                                                                radius = 'lg',
                                                                                                ...props
                                                                                            }: IdentityVerificationProps & {
    variant?: 'flat' | 'bordered' | 'shadow';
    radius?: 'none' | 'sm' | 'md' | 'lg';
}) {
    return (
        <Card className={`max-w-lg mx-auto ${props.className || ''}`} variant={variant} radius={radius}>
            <CardHeader className="text-center pb-2">
                <div className="flex flex-col items-center space-y-2">
                    <div className="h-12 w-12 bg-primary/10 rounded-full flex items-center justify-center">
                        <ShieldCheckIcon className="h-6 w-6 text-primary" />
                    </div>
                    <div>
                        <h2 className="text-xl font-bold">Identity Verification</h2>
                        <p className="text-default-500 text-sm">
                            Please verify your identity to continue
                        </p>
                    </div>
                </div>
            </CardHeader>

            <CardBody className="pt-2">
                <IdentityVerification {...props} />
            </CardBody>
        </Card>
    );
});

// ============================================================================
// Identity Verification Modal
// ============================================================================

export const IdentityVerificationModal = withErrorBoundary(function IdentityVerificationModal({
                                                                                                  isOpen,
                                                                                                  onClose,
                                                                                                  isDismissable = true,
                                                                                                  ...props
                                                                                              }: IdentityVerificationProps & {
    isOpen: boolean;
    onClose: () => void;
    isDismissable?: boolean;
}) {
    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            isDismissable={isDismissable}
            size="lg"
            classNames={{
                backdrop: "bg-gradient-to-t from-zinc-900 to-zinc-900/10 backdrop-opacity-20"
            }}
        >
            <ModalContent>
                <ModalHeader className="flex flex-col gap-1 text-center">
                    <div className="flex items-center justify-center gap-2">
                        <ShieldCheckIcon className="h-6 w-6 text-primary" />
                        <span>Identity Verification</span>
                    </div>
                </ModalHeader>
                <ModalBody className="pb-6">
                    <IdentityVerification
                        {...props}
                        onVerificationComplete={(result) => {
                            props.onVerificationComplete?.(result);
                            if (result.allVerified) {
                                setTimeout(() => onClose(), 2000);
                            }
                        }}
                    />
                </ModalBody>
            </ModalContent>
        </Modal>
    );
});