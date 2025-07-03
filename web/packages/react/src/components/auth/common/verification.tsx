/**
 * @frank-auth/react - Common Verification Components
 *
 * Shared components used across different verification flows.
 * Includes input fields, timers, error displays, and status indicators.
 */

import type React from 'react';
import {useEffect, useRef, useState} from 'react';
import {Alert, Input as HeroInput, Button, Chip, Progress} from '@heroui/react';
import {CheckCircleIcon, ClockIcon, ExclamationTriangleIcon, XCircleIcon} from '@heroicons/react/24/outline';
import {withErrorBoundary} from './error-boundary';
import {useConfig} from "@/hooks";
import type {RadiusT, SizeT} from "@/types";

// ============================================================================
// Verification Input Component
// ============================================================================

export interface VerificationInputProps {
    value: string;
    onChange: (value: string) => void;
    length?: number;
    disabled?: boolean;
    placeholder?: string;
    type?: 'text' | 'tel' | 'number';
    className?: string;
    autoFocus?: boolean;
    onComplete?: (code: string) => void;
    size?: SizeT;
    radius?: RadiusT;
}

export const VerificationInput = withErrorBoundary(function VerificationInput({
                                                                                  value,
                                                                                  onChange,
                                                                                  length = 6,
                                                                                  disabled = false,
                                                                                  placeholder = "Enter code",
                                                                                  type = "text",
                                                                                  className,
                                                                                  autoFocus = true,
                                                                                  onComplete,
    size = 'md',
    radius = 'md'
                                                                              }: VerificationInputProps) {
    const inputRefs = useRef<(HTMLInputElement | null)[]>([]);
    const [activeIndex, setActiveIndex] = useState(0);

    const { components } = useConfig();
    const Input = components.Input ?? HeroInput;

    // Initialize refs array
    useEffect(() => {
        inputRefs.current = inputRefs.current.slice(0, length);
    }, [length]);

    // Handle value changes
    useEffect(() => {
        const digits = value.split('');
        inputRefs.current.forEach((input, index) => {
            if (input) {
                input.value = digits[index] || '';
            }
        });

        if (value.length === length) {
            onComplete?.(value);
        }
    }, [value, length, onComplete]);

    // Auto-focus first input
    useEffect(() => {
        if (autoFocus && inputRefs.current[0] && !disabled) {
            inputRefs.current[0].focus();
        }
    }, [autoFocus, disabled]);

    const handleInputChange = (index: number, inputValue: string) => {
        // Only allow digits
        const digit = inputValue.replace(/\D/g, '').slice(-1);

        const newValue = value.split('');
        newValue[index] = digit;

        // Fill the rest with empty string if shorter
        while (newValue.length < length) {
            newValue.push('');
        }

        const finalValue = newValue.join('').slice(0, length);
        onChange(finalValue);

        // Move to next input if digit entered
        if (digit && index < length - 1) {
            const nextInput = inputRefs.current[index + 1];
            if (nextInput) {
                nextInput.focus();
                setActiveIndex(index + 1);
            }
        }
    };

    const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Backspace') {
            if (!value[index] && index > 0) {
                // Move to previous input and clear it
                const prevInput = inputRefs.current[index - 1];
                if (prevInput) {
                    prevInput.focus();
                    setActiveIndex(index - 1);

                    const newValue = value.split('');
                    newValue[index - 1] = '';
                    onChange(newValue.join(''));
                }
            } else {
                // Clear current input
                const newValue = value.split('');
                newValue[index] = '';
                onChange(newValue.join(''));
            }
        } else if (e.key === 'ArrowLeft' && index > 0) {
            const prevInput = inputRefs.current[index - 1];
            if (prevInput) {
                prevInput.focus();
                setActiveIndex(index - 1);
            }
        } else if (e.key === 'ArrowRight' && index < length - 1) {
            const nextInput = inputRefs.current[index + 1];
            if (nextInput) {
                nextInput.focus();
                setActiveIndex(index + 1);
            }
        }
    };

    const handlePaste = (e: React.ClipboardEvent) => {
        e.preventDefault();
        const pasteData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length);
        onChange(pasteData);

        // Focus the next empty input or the last one
        const nextIndex = Math.min(pasteData.length, length - 1);
        const nextInput = inputRefs.current[nextIndex];
        if (nextInput) {
            nextInput.focus();
            setActiveIndex(nextIndex);
        }
    };

    return (
        <div className={`flex gap-2 justify-center ${className || ''}`}>
            {Array.from({ length }, (_, index) => (
                <Input
                    key={index}
                    ref={(el) => (inputRefs.current[index] = el)}
                    type={type}
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={1}
                    className="w-12 h-12"
                    classNames={{
                        input: "text-center text-lg font-mono",
                        inputWrapper: `h-12 ${activeIndex === index ? 'ring-2 ring-primary' : ''}`
                    }}
                    placeholder={index === 0 ? placeholder : ''}
                    disabled={disabled}
                    onChange={(e) => handleInputChange(index, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(index, e)}
                    onPaste={handlePaste}
                    onFocus={() => setActiveIndex(index)}
                    variant="bordered"
                    size={size}
                    radius={radius}
                />
            ))}
        </div>
    );
});

// ============================================================================
// Verification Timer Component
// ============================================================================

export interface VerificationTimerProps {
    totalTime: number;
    remainingTime: number;
    onExpired?: () => void;
    showProgress?: boolean;
    format?: 'mm:ss' | 'seconds';
    className?: string;
    radius?: RadiusT;
}

export const VerificationTimer = withErrorBoundary(function VerificationTimer({
                                                                                  totalTime,
                                                                                  remainingTime,
                                                                                  onExpired,
                                                                                  showProgress = true,
                                                                                  format = 'mm:ss',
                                                                                  className,
                                                                                  radius = 'sm'
                                                                              }: VerificationTimerProps) {
    useEffect(() => {
        if (remainingTime === 0) {
            onExpired?.();
        }
    }, [remainingTime, onExpired]);

    const formatTime = (seconds: number): string => {
        if (format === 'seconds') {
            return `${seconds}s`;
        }

        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
    };

    const progressValue = totalTime > 0 ? ((totalTime - remainingTime) / totalTime) * 100 : 0;
    const isExpiring = remainingTime <= 30; // Last 30 seconds

    return (
        <div className={`flex items-center gap-3 ${className || ''}`}>
            <ClockIcon className={`h-4 w-4 ${isExpiring ? 'text-warning' : 'text-default-500'}`} />
            <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
          <span className="text-sm text-default-500">
            Code expires in
          </span>
                    <span className={`text-sm font-mono ${isExpiring ? 'text-warning' : 'text-default-700'}`}>
            {formatTime(remainingTime)}
          </span>
                </div>
                {showProgress && (
                    <Progress
                        value={progressValue}
                        color={isExpiring ? 'warning' : 'primary'}
                        size="sm"
                        className="w-full"
                        radius={radius}
                    />
                )}
            </div>
        </div>
    );
});

// ============================================================================
// Verification Error Component
// ============================================================================

export interface VerificationErrorProps {
    error: string;
    onRetry?: () => void;
    className?: string;
}

export const VerificationError = withErrorBoundary(function VerificationError({
                                                                                  error,
                                                                                  onRetry,
                                                                                  className
                                                                              }: VerificationErrorProps) {
    return (
        <Alert icon={<ExclamationTriangleIcon className="h-4 w-4" />} color="danger" variant="flat" className={className}>
            <span className="flex items-center justify-between w-full">
                <span>{error}</span>
                {onRetry && (
                    <Button
                        size="sm"
                        color="danger"
                        variant="light"
                        onClick={onRetry}
                        className="ml-2"
                    >
                        Retry
                    </Button>
                )}
            </span>
        </Alert>
    );
});

// ============================================================================
// Verification Badge Component
// ============================================================================

export interface VerificationBadgeProps {
    status: 'pending' | 'sent' | 'verifying' | 'verified' | 'error' | 'expired';
    method?: 'email' | 'phone' | 'both';
    className?: string;
}

export const Verification = withErrorBoundary(function VerificationBadge({
                                                                                  status,
                                                                                  method = 'email',
                                                                                  className
                                                                              }: VerificationBadgeProps) {
    const getStatusConfig = () => {
        switch (status) {
            case 'pending':
                return {
                    color: 'default' as const,
                    icon: <ClockIcon className="h-3 w-3" />,
                    text: 'Pending'
                };
            case 'sent':
                return {
                    color: 'primary' as const,
                    icon: <ClockIcon className="h-3 w-3" />,
                    text: `Code sent ${method === 'email' ? 'via email' : method === 'phone' ? 'via SMS' : ''}`
                };
            case 'verifying':
                return {
                    color: 'primary' as const,
                    icon: <ClockIcon className="h-3 w-3" />,
                    text: 'Verifying...'
                };
            case 'verified':
                return {
                    color: 'success' as const,
                    icon: <CheckCircleIcon className="h-3 w-3" />,
                    text: 'Verified'
                };
            case 'error':
                return {
                    color: 'danger' as const,
                    icon: <XCircleIcon className="h-3 w-3" />,
                    text: 'Failed'
                };
            case 'expired':
                return {
                    color: 'warning' as const,
                    icon: <XCircleIcon className="h-3 w-3" />,
                    text: 'Expired'
                };
            default:
                return {
                    color: 'default' as const,
                    icon: <ClockIcon className="h-3 w-3" />,
                    text: 'Unknown'
                };
        }
    };

    const config = getStatusConfig();

    return (
        <Chip
            color={config.color}
            variant="flat"
            size="sm"
            startContent={config.icon}
            className={className}
        >
            {config.text}
        </Chip>
    );
});

// ============================================================================
// Verification Progress Component
// ============================================================================

export interface VerificationProgressProps {
    steps: Array<{
        id: string;
        label: string;
        status: 'pending' | 'active' | 'completed' | 'error';
    }>;
    className?: string;
}

export const VerificationProgress = withErrorBoundary(function VerificationProgress({
                                                                                        steps,
                                                                                        className
                                                                                    }: VerificationProgressProps) {
    return (
        <div className={`space-y-4 ${className || ''}`}>
            {steps.map((step, index) => {
                const isLast = index === steps.length - 1;

                const getStepConfig = () => {
                    switch (step.status) {
                        case 'completed':
                            return {
                                color: 'success' as const,
                                icon: <CheckCircleIcon className="h-5 w-5" />,
                                bgClass: 'bg-success',
                                textClass: 'text-success'
                            };
                        case 'active':
                            return {
                                color: 'primary' as const,
                                icon: <ClockIcon className="h-5 w-5" />,
                                bgClass: 'bg-primary',
                                textClass: 'text-primary'
                            };
                        case 'error':
                            return {
                                color: 'danger' as const,
                                icon: <XCircleIcon className="h-5 w-5" />,
                                bgClass: 'bg-danger',
                                textClass: 'text-danger'
                            };
                        default:
                            return {
                                color: 'default' as const,
                                icon: <div className="h-5 w-5 rounded-full border-2 border-default-300" />,
                                bgClass: 'bg-default-200',
                                textClass: 'text-default-500'
                            };
                    }
                };

                const config = getStepConfig();

                return (
                    <div key={step.id} className="flex items-center">
                        <div className="flex items-center">
                            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${config.bgClass} text-white`}>
                                {config.icon}
                            </div>
                            <div className="ml-4">
                                <div className={`text-sm font-medium ${config.textClass}`}>
                                    {step.label}
                                </div>
                            </div>
                        </div>
                        {!isLast && (
                            <div className="flex-1 ml-4">
                                <div className={`h-0.5 ${step.status === 'completed' ? 'bg-success' : 'bg-default-200'}`} />
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
});

// ============================================================================
// Export Common Components Index
// ============================================================================

export const VerificationCommon = {
    VerificationInput,
    VerificationTimer,
    VerificationError,
    VerificationBadge: Verification,
    VerificationProgress
};