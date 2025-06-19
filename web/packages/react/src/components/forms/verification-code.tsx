/**
 * @frank-auth/react - Verification Code Component
 *
 * OTP/verification code input with auto-focus, paste support, and
 * customizable length. Supports MFA, email verification, and SMS codes.
 */

'use client';

import React from 'react';
import {Button, Input, Progress} from '@heroui/react';
import {AnimatePresence, motion} from 'framer-motion';
import {useConfig} from '../../hooks/use-config';
import {useFormField} from './form-wrapper';
import {FieldError} from './field-error';

// ============================================================================
// Verification Code Interface
// ============================================================================

export interface VerificationCodeProps {
    /**
     * Field name for form handling
     */
    name?: string;

    /**
     * Field label
     */
    label?: string;

    /**
     * Number of code digits
     */
    length?: number;

    /**
     * Code value
     */
    value?: string;

    /**
     * Change handler
     */
    onChange?: (value: string) => void;

    /**
     * Complete handler (called when all digits entered)
     */
    onComplete?: (value: string) => void;

    /**
     * Blur handler
     */
    onBlur?: () => void;

    /**
     * Focus handler
     */
    onFocus?: () => void;

    /**
     * Whether field is required
     */
    required?: boolean;

    /**
     * Whether field is disabled
     */
    disabled?: boolean;

    /**
     * Whether to auto-focus first input
     */
    autoFocus?: boolean;

    /**
     * Field size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Field variant
     */
    variant?: 'flat' | 'bordered' | 'underlined' | 'faded';

    /**
     * Custom className
     */
    className?: string;

    /**
     * Custom validation error
     */
    error?: string | string[];

    /**
     * Help text
     */
    description?: string;

    /**
     * Placeholder character
     */
    placeholder?: string;

    /**
     * Input type (numeric vs alphanumeric)
     */
    type?: 'numeric' | 'alphanumeric';

    /**
     * Whether to allow paste
     */
    allowPaste?: boolean;

    /**
     * Whether to show separator between groups
     */
    separator?: boolean;

    /**
     * Group size for separator (e.g., 3 for 123-456)
     */
    groupSize?: number;

    /**
     * Separator character
     */
    separatorChar?: string;

    /**
     * Resend functionality
     */
    canResend?: boolean;

    /**
     * Resend handler
     */
    onResend?: () => void;

    /**
     * Resend countdown (seconds)
     */
    resendCountdown?: number;

    /**
     * Loading state
     */
    isLoading?: boolean;

    /**
     * Success state
     */
    isSuccess?: boolean;

    /**
     * Input mode for mobile keyboards
     */
    inputMode?: 'numeric' | 'text';

    /**
     * Auto complete
     */
    autoComplete?: string;
}

// ============================================================================
// Verification Code Component
// ============================================================================

export function VerificationCode({
                                     name = 'verificationCode',
                                     label = 'Verification Code',
                                     length = 6,
                                     value = '',
                                     onChange,
                                     onComplete,
                                     onBlur,
                                     onFocus,
                                     required = false,
                                     disabled = false,
                                     autoFocus = true,
                                     size = 'md',
                                     variant = 'bordered',
                                     className = '',
                                     error: externalError,
                                     description,
                                     placeholder = '○',
                                     type = 'numeric',
                                     allowPaste = true,
                                     separator = false,
                                     groupSize = 3,
                                     separatorChar = '-',
                                     canResend = false,
                                     onResend,
                                     resendCountdown = 0,
                                     isLoading = false,
                                     isSuccess = false,
                                     inputMode = 'numeric',
                                     autoComplete = 'one-time-code',
                                 }: VerificationCodeProps) {
    const { components } = useConfig();
    const formField = useFormField(name);

    // Custom component override
    const CustomVerificationCode = components.VerificationCode;
    if (CustomVerificationCode) {
        return <CustomVerificationCode {...{
            name, label, length, value, onChange, onComplete, onBlur, onFocus, required,
            disabled, autoFocus, size, variant, className, error: externalError, description,
            placeholder, type, allowPaste, separator, groupSize, separatorChar, canResend,
            onResend, resendCountdown, isLoading, isSuccess, inputMode, autoComplete
        }} />;
    }

    // State
    const [internalValue, setInternalValue] = React.useState(value);
    const [activeIndex, setActiveIndex] = React.useState(0);
    const [isFocused, setIsFocused] = React.useState(false);
    const inputRefs = React.useRef<(HTMLInputElement | null)[]>([]);

    // Use external value if controlled
    const currentValue = onChange ? value : internalValue;

    // Split value into individual digits
    const digits = React.useMemo(() => {
        const valueArray = currentValue.split('').slice(0, length);
        return [...valueArray, ...Array(Math.max(0, length - valueArray.length)).fill('')];
    }, [currentValue, length]);

    // Combined errors
    const errors = React.useMemo(() => {
        const allErrors: string[] = [];

        if (externalError) {
            if (Array.isArray(externalError)) {
                allErrors.push(...externalError);
            } else {
                allErrors.push(externalError);
            }
        }

        if (formField.error) {
            if (Array.isArray(formField.error)) {
                allErrors.push(...formField.error);
            } else {
                allErrors.push(formField.error);
            }
        }

        return allErrors.length > 0 ? allErrors : null;
    }, [externalError, formField.error]);

    // Handle value change
    const handleChange = React.useCallback((newValue: string) => {
        // Validate input based on type
        const validValue = type === 'numeric'
            ? newValue.replace(/[^0-9]/g, '')
            : newValue.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

        if (onChange) {
            onChange(validValue);
        } else {
            setInternalValue(validValue);
        }

        // Clear errors when user starts typing
        if (formField.clearError) {
            formField.clearError();
        }

        // Check if complete
        if (validValue.length === length && onComplete) {
            onComplete(validValue);
        }
    }, [onChange, formField, length, onComplete, type]);

    // Handle single digit change
    const handleDigitChange = React.useCallback((index: number, digit: string) => {
        if (disabled) return;

        const newDigits = [...digits];
        const validDigit = type === 'numeric'
            ? digit.replace(/[^0-9]/g, '')
            : digit.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

        if (validDigit.length > 1) {
            // Handle multiple characters (paste or rapid input)
            const chars = validDigit.split('');
            for (let i = 0; i < chars.length && (index + i) < length; i++) {
                newDigits[index + i] = chars[i];
            }

            // Focus next empty field or last field
            const nextIndex = Math.min(index + chars.length, length - 1);
            setActiveIndex(nextIndex);
            inputRefs.current[nextIndex]?.focus();
        } else {
            newDigits[index] = validDigit;

            // Move to next field if digit entered and not last field
            if (validDigit && index < length - 1) {
                setActiveIndex(index + 1);
                inputRefs.current[index + 1]?.focus();
            }
        }

        const newValue = newDigits.join('');
        handleChange(newValue);
    }, [digits, disabled, length, type, handleChange]);

    // Handle key down
    const handleKeyDown = React.useCallback((index: number, event: React.KeyboardEvent) => {
        if (disabled) return;

        switch (event.key) {
            case 'Backspace':
                if (!digits[index] && index > 0) {
                    // Move to previous field if current is empty
                    event.preventDefault();
                    setActiveIndex(index - 1);
                    inputRefs.current[index - 1]?.focus();
                } else if (digits[index]) {
                    // Clear current field
                    const newDigits = [...digits];
                    newDigits[index] = '';
                    const newValue = newDigits.join('');
                    handleChange(newValue);
                }
                break;

            case 'Delete':
                // Clear current field
                const newDigits = [...digits];
                newDigits[index] = '';
                const newValue = newDigits.join('');
                handleChange(newValue);
                break;

            case 'ArrowLeft':
                event.preventDefault();
                if (index > 0) {
                    setActiveIndex(index - 1);
                    inputRefs.current[index - 1]?.focus();
                }
                break;

            case 'ArrowRight':
                event.preventDefault();
                if (index < length - 1) {
                    setActiveIndex(index + 1);
                    inputRefs.current[index + 1]?.focus();
                }
                break;

            case 'Home':
                event.preventDefault();
                setActiveIndex(0);
                inputRefs.current[0]?.focus();
                break;

            case 'End':
                event.preventDefault();
                setActiveIndex(length - 1);
                inputRefs.current[length - 1]?.focus();
                break;
        }
    }, [digits, disabled, length, handleChange]);

    // Handle paste
    const handlePaste = React.useCallback((event: React.ClipboardEvent) => {
        if (!allowPaste || disabled) return;

        event.preventDefault();
        const pastedData = event.clipboardData.getData('text');
        const validData = type === 'numeric'
            ? pastedData.replace(/[^0-9]/g, '')
            : pastedData.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

        if (validData) {
            const truncatedData = validData.slice(0, length);
            handleChange(truncatedData);

            // Focus last filled field
            const focusIndex = Math.min(truncatedData.length - 1, length - 1);
            setActiveIndex(focusIndex);
            inputRefs.current[focusIndex]?.focus();
        }
    }, [allowPaste, disabled, type, length, handleChange]);

    // Handle input focus
    const handleInputFocus = React.useCallback((index: number) => {
        setActiveIndex(index);
        setIsFocused(true);
        onFocus?.();
    }, [onFocus]);

    // Handle input blur
    const handleInputBlur = React.useCallback(() => {
        setIsFocused(false);
        if (formField.setTouched) {
            formField.setTouched(true);
        }
        onBlur?.();
    }, [formField, onBlur]);

    // Auto focus first input on mount
    React.useEffect(() => {
        if (autoFocus && !disabled) {
            inputRefs.current[0]?.focus();
        }
    }, [autoFocus, disabled]);

    // Size classes
    const sizeClasses = {
        sm: 'w-8 h-8 text-sm',
        md: 'w-10 h-10 text-base',
        lg: 'w-12 h-12 text-lg',
    };

    // Render separator
    const renderSeparator = (index: number) => {
        if (!separator || (index + 1) % groupSize !== 0 || index === length - 1) {
            return null;
        }

        return (
            <span className="text-default-400 text-xl font-mono mx-1">
        {separatorChar}
      </span>
        );
    };

    // Resend button
    const ResendButton = () => {
        if (!canResend || !onResend) return null;

        const canClickResend = resendCountdown === 0 && !isLoading;

        return (
            <div className="flex items-center justify-center mt-4">
                {canClickResend ? (
                    <Button
                        variant="light"
                        color="primary"
                        size="sm"
                        onPress={onResend}
                        isDisabled={isLoading}
                    >
                        Resend Code
                    </Button>
                ) : (
                    <div className="text-sm text-default-500">
                        Resend code in {resendCountdown}s
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className={`space-y-4 ${className}`}>
            {/* Label */}
            {label && (
                <div className="text-sm font-medium text-foreground">
                    {label}
                    {required && <span className="text-danger ml-1">*</span>}
                </div>
            )}

            {/* Description */}
            {description && (
                <div className="text-sm text-default-500">
                    {description}
                </div>
            )}

            {/* Input Fields */}
            <div className="flex items-center justify-center gap-2 flex-wrap">
                {digits.map((digit, index) => (
                    <React.Fragment key={index}>
                        <Input
                            ref={(el: HTMLInputElement | null) => {
                                inputRefs.current[index] = el;
                            }}
                            value={digit}
                            onChange={(e) => handleDigitChange(index, e.target.value)}
                            onKeyDown={(e) => handleKeyDown(index, e)}
                            onFocus={() => handleInputFocus(index)}
                            onBlur={handleInputBlur}
                            onPaste={handlePaste}
                            maxLength={1}
                            className={`${sizeClasses[size]} text-center font-mono`}
                            size={size}
                            variant={variant}
                            isDisabled={disabled || isLoading}
                            isInvalid={!!errors}
                            placeholder={placeholder}
                            inputMode={inputMode}
                            autoComplete={index === 0 ? autoComplete : 'off'}
                            type="text"
                        />
                        {renderSeparator(index)}
                    </React.Fragment>
                ))}
            </div>

            {/* Loading Progress */}
            <AnimatePresence>
                {isLoading && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                    >
                        <Progress
                            size="sm"
                            isIndeterminate
                            color="primary"
                            className="w-full"
                            label="Verifying..."
                        />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Success State */}
            <AnimatePresence>
                {isSuccess && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="flex items-center justify-center gap-2 text-success-600"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        <span className="text-sm font-medium">Verified!</span>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Field Errors */}
            {errors && <FieldError error={errors} fieldName={name} />}

            {/* Resend Button */}
            <ResendButton />

            {/* Progress Indicator */}
            <div className="flex justify-center">
                <div className="flex gap-1">
                    {Array.from({ length }, (_, index) => (
                        <div
                            key={index}
                            className={`
                w-2 h-1 rounded-full transition-colors duration-200
                ${index < currentValue.length
                                ? 'bg-primary'
                                : 'bg-default-200 dark:bg-default-800'
                            }
              `}
                        />
                    ))}
                </div>
            </div>
        </div>
    );
}

// ============================================================================
// Export
// ============================================================================

export default VerificationCode;