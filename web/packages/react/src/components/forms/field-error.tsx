/**
 * @frank-auth/react - Field Error Component
 *
 * Displays field validation errors with consistent styling and animation.
 * Integrates with form validation system and supports organization theming.
 */

'use client';

import React from 'react';
import {AnimatePresence, motion} from 'framer-motion';
import {useTheme} from '../../hooks/use-theme';
import {useConfig} from '../../hooks/use-config';
import type {SizeT} from "@/types";

// ============================================================================
// Field Error Interface
// ============================================================================

export interface FieldErrorProps {
    /**
     * The error message to display
     */
    error?: string | string[] | null;

    /**
     * Field name for accessibility
     */
    fieldName?: string;

    /**
     * Whether to show error immediately or animate in
     */
    immediate?: boolean;

    /**
     * Custom className for styling
     */
    className?: string;

    /**
     * Custom error icon
     */
    icon?: React.ReactNode;

    /**
     * Whether to show multiple errors or just the first one
     */
    showMultiple?: boolean;

    /**
     * Custom styling variant
     */
    variant?: 'default' | 'inline' | 'tooltip';

    /**
     * Size variant
     */
    size?: SizeT;
}

// ============================================================================
// Field Error Component
// ============================================================================

export function FieldError({
                               error,
                               fieldName,
                               immediate = false,
                               className = '',
                               icon,
                               showMultiple = false,
                               variant = 'default',
                               size = 'md',
                           }: FieldErrorProps) {
    const { getColorValue } = useTheme();
    const { components } = useConfig();

    // Custom component override
    const CustomFieldError = components.FieldError;
    if (CustomFieldError) {
        return <CustomFieldError {...{ error, fieldName, immediate, className, icon, showMultiple, variant, size }} />;
    }

    // Normalize error to array
    const errors = React.useMemo(() => {
        if (!error) return [];
        if (Array.isArray(error)) return error.filter(Boolean);
        return [error];
    }, [error]);

    // Don't render if no errors
    if (errors.length === 0) return null;

    // Display errors (show all if showMultiple is true, otherwise just first)
    const displayErrors = showMultiple ? errors : errors.slice(0, 1);

    // Size classes
    const sizeClasses = {
        sm: 'text-xs',
        md: 'text-sm',
        lg: 'text-base',
    };

    // Variant classes
    const variantClasses = {
        default: 'mt-1',
        inline: 'ml-2 inline-block',
        tooltip: 'absolute z-10 mt-1',
    };

    // Animation variants
    const animationVariants = {
        initial: { opacity: 0, y: -10, height: 0 },
        animate: {
            opacity: 1,
            y: 0,
            height: 'auto',
            transition: { duration: 0.2, ease: 'easeOut' }
        },
        exit: {
            opacity: 0,
            y: -10,
            height: 0,
            transition: { duration: 0.15, ease: 'easeIn' }
        },
    };

    // Default error icon
    const defaultIcon = (
        <svg
            className="w-4 h-4 shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
        >
            <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
        </svg>
    );

    const errorIcon = icon || defaultIcon;

    return (
        <AnimatePresence mode="wait">
            {displayErrors.length > 0 && (
                <motion.div
                    initial={immediate ? 'animate' : 'initial'}
                    animate="animate"
                    exit="exit"
                    variants={animationVariants}
                    className={`
            flex items-start gap-1
            text-danger-600 dark:text-danger-400
            ${sizeClasses[size]}
            ${variantClasses[variant]}
            ${className}
          `.trim()}
                    role="alert"
                    aria-live="polite"
                    aria-relevant="all"
                >
                    {errorIcon && (
                        <span className="text-danger-500 dark:text-danger-400 mt-0.5">
              {errorIcon}
            </span>
                    )}

                    <div className="flex-1 min-w-0">
                        {displayErrors.map((errorMessage, index) => (
                            <div
                                key={`${fieldName}-error-${index}`}
                                className={index > 0 ? 'mt-1' : ''}
                            >
                <span className="block text-inherit break-words">
                  {errorMessage}
                </span>
                            </div>
                        ))}
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
}

// ============================================================================
// Field Error Hook
// ============================================================================

/**
 * Hook for managing field error state
 */
export function useFieldError(fieldName?: string) {
    const [error, setError] = React.useState<string | string[] | null>(null);
    const [touched, setTouched] = React.useState(false);

    const showError = React.useMemo(() => {
        return touched && !!error;
    }, [touched, error]);

    const clearError = React.useCallback(() => {
        setError(null);
    }, []);

    const setFieldError = React.useCallback((newError: string | string[] | null) => {
        setError(newError);
    }, []);

    const touch = React.useCallback(() => {
        setTouched(true);
    }, []);

    const reset = React.useCallback(() => {
        setError(null);
        setTouched(false);
    }, []);

    return {
        error,
        showError,
        touched,
        setError: setFieldError,
        clearError,
        touch,
        reset,
        fieldName,
    };
}

// ============================================================================
// Export
// ============================================================================

export default FieldError;