/**
 * @frank-auth/react - Password Field Component
 *
 * Advanced password input with strength validation, visibility toggle, and
 * organization-specific password requirements. Supports MFA and security features.
 */

'use client';

import React from 'react';
import {Button, Chip, Input, Progress} from '@heroui/react';
import {AnimatePresence, motion} from 'framer-motion';
import {useConfig} from '../../hooks/use-config';
import {useFormField} from './form-wrapper';
import {FieldError} from './field-error';
import {CheckIcon, ExclamationTriangleIcon, EyeIcon, EyeSlashIcon} from "@heroicons/react/24/outline";
import type {FieldProps} from "@/components/forms/shared";
import {generatePasswordSuggestions, getPasswordStrength, type SignUpFormProps} from "@/components";

// ============================================================================
// Password Field Interface
// ============================================================================

export interface PasswordFieldProps extends FieldProps<string> {
    /**
     * Whether field is required
     */
    required?: boolean;

    /**
     * Whether field is disabled
     */
    disabled?: boolean;

    /**
     * Whether to show password strength indicator
     */
    showStrength?: boolean;

    /**
     * Whether to show password requirements
     */
    showRequirements?: boolean;
    showSuggestions?: boolean;
    enableGenerate?: boolean;

    /**
     * Whether to allow password visibility toggle
     */
    allowToggle?: boolean;

    /**
     * Custom password validation rules
     */
    rules?: PasswordRules;

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
     * Auto focus
     */
    autoFocus?: boolean;

    /**
     * Auto complete
     */
    autoComplete?: string;

    /**
     * Whether this is for password confirmation
     */
    isConfirmation?: boolean;

    /**
     * Original password for confirmation
     */
    originalPassword?: string;

    /**
     * Custom validation error
     */
    error?: string | string[];

    /**
     * Help text
     */
    description?: string;


    /**
     * Start icon
     */
    startContent?: React.ReactNode;

    advanceRequirements?: any;
}

// ============================================================================
// Password Validation Types
// ============================================================================

export interface PasswordRules {
    minLength?: number;
    maxLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
    preventCommon?: boolean;
    preventUserInfo?: boolean;
    customPattern?: RegExp;
    customMessage?: string;
}

export interface PasswordStrength {
    score: number; // 0-4 (very weak to very strong)
    label: string;
    color: string;
    percentage: number;
    feedback: string[];
    requirements: PasswordRequirement[];
}

export interface PasswordRequirement {
    id: string;
    label: string;
    met: boolean;
    required: boolean;
}

// ============================================================================
// Default Password Rules
// ============================================================================

const defaultPasswordRules: PasswordRules = {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventCommon: true,
    preventUserInfo: false,
};

// Common weak passwords
const commonPasswords = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
    'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'iloveyou'
];

// ============================================================================
// Password Validation Functions
// ============================================================================

function validatePassword(password: string, rules: PasswordRules, userInfo?: any): PasswordStrength {
    const requirements: PasswordRequirement[] = [];
    let score = 0;
    const feedback: string[] = [];

    // Length requirement
    if (rules.minLength) {
        const lengthMet = password.length >= rules.minLength;
        requirements.push({
            id: 'length',
            label: `At least ${rules.minLength} characters`,
            met: lengthMet,
            required: true,
        });
        if (lengthMet) score += 1;
        else feedback.push(`Password must be at least ${rules.minLength} characters long`);
    }

    // Uppercase requirement
    if (rules.requireUppercase) {
        const uppercaseMet = /[A-Z]/.test(password);
        requirements.push({
            id: 'uppercase',
            label: 'One uppercase letter',
            met: uppercaseMet,
            required: true,
        });
        if (uppercaseMet) score += 1;
        else feedback.push('Password must contain at least one uppercase letter');
    }

    // Lowercase requirement
    if (rules.requireLowercase) {
        const lowercaseMet = /[a-z]/.test(password);
        requirements.push({
            id: 'lowercase',
            label: 'One lowercase letter',
            met: lowercaseMet,
            required: true,
        });
        if (lowercaseMet) score += 1;
        else feedback.push('Password must contain at least one lowercase letter');
    }

    // Number requirement
    if (rules.requireNumbers) {
        const numberMet = /\d/.test(password);
        requirements.push({
            id: 'number',
            label: 'One number',
            met: numberMet,
            required: true,
        });
        if (numberMet) score += 1;
        else feedback.push('Password must contain at least one number');
    }

    // Special character requirement
    if (rules.requireSpecialChars) {
        const specialMet = /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'\/~`]/.test(password);
        requirements.push({
            id: 'special',
            label: 'One special character',
            met: specialMet,
            required: true,
        });
        if (specialMet) score += 1;
        else feedback.push('Password must contain at least one special character');
    }

    // Common password check
    if (rules.preventCommon) {
        const isCommon = commonPasswords.includes(password.toLowerCase());
        requirements.push({
            id: 'common',
            label: 'Not a common password',
            met: !isCommon,
            required: false,
        });
        if (isCommon) {
            score = Math.max(0, score - 2);
            feedback.push('This is a commonly used password');
        }
    }

    // Additional scoring for complexity
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (/[A-Z].*[A-Z]/.test(password)) score += 0.5;
    if (/\d.*\d/.test(password)) score += 0.5;
    if (/[!@#$%^&*()].*[!@#$%^&*()]/.test(password)) score += 0.5;

    // Cap the score at 4
    score = Math.min(4, Math.floor(score * 0.8));

    // Determine strength label and color
    let label: string;
    let color: string;
    let percentage: number;

    switch (score) {
        case 0:
        case 1:
            label = 'Very Weak';
            color = 'danger';
            percentage = 20;
            break;
        case 2:
            label = 'Weak';
            color = 'warning';
            percentage = 40;
            break;
        case 3:
            label = 'Good';
            color = 'primary';
            percentage = 70;
            break;
        case 4:
            label = 'Strong';
            color = 'success';
            percentage = 100;
            break;
        default:
            label = 'Very Weak';
            color = 'danger';
            percentage = 0;
    }

    return {
        score,
        label,
        color,
        percentage,
        feedback,
        requirements,
    };
}

// ============================================================================
// Password Field Component
// ============================================================================

export function PasswordFieldComponent({
                                           name = 'password',
                                           label = 'Password',
                                           placeholder = 'Enter your password',
                                           value = '',
                                           onChange,
                                           onBlur,
                                           onFocus,
                                           required = false,
                                           disabled = false,
                                           showStrength = true,
                                           showRequirements = false,
                                           showSuggestions = false,
                                           enableGenerate = false,
                                           allowToggle = true,
                                           rules = defaultPasswordRules,
                                           size = 'md',
                                           radius = 'md',
                                           variant = 'bordered',
                                           className = '',
                                           autoFocus = false,
                                           autoComplete = 'current-password',
                                           isConfirmation = false,
                                           originalPassword,
                                           error: externalError,
                                           description,
                                           startContent,
    advanceRequirements,
                                       }: PasswordFieldProps) {
    const {components, organizationSettings} = useConfig();
    const formField = useFormField(name);

    // Custom component override
    const RootInput = components.Input ?? Input;
    const RootButton = components.Button ?? Button;
    const CustomPasswordField = components.PasswordField;
    if (CustomPasswordField) {
        return <CustomPasswordField {...{
            name, label, placeholder, value, onChange, onBlur, onFocus, required, disabled,
            showStrength, showRequirements, allowToggle, rules, size, variant, className,
            autoFocus, autoComplete, isConfirmation, originalPassword, error: externalError, description
        }} />;
    }

    // State
    const [internalValue, setInternalValue] = React.useState(value);
    const [isVisible, setIsVisible] = React.useState(false);
    const [isFocused, setIsFocused] = React.useState(false);
    const [suggestedPasswords, setSuggestedPasswords] = React.useState<string[]>([]);

    // Use external value if controlled
    const currentValue = onChange ? value : internalValue;

    // Apply organization password rules if available
    const effectiveRules = React.useMemo(() => {
        const orgRules = organizationSettings?.passwordPolicy;
        if (orgRules) {
            return {
                ...defaultPasswordRules,
                ...rules,
                minLength: orgRules.minLength || rules.minLength,
                requireUppercase: orgRules.requireUppercase ?? rules.requireUppercase,
                requireLowercase: orgRules.requireLowercase ?? rules.requireLowercase,
                requireNumbers: orgRules.requireNumbers ?? rules.requireNumbers,
                requireSpecialChars: orgRules.requireSpecialChars ?? rules.requireSpecialChars,
            };
        }
        return {...defaultPasswordRules, ...rules};
    }, [rules, organizationSettings]);

    // Password strength validation
    const strength = React.useMemo(() => {
        if (!currentValue) return null;
        return validatePassword(currentValue, effectiveRules);
    }, [currentValue, effectiveRules]);

    // Password confirmation validation
    const confirmationError = React.useMemo(() => {
        if (!isConfirmation || !originalPassword || !currentValue) return null;
        return originalPassword !== currentValue ? 'Passwords do not match' : null;
    }, [isConfirmation, originalPassword, currentValue]);

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

        if (confirmationError) {
            allErrors.push(confirmationError);
        }

        return allErrors.length > 0 ? allErrors : null;
    }, [externalError, formField.error, confirmationError]);

    // Handle value change
    const handleChange = React.useCallback((newValue: string) => {
        if (onChange) {
            onChange(newValue);
        } else {
            setInternalValue(newValue);
        }

        // Clear errors when user starts typing
        if (formField.clearError) {
            formField.clearError();
        }
    }, [onChange, formField]);

    // Handle blur
    const handleBlur = React.useCallback(() => {
        setIsFocused(false);
        if (formField.setTouched) {
            formField.setTouched(true);
        }
        onBlur?.();
    }, [formField, onBlur]);

    // Handle focus
    const handleFocus = React.useCallback(() => {
        setIsFocused(true);
        onFocus?.();
    }, [onFocus]);

    // Toggle visibility
    const toggleVisibility = React.useCallback(() => {
        setIsVisible(prev => !prev);
    }, []);

    // Show requirements when focused or has value
    const shouldShowRequirements = showRequirements && (isFocused || currentValue);
    const shouldShowSuggestions = showSuggestions && (isFocused || currentValue);
    const shouldShowStrength = showStrength && currentValue && !isConfirmation;


    // Generate password suggestions
    const generateSuggestions = React.useCallback(() => {
        const suggestions = generatePasswordSuggestions();
        setSuggestedPasswords(suggestions);
    }, []);


    return (
        <div className={`space-y-2 ${className}`}>
            <RootInput
                name={name}
                label={label}
                placeholder={placeholder}
                value={currentValue}
                // onValueChange={handleChange}
                onBlur={handleBlur}
                onFocus={handleFocus}
                type={isVisible ? 'text' : 'password'}
                isRequired={required}
                isDisabled={disabled}
                onChange={(e: any) => handleChange(typeof e === "string" ? e : e.target.value)}
                required={required}
                disabled={disabled}
                size={size}
                radius={radius}
                variant={variant}
                autoFocus={autoFocus}
                autoComplete={autoComplete}
                description={description}
                isInvalid={!!errors}
                errorMessage=""
                startContent={startContent}
                endContent={
                    allowToggle && (
                        <RootButton
                            isIconOnly
                            variant="light"
                            size="sm"
                            onPress={toggleVisibility}
                            className="text-default-400 hover:text-default-600"
                            aria-label={isVisible ? 'Hide password' : 'Show password'}
                        >
                            {isVisible ? (
                                <EyeSlashIcon className="w-4 h-4 text-default-400"/>
                            ) : (
                                <EyeIcon className="w-4 h-4 text-default-400"/>
                            )}
                        </RootButton>
                    )
                }
            />

            {/* Field Errors */}
            {errors && <FieldError error={errors} fieldName={name}/>}

            {/* Password Strength Indicator */}
            <AnimatePresence>
                {shouldShowStrength && strength && (
                    <motion.div
                        initial={{opacity: 0, height: 0}}
                        animate={{opacity: 1, height: 'auto'}}
                        exit={{opacity: 0, height: 0}}
                        className="space-y-2"
                    >
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-default-600">Password strength:</span>
                            <span className={`font-medium text-${strength.color}`}>
                {strength.label}
              </span>
                        </div>
                        <Progress
                            value={strength.percentage}
                            color={strength.color as any}
                            size="sm"
                            className="w-full"
                        />
                        {strength.feedback.length > 0 && (
                            <div className="text-xs text-default-500">
                                {strength.feedback[0]}
                            </div>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Password Requirements */}
            <AnimatePresence>
                {shouldShowRequirements && strength && (
                    <motion.div
                        initial={{opacity: 0, height: 0}}
                        animate={{opacity: 1, height: 'auto'}}
                        exit={{opacity: 0, height: 0}}
                        className="space-y-2"
                    >
                        {!advanceRequirements ? <>
                            <div className="text-sm font-medium text-default-700">
                                Password Requirements:
                            </div>
                            <div className="space-y-1">
                                {strength.requirements.map(req => (
                                    <div key={req.id} className="flex items-center gap-2 text-xs">
                                        <div className={`
                    w-4 h-4 rounded-full flex items-center justify-center
                    ${req.met
                                            ? 'bg-success-100 text-success-600 dark:bg-success-900/30 dark:text-success-400'
                                            : 'bg-default-200 text-default-400 dark:bg-default-800'
                                        }
                  `}>
                                            {req.met ? (
                                                <svg className="w-3 h-3" fill="none" stroke="currentColor"
                                                     viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                                          d="M5 13l4 4L19 7"/>
                                                </svg>
                                            ) : (
                                                <div className="w-1.5 h-1.5 rounded-full bg-current"/>
                                            )}
                                        </div>
                                        <span
                                            className={req.met ? 'text-success-600 dark:text-success-400' : 'text-default-500'}>
                    {req.label}
                  </span>
                                    </div>
                                ))}
                            </div>
                        </>:
                            <PasswordStrengthIndicator
                                password={value}
                                requirements={advanceRequirements}
                            />}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Password Suggestions */}
            <AnimatePresence>
                {shouldShowSuggestions && strength && (
                    <div
                    >


                        {suggestedPasswords.length > 0 && (
                            <div className="space-y-2">
                                <div className="text-xs text-default-500">
                                    Suggested passwords:
                                </div>
                                <div className="space-y-1">
                                    {suggestedPasswords.map((suggestion, index) => (
                                        <button
                                            key={index}
                                            type="button"
                                            // onClick={() => {
                                            //     handleFieldChange('password', suggestion);
                                            //     handleFieldChange('confirmPassword', suggestion);
                                            // }}
                                            className="text-xs font-mono text-primary-600 hover:text-primary-800 hover:underline block"
                                        >
                                            {suggestion}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </AnimatePresence>

            {/* Generate Suggestions Button */}
            <AnimatePresence>
                {enableGenerate &&  (
                    <Button
                        type="button"
                        variant="light"
                        size="sm"
                        onPress={generateSuggestions}
                    >
                        Generate secure password
                    </Button>
                )}
            </AnimatePresence>
        </div>
    );
}

export const PasswordField = React.memo(PasswordFieldComponent);

// ============================================================================
// Password Confirmation Field
// ============================================================================

export function PasswordConfirmationField({
                                              originalPassword,
                                              ...props
                                          }: PasswordFieldProps & { originalPassword: string }) {
    return (
        <PasswordField
            {...props}
            name={props.name || 'passwordConfirmation'}
            label={props.label || 'Confirm Password'}
            placeholder={props.placeholder || 'Confirm your password'}
            autoComplete="new-password"
            isConfirmation={true}
            originalPassword={originalPassword}
            showStrength={false}
            showRequirements={false}
        />
    );
}


// ============================================================================
// Password Strength Indicator
// ============================================================================

function PasswordStrengthIndicator({
                                       password,
                                       requirements
                                   }: {
    password: string;
    requirements?: SignUpFormProps['passwordRequirements'];
}) {
    const strength = getPasswordStrength(password);

    const getStrengthColor = (strength: string) => {
        switch (strength) {
            case 'weak':
                return 'danger';
            case 'fair':
                return 'warning';
            case 'good':
                return 'primary';
            case 'strong':
                return 'success';
            default:
                return 'default';
        }
    };

    const getStrengthText = (strength: string) => {
        switch (strength) {
            case 'weak':
                return 'Weak';
            case 'fair':
                return 'Fair';
            case 'good':
                return 'Good';
            case 'strong':
                return 'Strong';
            default:
                return '';
        }
    };

    if (!password) return null;

    return (
        <div className="space-y-2">
            {/* Strength Bar */}
            <div className="flex items-center gap-2">
                <Progress
                    value={(strength.score / 6) * 100}
                    color={getStrengthColor(strength.strength) as any}
                    size="sm"
                    className="flex-1"
                />
                <Chip
                    size="sm"
                    color={getStrengthColor(strength.strength) as any}
                    variant="flat"
                >
                    {getStrengthText(strength.strength)}
                </Chip>
            </div>

            {/* Feedback */}
            {strength.feedback.length > 0 && (
                <div className="text-xs space-y-1">
                    {strength.feedback.map((feedback, index) => (
                        <div key={index} className="flex items-center gap-1 text-default-500">
                            <ExclamationTriangleIcon className="w-3 h-3"/>
                            <span>{feedback}</span>
                        </div>
                    ))}
                </div>
            )}

            {/* Requirements checklist */}
            {requirements && (
                <div className="text-xs space-y-1">
                    {requirements.minLength && (
                        <RequirementItem
                            met={password.length >= requirements.minLength}
                            text={`At least ${requirements.minLength} characters`}
                        />
                    )}
                    {requirements.requireUppercase && (
                        <RequirementItem
                            met={/[A-Z]/.test(password)}
                            text="One uppercase letter"
                        />
                    )}
                    {requirements.requireLowercase && (
                        <RequirementItem
                            met={/[a-z]/.test(password)}
                            text="One lowercase letter"
                        />
                    )}
                    {requirements.requireNumbers && (
                        <RequirementItem
                            met={/\d/.test(password)}
                            text="One number"
                        />
                    )}
                    {requirements.requireSymbols && (
                        <RequirementItem
                            met={/[!@#$%^&*(),.?":{}|<>]/.test(password)}
                            text="One symbol"
                        />
                    )}
                </div>
            )}
        </div>
    );
}

function RequirementItem({met, text}: { met: boolean; text: string }) {
    return (
        <div className={`flex items-center gap-1 ${met ? 'text-success-600' : 'text-default-400'}`}>
            <CheckIcon className={`w-3 h-3 ${met ? 'opacity-100' : 'opacity-30'}`}/>
            <span>{text}</span>
        </div>
    );
}

// ============================================================================
// Export
// ============================================================================

export default PasswordField;