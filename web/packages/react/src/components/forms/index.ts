/**
 * @frank-auth/react - Forms Components Index
 *
 * Main entry point for all form components. Exports all form fields,
 * validation utilities, and form management components.
 */

// ============================================================================
// Form Components
// ============================================================================

// Form wrapper and context
import {FormWrapper, type FormWrapperProps, useFormContext, useFormField} from './form-wrapper';
// Input field components
import {PasswordConfirmationField, PasswordField, type PasswordFieldProps,} from './password-field';
import {EmailField, type EmailFieldProps,} from './email-field';
import {PhoneField, type PhoneFieldProps,} from './phone-field';
import {VerificationCode, type VerificationCodeProps} from './verification-code';
import FieldError, {FieldErrorProps, useFieldError} from './field-error';

export {
    FormWrapper,
    useFormContext,
    useFormField,
    FormContext,
    type FormWrapperProps
} from './form-wrapper';

// Field error handling
export {
    FieldError,
    useFieldError,
    type FieldErrorProps
} from './field-error';

export {
    PasswordField,
    PasswordConfirmationField,
    type PasswordFieldProps,
    type PasswordRules,
    type PasswordStrength,
    type PasswordRequirement
} from './password-field';

export {
    EmailField,
    type EmailFieldProps,
    type EmailValidation
} from './email-field';

export {
    PhoneField,
    type PhoneFieldProps,
    type Country
} from './phone-field';

export {
    VerificationCode,
    type VerificationCodeProps
} from './verification-code';

// ============================================================================
// Form Validation Utilities
// ============================================================================

/**
 * Common validation rules for forms
 */
export const ValidationRules = {
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    phone: /^\+?[\d\s\-\(\)]+$/,
    password: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: /[A-Z]/,
        requireLowercase: /[a-z]/,
        requireNumbers: /\d/,
        requireSpecialChars: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'\/~`]/,
    },
    verificationCode: {
        numeric: /^\d+$/,
        alphanumeric: /^[a-zA-Z0-9]+$/,
    },
};

/**
 * Common validation functions
 */
export const ValidationHelpers = {
    isValidEmail: (email: string): boolean => ValidationRules.email.test(email),

    isValidPhone: (phone: string): boolean => ValidationRules.phone.test(phone),

    isStrongPassword: (password: string): boolean => {
        const rules = ValidationRules.password;
        return password.length >= rules.minLength &&
            password.length <= rules.maxLength &&
            rules.requireUppercase.test(password) &&
            rules.requireLowercase.test(password) &&
            rules.requireNumbers.test(password) &&
            rules.requireSpecialChars.test(password);
    },

    isValidVerificationCode: (code: string, length: number, type: 'numeric' | 'alphanumeric' = 'numeric'): boolean => {
        if (code.length !== length) return false;
        return type === 'numeric'
            ? ValidationRules.verificationCode.numeric.test(code)
            : ValidationRules.verificationCode.alphanumeric.test(code);
    },
};

// ============================================================================
// Form Field Collections
// ============================================================================

/**
 * Collection of all form field components
 */
export const FormFields = {
    PasswordField,
    PasswordConfirmationField,
    EmailField,
    PhoneField,
    VerificationCode,
} as const;

/**
 * Collection of form utility components
 */
export const FormUtilities = {
    FormWrapper,
    FieldError,
} as const;

// ============================================================================
// Form Hook Collections
// ============================================================================

/**
 * Collection of form hooks
 */
export const FormHooks = {
    useFormContext,
    useFormField,
    useFieldError,
} as const;

// ============================================================================
// Form Type Collections
// ============================================================================

/**
 * Collection of form field prop types
 */
export type FormFieldProps = {
    PasswordField: PasswordFieldProps;
    EmailField: EmailFieldProps;
    PhoneField: PhoneFieldProps;
    VerificationCode: VerificationCodeProps;
};

/**
 * Collection of form utility prop types
 */
export type FormUtilityProps = {
    FormWrapper: FormWrapperProps;
    FieldError: FieldErrorProps;
};

// ============================================================================
// Form Presets
// ============================================================================

/**
 * Common form configurations for different auth flows
 */
export const FormPresets = {
    signIn: {
        fields: ['email', 'password'],
        validation: {
            email: { required: true, validateFormat: true },
            password: { required: true, minLength: 1 },
        },
    },

    signUp: {
        fields: ['email', 'password', 'passwordConfirmation'],
        validation: {
            email: { required: true, validateFormat: true },
            password: { required: true, showStrength: true },
            passwordConfirmation: { required: true, mustMatch: 'password' },
        },
    },

    resetPassword: {
        fields: ['email'],
        validation: {
            email: { required: true, validateFormat: true },
        },
    },

    changePassword: {
        fields: ['currentPassword', 'newPassword', 'confirmPassword'],
        validation: {
            currentPassword: { required: true },
            newPassword: { required: true, showStrength: true },
            confirmPassword: { required: true, mustMatch: 'newPassword' },
        },
    },

    verifyEmail: {
        fields: ['verificationCode'],
        validation: {
            verificationCode: { required: true, length: 6, type: 'numeric' },
        },
    },

    verifyPhone: {
        fields: ['phone', 'verificationCode'],
        validation: {
            phone: { required: true, validateFormat: true },
            verificationCode: { required: true, length: 6, type: 'numeric' },
        },
    },

    setupMFA: {
        fields: ['verificationCode'],
        validation: {
            verificationCode: { required: true, length: 6, type: 'numeric' },
        },
    },

    verifyMFA: {
        fields: ['verificationCode'],
        validation: {
            verificationCode: { required: true, length: 6, type: 'numeric' },
        },
    },

    organizationInvite: {
        fields: ['email'],
        validation: {
            email: { required: true, validateFormat: true },
        },
    },
} as const;

// ============================================================================
// Form Builder Utility
// ============================================================================

/**
 * Utility function to build forms from presets
 */
export function buildForm(preset: keyof typeof FormPresets, overrides: any = {}) {
    const presetConfig = FormPresets[preset];

    return {
        ...presetConfig,
        ...overrides,
        validation: {
            ...presetConfig.validation,
            ...overrides.validation,
        },
    };
}

// ============================================================================
// Form State Management
// ============================================================================

/**
 * Generic form state interface
 */
export interface FormState {
    values: Record<string, any>;
    errors: Record<string, string | string[]>;
    touched: Record<string, boolean>;
    isSubmitting: boolean;
    isValid: boolean;
    isDirty: boolean;
}

/**
 * Form action types
 */
export type FormAction =
    | { type: 'SET_VALUE'; field: string; value: any }
    | { type: 'SET_ERROR'; field: string; error: string | string[] | null }
    | { type: 'SET_TOUCHED'; field: string; touched: boolean }
    | { type: 'SET_SUBMITTING'; isSubmitting: boolean }
    | { type: 'RESET_FORM'; initialValues?: Record<string, any> }
    | { type: 'CLEAR_ERRORS' };

/**
 * Form reducer function
 */
export function formReducer(state: FormState, action: FormAction): FormState {
    switch (action.type) {
        case 'SET_VALUE':
            return {
                ...state,
                values: { ...state.values, [action.field]: action.value },
                isDirty: true,
                // Clear error when value changes
                errors: { ...state.errors, [action.field]: '' },
            };

        case 'SET_ERROR':
            return {
                ...state,
                errors: {
                    ...state.errors,
                    [action.field]: action.error || '',
                },
            };

        case 'SET_TOUCHED':
            return {
                ...state,
                touched: { ...state.touched, [action.field]: action.touched },
            };

        case 'SET_SUBMITTING':
            return {
                ...state,
                isSubmitting: action.isSubmitting,
            };

        case 'RESET_FORM':
            return {
                values: action.initialValues || {},
                errors: {},
                touched: {},
                isSubmitting: false,
                isValid: true,
                isDirty: false,
            };

        case 'CLEAR_ERRORS':
            return {
                ...state,
                errors: {},
            };

        default:
            return state;
    }
}

// ============================================================================
// Export Default
// ============================================================================

// Export the most commonly used components as default
export default {
    FormWrapper,
    FieldError,
    PasswordField,
    EmailField,
    PhoneField,
    VerificationCode,
    ValidationHelpers,
    FormPresets,
};