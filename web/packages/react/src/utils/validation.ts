// Validation result interface
export interface ValidationResult {
    isValid: boolean;
    error?: string;
    errors?: string[];
}

// Validation rule interface
export type ValidationRule = (value: any) => ValidationResult | Promise<ValidationResult>

// Common validation rules
export const required = (message = 'This field is required'): ValidationRule => {
    return (value: any): ValidationResult => {
        const isEmpty = value === null ||
            value === undefined ||
            (typeof value === 'string' && value.trim() === '') ||
            (Array.isArray(value) && value.length === 0);

        return {
            isValid: !isEmpty,
            error: isEmpty ? message : undefined,
        };
    };
};

export const minLength = (min: number, message?: string): ValidationRule => {
    return (value: string): ValidationResult => {
        const actualMessage = message || `Must be at least ${min} characters`;
        const isValid = typeof value === 'string' && value.length >= min;

        return {
            isValid,
            error: isValid ? undefined : actualMessage,
        };
    };
};

export const maxLength = (max: number, message?: string): ValidationRule => {
    return (value: string): ValidationResult => {
        const actualMessage = message || `Must be no more than ${max} characters`;
        const isValid = typeof value === 'string' && value.length <= max;

        return {
            isValid,
            error: isValid ? undefined : actualMessage,
        };
    };
};

export const pattern = (regex: RegExp, message = 'Invalid format'): ValidationRule => {
    return (value: string): ValidationResult => {
        const isValid = typeof value === 'string' && regex.test(value);

        return {
            isValid,
            error: isValid ? undefined : message,
        };
    };
};

export const email = (message = 'Invalid email address'): ValidationRule => {
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

    return (value: string): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        const isValid = emailRegex.test(value);
        return {
            isValid,
            error: isValid ? undefined : message,
        };
    };
};

export const phone = (message = 'Invalid phone number'): ValidationRule => {
    // Basic international phone number regex
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;

    return (value: string): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        // Remove all non-digit characters except +
        const cleaned = value.replace(/[^\d+]/g, '');
        const isValid = phoneRegex.test(cleaned);

        return {
            isValid,
            error: isValid ? undefined : message,
        };
    };
};

export const username = (message = 'Username must be 3-30 characters and contain only letters, numbers, and underscores'): ValidationRule => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;

    return (value: string): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        const isValid = usernameRegex.test(value);
        return {
            isValid,
            error: isValid ? undefined : message,
        };
    };
};

export const password = (options: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSymbols?: boolean;
    message?: string;
} = {}): ValidationRule => {
    const {
        minLength: min = 8,
        requireUppercase = true,
        requireLowercase = true,
        requireNumbers = true,
        requireSymbols = false,
        message,
    } = options;

    return (value: string): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        const errors: string[] = [];

        if (value.length < min) {
            errors.push(`Must be at least ${min} characters long`);
        }

        if (requireUppercase && !/[A-Z]/.test(value)) {
            errors.push('Must contain at least one uppercase letter');
        }

        if (requireLowercase && !/[a-z]/.test(value)) {
            errors.push('Must contain at least one lowercase letter');
        }

        if (requireNumbers && !/\d/.test(value)) {
            errors.push('Must contain at least one number');
        }

        if (requireSymbols && !/[^A-Za-z0-9]/.test(value)) {
            errors.push('Must contain at least one special character');
        }

        const isValid = errors.length === 0;

        return {
            isValid,
            error: message || (isValid ? undefined : errors[0]),
            errors: errors.length > 0 ? errors : undefined,
        };
    };
};

export const confirmPassword = (originalPassword: string, message = 'Passwords do not match'): ValidationRule => {
    return (value: string): ValidationResult => {
        const isValid = value === originalPassword;

        return {
            isValid,
            error: isValid ? undefined : message,
        };
    };
};

export const url = (message = 'Invalid URL'): ValidationRule => {
    return (value: string): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        try {
            new URL(value);
            return { isValid: true };
        } catch {
            return {
                isValid: false,
                error: message,
            };
        }
    };
};

export const number = (options: {
    min?: number;
    max?: number;
    integer?: boolean;
    message?: string;
} = {}): ValidationRule => {
    const { min, max, integer = false, message } = options;

    return (value: any): ValidationResult => {
        if (value === null || value === undefined || value === '') {
            return { isValid: true }; // Allow empty for optional fields
        }

        const num = Number(value);

        if (isNaN(num)) {
            return {
                isValid: false,
                error: message || 'Must be a valid number',
            };
        }

        if (integer && !Number.isInteger(num)) {
            return {
                isValid: false,
                error: message || 'Must be a whole number',
            };
        }

        if (min !== undefined && num < min) {
            return {
                isValid: false,
                error: message || `Must be at least ${min}`,
            };
        }

        if (max !== undefined && num > max) {
            return {
                isValid: false,
                error: message || `Must be no more than ${max}`,
            };
        }

        return { isValid: true };
    };
};

export const oneOf = (options: any[], message?: string): ValidationRule => {
    return (value: any): ValidationResult => {
        if (!value) return { isValid: true }; // Allow empty for optional fields

        const isValid = options.includes(value);
        const actualMessage = message || `Must be one of: ${options.join(', ')}`;

        return {
            isValid,
            error: isValid ? undefined : actualMessage,
        };
    };
};

export const custom = (validator: (value: any) => boolean | string, message = 'Invalid value'): ValidationRule => {
    return (value: any): ValidationResult => {
        const result = validator(value);

        if (typeof result === 'boolean') {
            return {
                isValid: result,
                error: result ? undefined : message,
            };
        }

        // If validator returns a string, it's an error message
        return {
            isValid: false,
            error: result,
        };
    };
};

export const asyncValidation = (validator: (value: any) => Promise<boolean | string>, message = 'Invalid value'): ValidationRule => {
    return async (value: any): Promise<ValidationResult> => {
        try {
            const result = await validator(value);

            if (typeof result === 'boolean') {
                return {
                    isValid: result,
                    error: result ? undefined : message,
                };
            }

            // If validator returns a string, it's an error message
            return {
                isValid: false,
                error: result,
            };
        } catch (error) {
            return {
                isValid: false,
                error: error instanceof Error ? error.message : 'Validation failed',
            };
        }
    };
};

// Combine multiple validation rules
export const combine = (...rules: ValidationRule[]): ValidationRule => {
    return async (value: any): Promise<ValidationResult> => {
        for (const rule of rules) {
            const result = await rule(value);
            if (!result.isValid) {
                return result;
            }
        }

        return { isValid: true };
    };
};

// Form validation utilities
export interface FormValidationRules {
    [fieldName: string]: ValidationRule | ValidationRule[];
}

export interface FormValidationResult {
    isValid: boolean;
    errors: Record<string, string>;
    fieldErrors: Record<string, string[]>;
}

export const validateForm = async (
    data: Record<string, any>,
    rules: FormValidationRules
): Promise<FormValidationResult> => {
    const errors: Record<string, string> = {};
    const fieldErrors: Record<string, string[]> = {};

    for (const [fieldName, fieldRules] of Object.entries(rules)) {
        const value = data[fieldName];
        const rulesArray = Array.isArray(fieldRules) ? fieldRules : [fieldRules];

        for (const rule of rulesArray) {
            const result = await rule(value);

            if (!result.isValid) {
                errors[fieldName] = result.error || 'Invalid value';

                if (result.errors) {
                    fieldErrors[fieldName] = result.errors;
                } else if (result.error) {
                    fieldErrors[fieldName] = [result.error];
                }

                break; // Stop at first error for this field
            }
        }
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
        fieldErrors,
    };
};

export const validateField = async (
    value: any,
    rules: ValidationRule | ValidationRule[]
): Promise<ValidationResult> => {
    const rulesArray = Array.isArray(rules) ? rules : [rules];

    for (const rule of rulesArray) {
        const result = await rule(value);
        if (!result.isValid) {
            return result;
        }
    }

    return { isValid: true };
};

// Specific validation functions for auth forms
export const validateSignInForm = async (data: {
    identifier: string;
    password?: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {
        identifier: [
            required('Email or username is required'),
            // Could be email or username, so we don't validate format here
        ],
    };

    if (data.password !== undefined) {
        rules.password = required('Password is required');
    }

    return validateForm(data, rules);
};

export const validateSignUpForm = async (data: {
    emailAddress?: string;
    username?: string;
    password?: string;
    confirmPassword?: string;
    firstName?: string;
    lastName?: string;
    phoneNumber?: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {};

    if (data.emailAddress !== undefined) {
        rules.emailAddress = [required('Email is required'), email()];
    }

    if (data.username !== undefined) {
        rules.username = [required('Username is required'), username()];
    }

    if (data.password !== undefined) {
        rules.password = [required('Password is required'), password()];
    }

    if (data.confirmPassword !== undefined) {
        rules.confirmPassword = [
            required('Please confirm your password'),
            confirmPassword(data.password || ''),
        ];
    }

    if (data.firstName !== undefined) {
        rules.firstName = [
            required('First name is required'),
            minLength(1),
            maxLength(50),
        ];
    }

    if (data.lastName !== undefined) {
        rules.lastName = [
            required('Last name is required'),
            minLength(1),
            maxLength(50),
        ];
    }

    if (data.phoneNumber !== undefined) {
        rules.phoneNumber = phone();
    }

    return validateForm(data, rules);
};

export const validatePasswordResetForm = async (data: {
    emailAddress: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {
        emailAddress: [required('Email is required'), email()],
    };

    return validateForm(data, rules);
};

export const validatePasswordChangeForm = async (data: {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {
        currentPassword: required('Current password is required'),
        newPassword: [required('New password is required'), password()],
        confirmPassword: [
            required('Please confirm your new password'),
            confirmPassword(data.newPassword),
        ],
    };

    return validateForm(data, rules);
};

export const validateProfileForm = async (data: {
    firstName?: string;
    lastName?: string;
    username?: string;
    emailAddress?: string;
    phoneNumber?: string;
    bio?: string;
    website?: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {};

    if (data.firstName !== undefined) {
        rules.firstName = [minLength(1), maxLength(50)];
    }

    if (data.lastName !== undefined) {
        rules.lastName = [minLength(1), maxLength(50)];
    }

    if (data.username !== undefined) {
        rules.username = username();
    }

    if (data.emailAddress !== undefined) {
        rules.emailAddress = email();
    }

    if (data.phoneNumber !== undefined) {
        rules.phoneNumber = phone();
    }

    if (data.bio !== undefined) {
        rules.bio = maxLength(500);
    }

    if (data.website !== undefined) {
        rules.website = url();
    }

    return validateForm(data, rules);
};

export const validateOrganizationForm = async (data: {
    name: string;
    slug?: string;
    description?: string;
    website?: string;
    billingEmail?: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {
        name: [
            required('Organization name is required'),
            minLength(1),
            maxLength(100),
        ],
    };

    if (data.slug !== undefined) {
        rules.slug = [
            pattern(/^[a-z0-9-]+$/, 'Slug can only contain lowercase letters, numbers, and hyphens'),
            minLength(3),
            maxLength(50),
        ];
    }

    if (data.description !== undefined) {
        rules.description = maxLength(500);
    }

    if (data.website !== undefined) {
        rules.website = url();
    }

    if (data.billingEmail !== undefined) {
        rules.billingEmail = email();
    }

    return validateForm(data, rules);
};

export const validateInvitationForm = async (data: {
    emailAddress: string;
    roleId: string;
    customMessage?: string;
}): Promise<FormValidationResult> => {
    const rules: FormValidationRules = {
        emailAddress: [required('Email is required'), email()],
        roleId: required('Role is required'),
    };

    if (data.customMessage !== undefined) {
        rules.customMessage = maxLength(500);
    }

    return validateForm(data, rules);
};

// Utility functions for validation
export const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email);
};

export const isValidPhone = (phone: string): boolean => {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    const cleaned = phone.replace(/[^\d+]/g, '');
    return phoneRegex.test(cleaned);
};

export const isValidUsername = (username: string): boolean => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    return usernameRegex.test(username);
};

export const isValidUrl = (url: string): boolean => {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
};

export const sanitizeInput = (input: string): string => {
    return input.trim().replace(/[<>]/g, '');
};

export const normalizeEmail = (email: string): string => {
    return email.toLowerCase().trim();
};

export const normalizePhone = (phone: string): string => {
    return phone.replace(/[^\d+]/g, '');
};