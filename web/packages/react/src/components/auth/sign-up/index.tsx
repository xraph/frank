/**
 * @frank-auth/react - Sign Up Components Index
 *
 * Main entry point for all sign-up related components.
 * Exports all sign-up variants and utilities.
 */

// ============================================================================
// Main Components
// ============================================================================

import type {RadiusT, SizeT} from "@/types";

export * from './sign-up';
export { SignUpForm } from './sign-up-form';
export { SignUpModal } from './sign-up-modal';
export { SignUpButton } from './sign-up-button';
export { SignUpCard } from './sign-up-card';

// ============================================================================
// Shared Types and Interfaces
// ============================================================================

export interface BaseSignUpProps {
    /**
     * Sign-up methods to show
     */
    methods?: ('password' | 'oauth' | 'magic-link' | 'passkey' | 'sso')[];

    /**
     * Initial email value
     */
    email?: string;

    /**
     * Initial organization ID (for invitations)
     */
    organizationId?: string;

    /**
     * Invitation token (for org invitations)
     */
    invitationToken?: string;

    /**
     * Redirect URL after successful sign-up
     */
    redirectUrl?: string;

    /**
     * Success callback
     */
    onSuccess?: (result: any) => void;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Custom title
     */
    title?: string;

    /**
     * Custom subtitle
     */
    subtitle?: string;

    /**
     * Form size
     */
    size?: SizeT;

    radius?: RadiusT;

    /**
     * Whether to show branding
     */
    showBranding?: boolean;

    /**
     * Disabled state
     */
    disabled?: boolean;

    /**
     * Require terms of service acceptance
     */
    requireTerms?: boolean;

    /**
     * Terms of service URL
     */
    termsUrl?: string;

    /**
     * Privacy policy URL
     */
    privacyUrl?: string;
}

export interface SignUpFormProps extends BaseSignUpProps {
    /**
     * Show sign-in link
     */
    showSignInLink?: boolean;

    /**
     * Form variant
     */
    variant?: 'default' | 'minimal' | 'compact';

    /**
     * Custom className
     */
    className?: string;

    /**
     * Custom footer content
     */
    footer?: React.ReactNode;

    /**
     * Custom header content
     */
    header?: React.ReactNode;

    /**
     * Password requirements
     */
    passwordRequirements?: {
        minLength?: number;
        requireUppercase?: boolean;
        requireLowercase?: boolean;
        requireNumbers?: boolean;
        requireSymbols?: boolean;
    };

    /**
     * Auto-focus first field
     */
    autoFocus?: boolean;

    /**
     * Collect additional fields
     */
    collectFields?: ('firstName' | 'lastName' | 'username' | 'phoneNumber')[];
}

export interface SignUpModalProps extends BaseSignUpProps {
    /**
     * Whether the modal is open
     */
    isOpen?: boolean;

    /**
     * Callback for when modal should close
     */
    onClose?: () => void;

    /**
     * Modal size
     */
    modalSize?: 'sm' | 'md' | 'lg' | 'xl' | 'full';

    /**
     * Whether modal can be closed by clicking backdrop
     */
    closeOnBackdropClick?: boolean;

    /**
     * Whether modal can be closed by pressing escape
     */
    closeOnEscape?: boolean;

    /**
     * Custom modal className
     */
    modalClassName?: string;

    /**
     * Show close button
     */
    showCloseButton?: boolean;

    /**
     * Modal backdrop blur
     */
    backdrop?: 'opaque' | 'blur' | 'transparent';

    /**
     * Modal placement
     */
    placement?: 'auto' | 'top' | 'center' | 'bottom';
}

export interface SignUpButtonProps {
    /**
     * Button text
     */
    children?: React.ReactNode;

    /**
     * Button variant
     */
    variant?: 'solid' | 'bordered' | 'light' | 'flat' | 'faded' | 'shadow' | 'ghost';

    /**
     * Button color
     */
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    /**
     * Button size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Full width button
     */
    fullWidth?: boolean;

    /**
     * Button icon
     */
    startContent?: React.ReactNode;
    endContent?: React.ReactNode;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Modal mode - opens sign-up in modal instead of navigation
     */
    modalMode?: boolean;

    /**
     * Props to pass to the sign-up modal
     */
    modalProps?: Partial<SignUpModalProps>;

    /**
     * Navigation URL (when not in modal mode)
     */
    href?: string;

    /**
     * Custom onClick handler
     */
    onClick?: () => void;

    /**
     * Disabled state
     */
    disabled?: boolean;
}

export interface SignUpCardProps extends BaseSignUpProps {
    /**
     * Card variant
     */
    variant?: 'shadow' | 'bordered' | 'flat';

    /**
     * Custom className
     */
    className?: string;

    /**
     * Card padding
     */
    padding?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Card radius
     */
    radius?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Whether card has shadow
     */
    shadow?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Whether card is blurred
     */
    isBlurred?: boolean;

    /**
     * Custom footer content
     */
    footer?: React.ReactNode;

    /**
     * Custom header content
     */
    header?: React.ReactNode;

    /**
     * Card max width
     */
    maxWidth?: string | number;

    /**
     * Center the card
     */
    centered?: boolean;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get default sign-up configuration based on features
 */
export const getDefaultSignUpConfig = (features: any) => {
    const methods: ('password' | 'oauth' | 'magic-link' | 'passkey')[] = [];

    if (features.signUp) methods.push('password');
    if (features.oauth) methods.push('oauth');
    if (features.magicLink) methods.push('magic-link');
    if (features.passkeys) methods.push('passkey');

    return {
        methods,
        showSignInLink: features.signIn,
        requireTerms: true,
    };
};

/**
 * Sign-up validation helpers
 */
export const signUpValidation = {
    email: (email: string) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    password: (password: string, requirements?: SignUpFormProps['passwordRequirements']) => {
        const req = requirements || {};

        if (req.minLength && password.length < req.minLength) return false;
        if (req.requireUppercase && !/[A-Z]/.test(password)) return false;
        if (req.requireLowercase && !/[a-z]/.test(password)) return false;
        if (req.requireNumbers && !/\d/.test(password)) return false;
        if (req.requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;

        return password.length >= (req.minLength || 8);
    },

    firstName: (name: string) => {
        return name.length >= 2 && /^[a-zA-Z\s]+$/.test(name);
    },

    lastName: (name: string) => {
        return name.length >= 2 && /^[a-zA-Z\s]+$/.test(name);
    },

    username: (username: string) => {
        return username.length >= 3 && /^[a-zA-Z0-9_-]+$/.test(username);
    },

    phoneNumber: (phone: string) => {
        return /^\+?[1-9]\d{1,14}$/.test(phone.replace(/\s/g, ''));
    },
};

/**
 * Password strength calculator
 */
export const getPasswordStrength = (password: string): {
    score: number;
    feedback: string[];
    strength: 'weak' | 'fair' | 'good' | 'strong';
} => {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= 8) {
        score += 1;
    } else {
        feedback.push('Use at least 8 characters');
    }

    if (password.length >= 12) {
        score += 1;
    }

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Include lowercase letters');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Include uppercase letters');

    if (/\d/.test(password)) score += 1;
    else feedback.push('Include numbers');

    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    else feedback.push('Include symbols');

    // Common patterns penalty
    if (/(.)\1{2,}/.test(password)) {
        score -= 1;
        feedback.push('Avoid repeated characters');
    }

    if (/123|abc|qwe/i.test(password)) {
        score -= 1;
        feedback.push('Avoid common patterns');
    }

    // Determine strength level
    let strength: 'weak' | 'fair' | 'good' | 'strong';
    if (score <= 2) strength = 'weak';
    else if (score <= 4) strength = 'fair';
    else if (score <= 5) strength = 'good';
    else strength = 'strong';

    return {
        score: Math.max(0, Math.min(6, score)),
        feedback,
        strength,
    };
};

/**
 * Generate secure password suggestions
 */
export const generatePasswordSuggestions = (length = 12): string[] => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*(),.?":{}|<>';

    const allChars = lowercase + uppercase + numbers + symbols;

    const suggestions: string[] = [];

    for (let i = 0; i < 3; i++) {
        let password = '';

        // Ensure at least one character from each category
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        // Fill the rest randomly
        for (let j = 4; j < length; j++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        // Shuffle the password
        password = password.split('').sort(() => Math.random() - 0.5).join('');
        suggestions.push(password);
    }

    return suggestions;
};

/**
 * Format invitation data
 */
export const formatInvitationData = (invitationToken?: string) => {
    if (!invitationToken) return null;

    try {
        // Decode invitation token (assuming it's base64 encoded JSON)
        const decoded = atob(invitationToken);
        const data = JSON.parse(decoded);

        return {
            organizationId: data.orgId,
            organizationName: data.orgName,
            inviterName: data.inviterName,
            inviterEmail: data.inviterEmail,
            role: data.role,
            expiresAt: new Date(data.expiresAt),
        };
    } catch {
        return null;
    }
};

// ============================================================================
// Constants
// ============================================================================

export const DEFAULT_PASSWORD_REQUIREMENTS = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: false,
};

export const COLLECT_FIELDS_OPTIONS = [
    { key: 'firstName', label: 'First Name', required: true },
    { key: 'lastName', label: 'Last Name', required: true },
    { key: 'username', label: 'Username', required: false },
    { key: 'phoneNumber', label: 'Phone Number', required: false },
] as const;

// ============================================================================
// Default Export - Main Sign Up Component
// ============================================================================

export { SignUp as default } from './sign-up';