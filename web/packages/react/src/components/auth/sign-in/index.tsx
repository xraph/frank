/**
 * @frank-auth/react - Sign In Components Index
 *
 * Main entry point for all sign-in related components.
 * Exports all sign-in variants and utilities.
 */

// ============================================================================
// Main Components
// ============================================================================

export { SignInForm } from './sign-in-form';
export { SignInModal } from './sign-in-modal';
export { SignInButton } from './sign-in-button';
export { SignInCard } from './sign-in-card';
export { SignIn, OrganizationSignIn, PasswordlessSignIn, ProgressiveSignIn, SecureSignIn, InvitationSignIn,
    MultiOrganizationSignIn, SSOSignIn, URLBasedSignIn, SubdomainSignIn } from './sign-in';

// ============================================================================
// Component Types
// ============================================================================

// ============================================================================
// Shared Types and Interfaces
// ============================================================================

export interface BaseSignInProps {
    /**
     * Sign-in methods to show
     */
    methods?: ('password' | 'oauth' | 'magic-link' | 'passkey' | 'sso')[];

    /**
     * Initial email value
     */
    email?: string;

    /**
     * Initial organization ID
     */
    organizationId?: string;

    /**
     * Redirect URL after successful sign-in
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
    size?: 'sm' | 'md' | 'lg';

    /**
     * Whether to show branding
     */
    showBranding?: boolean;

    /**
     * Disabled state
     */
    disabled?: boolean;
}

export interface SignInFormProps extends BaseSignInProps {
    /**
     * Show sign-up link
     */
    showSignUpLink?: boolean;

    /**
     * Show forgot password link
     */
    showForgotPasswordLink?: boolean;

    /**
     * Show organization selector
     */
    showOrganizationSelector?: boolean;

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
}

export interface SignInModalProps extends BaseSignInProps {
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
}

export interface SignInButtonProps {
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
     * Modal mode - opens sign-in in modal instead of navigation
     */
    modalMode?: boolean;

    /**
     * Props to pass to the sign-in modal
     */
    modalProps?: Partial<SignInModalProps>;

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

export interface SignInCardProps extends BaseSignInProps {
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
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get default sign-in configuration based on features
 */
export const getDefaultSignInConfig = (features: any) => {
    const methods: ('password' | 'oauth' | 'magic-link' | 'passkey' | 'sso')[] = [];

    if (features.signIn) methods.push('password');
    if (features.oauth) methods.push('oauth');
    if (features.magicLink) methods.push('magic-link');
    if (features.passkeys) methods.push('passkey');
    if (features.sso) methods.push('sso');

    return {
        methods,
        showSignUpLink: features.signUp,
        showForgotPasswordLink: features.passwordReset,
    };
};

/**
 * Sign-in validation helpers
 */
export const signInValidation = {
    email: (email: string) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    password: (password: string) => {
        return password.length >= 8;
    },

    organizationId: (orgId: string) => {
        return orgId.length > 0;
    },
};

// ============================================================================
// Default Export - Main Sign In Form
// ============================================================================

export { SignInForm as default } from './sign-in-form';