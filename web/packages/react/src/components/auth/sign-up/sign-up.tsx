/**
 * @frank-auth/react - Main Sign Up Component
 *
 * Comprehensive sign-up component that can render as form, modal, or card
 * based on props. This is the main entry point for sign-up functionality.
 */

'use client';

import React from 'react';

import {SignUpForm} from './sign-up-form';
import {SignUpModal} from './sign-up-modal';
import {SignUpCard} from './sign-up-card';

import type {BaseSignUpProps, SignUpCardProps, SignUpFormProps, SignUpModalProps} from './index';

// ============================================================================
// Sign Up Component Types
// ============================================================================

export interface SignUpProps extends BaseSignUpProps {
    /**
     * Render mode
     */
    mode?: 'form' | 'modal' | 'card';

    /**
     * Modal-specific props (when mode is 'modal')
     */
    modalProps?: Partial<SignUpModalProps>;

    /**
     * Card-specific props (when mode is 'card')
     */
    cardProps?: Partial<SignUpCardProps>;

    /**
     * Form-specific props (when mode is 'form' or not specified)
     */
    formProps?: Partial<SignUpFormProps>;

    /**
     * Auto-detect mode based on context
     */
    autoMode?: boolean;
}

// ============================================================================
// Main Sign Up Component
// ============================================================================

/**
 * Universal Sign Up component that can render in different modes
 *
 * @example Form mode (default)
 * ```tsx
 * <SignUp
 *   methods={['password', 'oauth']}
 *   onSuccess={(result) => console.log('Signed up:', result)}
 * />
 * ```
 *
 * @example Modal mode
 * ```tsx
 * <SignUp
 *   mode="modal"
 *   isOpen={isModalOpen}
 *   onClose={() => setIsModalOpen(false)}
 *   onSuccess={(result) => console.log('Signed up:', result)}
 * />
 * ```
 *
 * @example Card mode
 * ```tsx
 * <SignUp
 *   mode="card"
 *   centered
 *   maxWidth={400}
 *   onSuccess={(result) => console.log('Signed up:', result)}
 * />
 * ```
 *
 * @example Auto-mode (detects context)
 * ```tsx
 * <SignUp
 *   autoMode
 *   onSuccess={(result) => console.log('Signed up:', result)}
 * />
 * ```
 */
export function SignUp({
                           mode = 'form',
                           modalProps = {},
                           cardProps = {},
                           formProps = {},
                           autoMode = false,
                           ...baseProps
                       }: SignUpProps) {
    // Auto-detect mode based on context
    const detectedMode = React.useMemo(() => {
        if (!autoMode) return mode;

        // Check if we're in a modal context (has backdrop)
        const hasBackdrop = typeof window !== 'undefined' &&
            document.querySelector('[data-modal-backdrop]');

        if (hasBackdrop) return 'modal';

        // Check if we're in a card context (has card container)
        const hasCardContainer = typeof window !== 'undefined' &&
            document.querySelector('[data-card-container]');

        if (hasCardContainer) return 'card';

        // Default to form
        return 'form';
    }, [autoMode, mode]);

    const finalMode = autoMode ? detectedMode : mode;

    // Render based on mode
    switch (finalMode) {
        case 'modal':
            return (
                <SignUpModal
                    {...baseProps}
                    {...modalProps}
                />
            );

        case 'card':
            return (
                <SignUpCard
                    {...baseProps}
                    {...cardProps}
                />
            );

        case 'form':
        default:
            return (
                <SignUpForm
                    {...baseProps}
                    {...formProps}
                />
            );
    }
}

// ============================================================================
// Sign Up Component Variants
// ============================================================================

/**
 * Sign Up Form (explicit form mode)
 */
export function SignUpFormComponent(props: SignUpProps) {
    return <SignUp {...props} mode="form" />;
}

/**
 * Sign Up Modal (explicit modal mode)
 */
export function SignUpModalComponent(props: SignUpProps) {
    return <SignUp {...props} mode="modal" />;
}

/**
 * Sign Up Card (explicit card mode)
 */
export function SignUpCardComponent(props: SignUpProps) {
    return <SignUp {...props} mode="card" />;
}

// ============================================================================
// Specialized Sign Up Components
// ============================================================================

/**
 * Organization Invitation Sign Up
 */
export interface OrganizationInviteSignUpProps extends Omit<SignUpProps, 'invitationToken' | 'organizationId'> {
    /**
     * Invitation token
     */
    invitationToken: string;

    /**
     * Organization name for display
     */
    organizationName?: string;

    /**
     * Inviter information
     */
    inviterInfo?: {
        name?: string;
        email?: string;
    };
}

export function OrganizationInviteSignUp({
                                             invitationToken,
                                             organizationName,
                                             inviterInfo,
                                             title,
                                             subtitle,
                                             ...props
                                         }: OrganizationInviteSignUpProps) {
    // Parse invitation token to get organization info
    const invitationData = React.useMemo(() => {
        try {
            const decoded = atob(invitationToken);
            return JSON.parse(decoded);
        } catch {
            return null;
        }
    }, [invitationToken]);

    const orgName = organizationName || invitationData?.orgName || 'the organization';
    const inviterName = inviterInfo?.name || invitationData?.inviterName;

    const finalTitle = title || `Join ${orgName}`;
    const finalSubtitle = subtitle || (
        inviterName
            ? `${inviterName} has invited you to join ${orgName}`
            : `You've been invited to join ${orgName}`
    );

    return (
        <SignUp
            {...props}
            invitationToken={invitationToken}
            organizationId={invitationData?.orgId}
            title={finalTitle}
            subtitle={finalSubtitle}
            showBranding={true}
        />
    );
}

/**
 * Quick Sign Up (minimal fields)
 */
export function QuickSignUp(props: SignUpProps) {
    return (
        <SignUp
            {...props}
            formProps={{
                variant: 'compact',
                collectFields: ['firstName', 'lastName'],
                ...props.formProps,
            }}
        />
    );
}

/**
 * Comprehensive Sign Up (all fields)
 */
export function ComprehensiveSignUp(props: SignUpProps) {
    return (
        <SignUp
            {...props}
            formProps={{
                variant: 'default',
                collectFields: ['firstName', 'lastName', 'username', 'phoneNumber'],
                passwordRequirements: {
                    minLength: 12,
                    requireUppercase: true,
                    requireLowercase: true,
                    requireNumbers: true,
                    requireSymbols: true,
                },
                ...props.formProps,
            }}
        />
    );
}

/**
 * Social Sign Up (OAuth only)
 */
export function SocialSignUp(props: SignUpProps) {
    return (
        <SignUp
            {...props}
            methods={['oauth']}
            title="Create your account"
            subtitle="Sign up with your social account"
        />
    );
}

/**
 * Passwordless Sign Up (magic link + passkey)
 */
export function PasswordlessSignUp(props: SignUpProps) {
    return (
        <SignUp
            {...props}
            methods={['magic-link', 'passkey', 'oauth']}
            title="Create your account"
            subtitle="Sign up without a password"
        />
    );
}

// ============================================================================
// Sign Up with Progressive Enhancement
// ============================================================================

/**
 * Progressive Sign Up - starts simple, adds complexity as needed
 */
export function ProgressiveSignUp({
                                      onSuccess,
                                      ...props
                                  }: SignUpProps) {
    const [step, setStep] = React.useState<'basic' | 'detailed' | 'verification'>('basic');
    const [userData, setUserData] = React.useState<any>(null);

    const handleBasicSuccess = React.useCallback((result: any) => {
        if (result.status === 'complete') {
            onSuccess?.(result);
        } else if (result.status === 'needs_verification') {
            setUserData(result);
            setStep('verification');
        } else {
            setUserData(result);
            setStep('detailed');
        }
    }, [onSuccess]);

    const handleDetailedSuccess = React.useCallback((result: any) => {
        if (result.status === 'complete') {
            onSuccess?.(result);
        } else {
            setUserData(result);
            setStep('verification');
        }
    }, [onSuccess]);

    const handleVerificationSuccess = React.useCallback((result: any) => {
        onSuccess?.(result);
    }, [onSuccess]);

    // Render based on step
    switch (step) {
        case 'detailed':
            return (
                <SignUp
                    {...props}
                    title="Complete your profile"
                    subtitle="Tell us a bit more about yourself"
                    formProps={{
                        collectFields: ['firstName', 'lastName', 'username'],
                        autoFocus: true,
                        ...props.formProps,
                    }}
                    onSuccess={handleDetailedSuccess}
                />
            );

        case 'verification':
            return (
                <div className="text-center space-y-4">
                    <h2 className="text-xl font-semibold">Check your email</h2>
                    <p className="text-default-500">
                        We've sent a verification link to your email address
                    </p>
                    <button
                        onClick={() => setStep('basic')}
                        className="text-primary hover:underline"
                    >
                        Use a different email
                    </button>
                </div>
            );

        case 'basic':
        default:
            return (
                <SignUp
                    {...props}
                    formProps={{
                        variant: 'minimal',
                        collectFields: [],
                        ...props.formProps,
                    }}
                    onSuccess={handleBasicSuccess}
                />
            );
    }
}

// ============================================================================
// Export
// ============================================================================

export default SignUp;