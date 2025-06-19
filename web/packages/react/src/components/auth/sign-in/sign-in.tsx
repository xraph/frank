/**
 * @frank-auth/react - Main Sign In Component
 *
 * Universal sign-in component that can render as form, modal, or card
 * based on props. Focuses on organization-user relationships and provides
 * comprehensive authentication flows for multi-tenant applications.
 */

'use client';

import React from 'react';

import {SignInForm} from './sign-in-form';
import {SignInModal} from './sign-in-modal';
import {SignInCard} from './sign-in-card';

import type {BaseSignInProps, SignInCardProps, SignInFormProps, SignInModalProps} from './index';

// ============================================================================
// Sign In Component Types
// ============================================================================

export interface SignInProps extends BaseSignInProps {
    /**
     * Render mode
     */
    mode?: 'form' | 'modal' | 'card';

    /**
     * Modal-specific props (when mode is 'modal')
     */
    modalProps?: Partial<SignInModalProps>;

    /**
     * Card-specific props (when mode is 'card')
     */
    cardProps?: Partial<SignInCardProps>;

    /**
     * Form-specific props (when mode is 'form' or not specified)
     */
    formProps?: Partial<SignInFormProps>;

    /**
     * Auto-detect mode based on context
     */
    autoMode?: boolean;

    /**
     * Organization-specific sign-in flow
     */
    organizationFlow?: boolean;

    /**
     * Show organization selector
     */
    showOrganizationSelector?: boolean;

    /**
     * Pre-select organization from URL or context
     */
    autoSelectOrganization?: boolean;
}

// ============================================================================
// Main Sign In Component
// ============================================================================

/**
 * Universal Sign In component that can render in different modes
 *
 * @example Form mode (default)
 * ```tsx
 * <SignIn
 *   methods={['password', 'oauth']}
 *   organizationId="org_123"
 *   onSuccess={(result) => console.log('Signed in:', result)}
 * />
 * ```
 *
 * @example Modal mode
 * ```tsx
 * <SignIn
 *   mode="modal"
 *   isOpen={isModalOpen}
 *   onClose={() => setIsModalOpen(false)}
 *   organizationFlow
 *   onSuccess={(result) => console.log('Signed in:', result)}
 * />
 * ```
 *
 * @example Card mode with organization branding
 * ```tsx
 * <SignIn
 *   mode="card"
 *   centered
 *   organizationId="org_123"
 *   showBranding
 *   onSuccess={(result) => console.log('Signed in:', result)}
 * />
 * ```
 *
 * @example Auto-mode with organization flow
 * ```tsx
 * <SignIn
 *   autoMode
 *   organizationFlow
 *   autoSelectOrganization
 *   onSuccess={(result) => console.log('Signed in:', result)}
 * />
 * ```
 */
export function SignIn({
                           mode = 'form',
                           modalProps = {},
                           cardProps = {},
                           formProps = {},
                           autoMode = false,
                           organizationFlow = false,
                           showOrganizationSelector = false,
                           autoSelectOrganization = false,
                           ...baseProps
                       }: SignInProps) {
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

    // Auto-select organization from URL params or context
    const selectedOrganizationId = React.useMemo(() => {
        if (!autoSelectOrganization) return baseProps.organizationId;

        // Check URL parameters
        if (typeof window !== 'undefined') {
            const urlParams = new URLSearchParams(window.location.search);
            const orgFromUrl = urlParams.get('org') || urlParams.get('organization_id');
            if (orgFromUrl) return orgFromUrl;

            // Check subdomain for organization slug
            const subdomain = window.location.hostname.split('.')[0];
            if (subdomain && subdomain !== 'www' && subdomain !== 'app') {
                return subdomain; // Assume subdomain is organization slug
            }
        }

        return baseProps.organizationId;
    }, [autoSelectOrganization, baseProps.organizationId]);

    // Enhanced props with organization flow
    const enhancedBaseProps = {
        ...baseProps,
        organizationId: selectedOrganizationId,
        showOrganizationSelector: organizationFlow ? showOrganizationSelector : false,
    };

    // Enhanced form props for organization flow
    const enhancedFormProps = {
        ...formProps,
        showOrganizationSelector: organizationFlow ? showOrganizationSelector : formProps.showOrganizationSelector,
        variant: organizationFlow ? 'default' : formProps.variant,
    };

    // Render based on mode
    switch (finalMode) {
        case 'modal':
            return (
                <SignInModal
                    {...enhancedBaseProps}
                    {...modalProps}
                    showOrganizationSelector={organizationFlow ? showOrganizationSelector : modalProps.showOrganizationSelector}
                />
            );

        case 'card':
            return (
                <SignInCard
                    {...enhancedBaseProps}
                    {...cardProps}
                    showOrganizationBranding={organizationFlow}
                />
            );

        case 'form':
        default:
            return (
                <SignInForm
                    {...enhancedBaseProps}
                    {...enhancedFormProps}
                />
            );
    }
}

// ============================================================================
// Sign In Component Variants
// ============================================================================

/**
 * Sign In Form (explicit form mode)
 */
export function SignInFormComponent(props: SignInProps) {
    return <SignIn {...props} mode="form" />;
}

/**
 * Sign In Modal (explicit modal mode)
 */
export function SignInModalComponent(props: SignInProps) {
    return <SignIn {...props} mode="modal" />;
}

/**
 * Sign In Card (explicit card mode)
 */
export function SignInCardComponent(props: SignInProps) {
    return <SignIn {...props} mode="card" />;
}

// ============================================================================
// Organization-Focused Sign In Components
// ============================================================================

/**
 * Organization Sign In - Focused on organization-user relationships
 */
export interface OrganizationSignInProps extends Omit<SignInProps, 'organizationFlow' | 'organizationId'> {
    /**
     * Organization ID (required)
     */
    organizationId: string;

    /**
     * Organization name for display
     */
    organizationName?: string;

    /**
     * Organization logo URL
     */
    organizationLogo?: string;

    /**
     * Allow users to switch organizations
     */
    allowOrganizationSwitching?: boolean;

    /**
     * Show organization member count or info
     */
    showOrganizationInfo?: boolean;

    /**
     * Custom organization welcome message
     */
    organizationWelcomeMessage?: string;

    /**
     * Organization-specific auth methods
     */
    organizationAuthMethods?: ('password' | 'oauth' | 'magic-link' | 'passkey' | 'sso')[];
}

export function OrganizationSignIn({
                                       organizationId,
                                       organizationName,
                                       organizationLogo,
                                       allowOrganizationSwitching = false,
                                       showOrganizationInfo = true,
                                       organizationWelcomeMessage,
                                       organizationAuthMethods,
                                       title,
                                       subtitle,
                                       methods,
                                       ...props
                                   }: OrganizationSignInProps) {
    const finalTitle = title || (organizationName ? `Welcome to ${organizationName}` : 'Welcome back');
    const finalSubtitle = subtitle || organizationWelcomeMessage || 'Sign in to your account';
    const finalMethods = organizationAuthMethods || methods || ['password', 'oauth', 'sso'];

    return (
        <SignIn
            {...props}
            organizationId={organizationId}
            organizationFlow
            title={finalTitle}
            subtitle={finalSubtitle}
            methods={finalMethods}
            showOrganizationSelector={allowOrganizationSwitching}
            showBranding={showOrganizationInfo}
        />
    );
}

/**
 * Multi-Organization Sign In - Allows users to select from their organizations
 */
export interface MultiOrganizationSignInProps extends Omit<SignInProps, 'organizationId'> {
    /**
     * Available organizations for the user
     */
    organizations?: Array<{
        id: string;
        name: string;
        slug?: string;
        logoUrl?: string;
    }>;

    /**
     * Default organization to pre-select
     */
    defaultOrganizationId?: string;

    /**
     * Show organization logos in selector
     */
    showOrganizationLogos?: boolean;

    /**
     * Allow creating new organization
     */
    allowCreateOrganization?: boolean;

    /**
     * Callback when organization is selected
     */
    onOrganizationSelected?: (organizationId: string) => void;
}

export function MultiOrganizationSignIn({
                                            organizations = [],
                                            defaultOrganizationId,
                                            showOrganizationLogos = true,
                                            allowCreateOrganization = false,
                                            onOrganizationSelected,
                                            ...props
                                        }: MultiOrganizationSignInProps) {
    const [selectedOrgId, setSelectedOrgId] = React.useState(defaultOrganizationId);

    const handleOrganizationChange = React.useCallback((orgId: string) => {
        setSelectedOrgId(orgId);
        onOrganizationSelected?.(orgId);
    }, [onOrganizationSelected]);

    return (
        <SignIn
            {...props}
            organizationId={selectedOrgId}
            organizationFlow
            showOrganizationSelector
            autoSelectOrganization={false}
        />
    );
}

/**
 * SSO Sign In - Focused on Single Sign-On flows
 */
export function SSOSignIn({
                              organizationId,
                              ...props
                          }: Omit<OrganizationSignInProps, 'organizationAuthMethods'>) {
    return (
        <OrganizationSignIn
            {...props}
            organizationId={organizationId}
            organizationAuthMethods={['sso', 'password']}
            title="Single Sign-On"
            subtitle="Sign in with your organization's SSO provider"
        />
    );
}

/**
 * Passwordless Sign In - No password required
 */
export function PasswordlessSignIn(props: SignInProps) {
    return (
        <SignIn
            {...props}
            methods={['magic-link', 'passkey', 'oauth', 'sso']}
            title="Sign in securely"
            subtitle="No password required"
        />
    );
}

/**
 * Secure Sign In - Enhanced security features
 */
export function SecureSignIn(props: SignInProps) {
    return (
        <SignIn
            {...props}
            methods={['passkey', 'password', 'sso']}
            title="Secure Sign In"
            subtitle="Sign in with enhanced security"
        />
    );
}

// ============================================================================
// Context-Aware Sign In Components
// ============================================================================

/**
 * Subdomain Sign In - Automatically detects organization from subdomain
 */
export function SubdomainSignIn(props: Omit<SignInProps, 'organizationId' | 'autoSelectOrganization'>) {
    return (
        <SignIn
            {...props}
            organizationFlow
            autoSelectOrganization
            showBranding
        />
    );
}

/**
 * URL-Based Sign In - Detects organization from URL parameters
 */
export function URLBasedSignIn(props: Omit<SignInProps, 'organizationId' | 'autoSelectOrganization'>) {
    return (
        <SignIn
            {...props}
            organizationFlow
            autoSelectOrganization
            showOrganizationSelector
        />
    );
}

/**
 * Invitation-Based Sign In - For organization invitations
 */
export interface InvitationSignInProps extends Omit<SignInProps, 'organizationId'> {
    /**
     * Invitation token
     */
    invitationToken: string;

    /**
     * Organization name from invitation
     */
    organizationName?: string;

    /**
     * Inviter information
     */
    inviterInfo?: {
        name?: string;
        email?: string;
    };

    /**
     * Auto-create account if not exists
     */
    autoCreateAccount?: boolean;
}

export function InvitationSignIn({
                                     invitationToken,
                                     organizationName,
                                     inviterInfo,
                                     autoCreateAccount = true,
                                     title,
                                     subtitle,
                                     onSuccess,
                                     ...props
                                 }: InvitationSignInProps) {
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
            ? `${inviterName} invited you to sign in to ${orgName}`
            : `You've been invited to sign in to ${orgName}`
    );

    // Enhanced success handler for invitations
    const handleSuccess = React.useCallback((result: any) => {
        // Handle invitation acceptance logic here
        onSuccess?.(result);
    }, [onSuccess]);

    return (
        <SignIn
            {...props}
            organizationId={invitationData?.orgId}
            organizationFlow
            title={finalTitle}
            subtitle={finalSubtitle}
            showBranding
            onSuccess={handleSuccess}
            formProps={{
                ...props.formProps,
                footer: (
                    <div className="text-center text-sm text-default-500">
                        {autoCreateAccount && (
                            <p>Don't have an account? One will be created for you.</p>
                        )}
                    </div>
                ),
            }}
        />
    );
}

// ============================================================================
// Progressive Sign In Flow
// ============================================================================

/**
 * Progressive Sign In - Adapts based on user context and organization
 */
export function ProgressiveSignIn({
                                      onSuccess,
                                      ...props
                                  }: SignInProps) {
    const [step, setStep] = React.useState<'organization' | 'credentials' | 'mfa' | 'complete'>('organization');
    const [selectedOrg, setSelectedOrg] = React.useState<string | undefined>(props.organizationId);
    const [authData, setAuthData] = React.useState<any>(null);

    // Handle organization selection
    const handleOrganizationSelected = React.useCallback((orgId: string) => {
        setSelectedOrg(orgId);
        setStep('credentials');
    }, []);

    // Handle credential success
    const handleCredentialSuccess = React.useCallback((result: any) => {
        if (result.status === 'complete') {
            setStep('complete');
            onSuccess?.(result);
        } else if (result.status === 'needs_mfa') {
            setAuthData(result);
            setStep('mfa');
        } else {
            onSuccess?.(result);
        }
    }, [onSuccess]);

    // Handle MFA success
    const handleMFASuccess = React.useCallback((result: any) => {
        setStep('complete');
        onSuccess?.(result);
    }, [onSuccess]);

    // Render based on step
    switch (step) {
        case 'organization':
            if (selectedOrg) {
                setStep('credentials');
                return null;
            }
            return (
                <MultiOrganizationSignIn
                    {...props}
                    onOrganizationSelected={handleOrganizationSelected}
                />
            );

        case 'mfa':
            return (
                <div className="space-y-4">
                    <div className="text-center">
                        <h2 className="text-xl font-semibold">Two-Factor Authentication</h2>
                        <p className="text-default-500">Complete your sign-in with MFA</p>
                    </div>
                    {/* MFA component would go here */}
                </div>
            );

        case 'complete':
            return (
                <div className="text-center space-y-4">
                    <div className="text-success-600 text-xl">✓</div>
                    <h2 className="text-xl font-semibold">Welcome back!</h2>
                    <p className="text-default-500">You have been successfully signed in.</p>
                </div>
            );

        case 'credentials':
        default:
            return (
                <OrganizationSignIn
                    {...props}
                    organizationId={selectedOrg!}
                    onSuccess={handleCredentialSuccess}
                />
            );
    }
}

// ============================================================================
// Export
// ============================================================================

export default SignIn;