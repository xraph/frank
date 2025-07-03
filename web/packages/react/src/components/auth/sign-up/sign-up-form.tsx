/**
 * @frank-auth/react - Sign Up Form Component
 *
 * Comprehensive sign-up form with multiple registration methods,
 * organization support, and customizable validation.
 */

'use client';

import type React from 'react';
import {useCallback, useMemo, useState} from 'react';
import {Button as HeroButton, Checkbox, Divider, Input as HeroInput, Link} from '@heroui/react';
import {motion} from 'framer-motion';
import {
    CheckIcon,
    EnvelopeIcon,
    EyeIcon,
    EyeSlashIcon,
    LockClosedIcon,
    PhoneIcon,
    UserIcon
} from '@heroicons/react/24/outline';

import {useAuth} from '../../../hooks/use-auth';
import {useConfig} from '../../../hooks/use-config';
import {useOAuth} from '../../../hooks/use-oauth';
import {usePasskeys} from '../../../hooks/use-passkeys';

import {DEFAULT_PASSWORD_REQUIREMENTS, formatInvitationData, type SignUpFormProps, signUpValidation} from './index';
import FormWrapper from "@/components/forms/form-wrapper";
import EmailField from "@/components/forms/email-field";
import PasswordField from "@/components/forms/password-field";
import type {RadiusT, SizeT} from "@/types";

// ============================================================================
// Sign Up Form State
// ============================================================================

type SignUpStep = 'form' | 'verification' | 'success';

interface SignUpState {
    step: SignUpStep;
    method: string;

    // Basic fields
    email: string;
    password: string;
    confirmPassword: string;

    // Optional fields
    firstName: string;
    lastName: string;
    username: string;
    phoneNumber: string;

    // UI state
    showPassword: boolean;
    showConfirmPassword: boolean;
    acceptTerms: boolean;
    acceptMarketing: boolean;

    // Validation
    fieldErrors: Record<string, string>;
    passwordSuggestions: string[];
}

// ============================================================================
// OAuth Provider Buttons Component
// ============================================================================

function OAuthButtons({
                          onSuccess,
                          onError,
                          redirectUrl,
                          organizationId,
                          disabled,
                          size = 'md',
    radius = 'md',
                      }: {
    onSuccess: (provider: string, result: any) => void;
    onError?: (error: Error) => void;
    redirectUrl?: string;
    organizationId?: string;
    disabled?: boolean;
    size?: SizeT;
    radius?: RadiusT;
}) {
    const {
        signInWithGoogle,
        signInWithGitHub,
        signInWithMicrosoft,
        signInWithApple,
        isLoading
    } = useOAuth();
    const { components } = useConfig();

    const Button = components.Button ?? HeroButton;

    const handleOAuthSignUp = useCallback(async (provider: string, signInMethod: () => Promise<void>) => {
        try {
            await signInMethod();
            onSuccess(provider, { provider });
        } catch (error) {
            onError?.(error instanceof Error ? error : new Error(`${provider} sign-up failed`));
        }
    }, [onSuccess, onError]);

    return (
        <div className="space-y-3">
            <Button
                variant="bordered"
                size={size}
                radius={radius}
                className="w-full"
                startContent={<GoogleIcon />}
                onPress={() => handleOAuthSignUp('google', () => signInWithGoogle({ redirectUrl, organizationId }))}
                isDisabled={disabled || isLoading}
            >
                Continue with Google
            </Button>

            <Button
                variant="bordered"
                size={size}
                radius={radius}
                className="w-full"
                startContent={<GitHubIcon />}
                onPress={() => handleOAuthSignUp('github', () => signInWithGitHub({ redirectUrl, organizationId }))}
                isDisabled={disabled || isLoading}
            >
                Continue with GitHub
            </Button>

            <Button
                variant="bordered"
                size={size}
                radius={radius}
                className="w-full"
                startContent={<MicrosoftIcon />}
                onPress={() => handleOAuthSignUp('microsoft', () => signInWithMicrosoft({ redirectUrl, organizationId }))}
                isDisabled={disabled || isLoading}
            >
                Continue with Microsoft
            </Button>

            <Button
                variant="bordered"
                size={size}
                radius={radius}
                className="w-full"
                startContent={<AppleIcon />}
                onPress={() => handleOAuthSignUp('apple', () => signInWithApple({ redirectUrl, organizationId }))}
                isDisabled={disabled || isLoading}
            >
                Continue with Apple
            </Button>
        </div>
    );
}


// ============================================================================
// Main Sign Up Form Component
// ============================================================================

export function SignUpForm({
                               methods = ['password', 'sso', 'magic-link'],
                               email: initialEmail = '',
                               organizationId: initialOrganizationId,
                               invitationToken,
                               redirectUrl,
                               onSuccess,
                               onError,
                               showSignInLink = true,
                               title,
                               subtitle,
                               variant = 'default',
                               size = 'md',
                               radius = 'md',
                               className = '',
                               showBranding = true,
                               disabled = false,
                               footer,
                               header,
                               requireTerms = true,
                               termsUrl = '/terms',
                               privacyUrl = '/privacy',
                               passwordRequirements = DEFAULT_PASSWORD_REQUIREMENTS,
                               autoFocus = true,
                               collectFields = ['firstName', 'lastName'],
                           }: SignUpFormProps) {
    const { signUp, isLoading } = useAuth();
    const { features, organizationSettings, components, linksPath } = useConfig();
    const { registerPasskey } = usePasskeys();

    // Custom component override
    const Input = components.Input ?? HeroInput;
    const Button = components.Button ?? HeroButton;
    const CustomSignUpForm = components.SignUpForm;
    if (CustomSignUpForm) {
        return <CustomSignUpForm {...{
            methods, email: initialEmail, organizationId: initialOrganizationId,
            invitationToken, redirectUrl, onSuccess, onError, showSignInLink,
            title, subtitle, variant, size, className, showBranding, disabled,
            footer, header, requireTerms, termsUrl, privacyUrl, passwordRequirements,
            autoFocus, collectFields
        }} />;
    }

    // Parse invitation data
    const invitationData = useMemo(() => {
        return formatInvitationData(invitationToken);
    }, [invitationToken]);

    // Form state
    const [state, setState] = useState<SignUpState>({
        step: 'form',
        method: 'password',
        email: initialEmail,
        password: '',
        confirmPassword: '',
        firstName: '',
        lastName: '',
        username: '',
        phoneNumber: '',
        showPassword: false,
        showConfirmPassword: false,
        acceptTerms: false,
        acceptMarketing: false,
        fieldErrors: {},
        passwordSuggestions: [],
    });

    const [formError, setFormError] = useState<string | null>(null);

    // Available methods based on features
    const availableMethods = useMemo(() => {
        return methods.filter(method => {
            switch (method) {
                case 'oauth':
                    return features.oauth;
                case 'magic-link':
                    return features.magicLink;
                case 'passkey':
                    return features.passkeys;
                case 'password':
                default:
                    return true;
            }
        });
    }, [methods, features]);

    // Field validation
    const validateField = useCallback((field: string, value: string) => {
        const newErrors = { ...state.fieldErrors };

        switch (field) {
            case 'email':
                if (!signUpValidation.email(value)) {
                    newErrors.email = 'Please enter a valid email address';
                } else {
                    delete newErrors.email;
                }
                break;

            case 'password':
                if (!signUpValidation.password(value, passwordRequirements)) {
                    newErrors.password = 'Password does not meet requirements';
                } else {
                    delete newErrors.password;
                }

                // Check confirm password match
                if (state.confirmPassword && value !== state.confirmPassword) {
                    newErrors.confirmPassword = 'Passwords do not match';
                } else if (state.confirmPassword) {
                    delete newErrors.confirmPassword;
                }
                break;

            case 'confirmPassword':
                if (value !== state.password) {
                    newErrors.confirmPassword = 'Passwords do not match';
                } else {
                    delete newErrors.confirmPassword;
                }
                break;

            case 'firstName':
                if (collectFields.includes('firstName') && !signUpValidation.firstName(value)) {
                    newErrors.firstName = 'Please enter a valid first name';
                } else {
                    delete newErrors.firstName;
                }
                break;

            case 'lastName':
                if (collectFields.includes('lastName') && !signUpValidation.lastName(value)) {
                    newErrors.lastName = 'Please enter a valid last name';
                } else {
                    delete newErrors.lastName;
                }
                break;

            case 'username':
                if (collectFields.includes('username') && value && !signUpValidation.username(value)) {
                    newErrors.username = 'Username must be at least 3 characters and contain only letters, numbers, - and _';
                } else {
                    delete newErrors.username;
                }
                break;

            case 'phoneNumber':
                if (collectFields.includes('phoneNumber') && value && !signUpValidation.phoneNumber(value)) {
                    newErrors.phoneNumber = 'Please enter a valid phone number';
                } else {
                    delete newErrors.phoneNumber;
                }
                break;
        }

        setState(prev => ({ ...prev, fieldErrors: newErrors }));
    }, [state.fieldErrors, state.password, state.confirmPassword, passwordRequirements, collectFields]);

    // Handle field changes
    const handleFieldChange = useCallback((field: string, value: string) => {
        setState(prev => ({ ...prev, [field]: value }));
        validateField(field, value);
    }, [validateField]);

    // Default content
    const getDefaultContent = () => {
        if (invitationData) {
            return {
                title: `Join ${invitationData.organizationName}`,
                subtitle: invitationData.inviterName
                    ? `${invitationData.inviterName} has invited you to join`
                    : 'You\'ve been invited to join',
            };
        }

        if (organizationSettings?.branding?.customSignUpText) {
            return {
                title: organizationSettings.branding.customSignUpText.title || 'Create your account',
                subtitle: organizationSettings.branding.customSignUpText.subtitle || 'Join us today',
            };
        }

        return {
            title: 'Create your account',
            subtitle: 'Join us today',
        };
    };

    const defaultContent = getDefaultContent();
    const finalTitle = title || defaultContent.title;
    const finalSubtitle = subtitle || defaultContent.subtitle;

    // Handle form submission
    const handleSubmit = useCallback(async (e: React.FormEvent) => {
        e.preventDefault();
        setFormError(null);

        // Validate required fields
        const requiredFields = ['email', 'password'];
        if (collectFields.includes('firstName')) requiredFields.push('firstName');
        if (collectFields.includes('lastName')) requiredFields.push('lastName');

        for (const field of requiredFields) {
            const value = state[field as keyof SignUpState] as string;
            if (!value) {
                setFormError(`Please fill in all required fields`);
                return;
            }
        }

        // Check for validation errors
        if (Object.keys(state.fieldErrors).length > 0) {
            setFormError('Please fix the errors above');
            return;
        }

        // Check password confirmation
        if (state.password !== state.confirmPassword) {
            setFormError('Passwords do not match');
            return;
        }

        // Check terms acceptance
        if (requireTerms && !state.acceptTerms) {
            setFormError('Please accept the terms of service');
            return;
        }

        try {
            const result = await signUp({
                emailAddress: state.email,
                password: state.password,
                firstName: state.firstName || undefined,
                lastName: state.lastName || undefined,
                username: state.username || undefined,
                organizationId: invitationData?.organizationId || initialOrganizationId,
                invitationToken,
                acceptTerms: state.acceptTerms,
                marketingConsent: state.acceptMarketing,
                unsafeMetadata: {
                    phoneNumber: state.phoneNumber || undefined,
                    acceptMarketing: state.acceptMarketing,
                },
            });

            if (result.status === 'needs_verification') {
                setState(prev => ({ ...prev, step: 'verification' }));
                return;
            }

            if (result.status === 'complete' && result.user) {
                setState(prev => ({ ...prev, step: 'success' }));
                onSuccess?.(result);

                // Redirect if URL provided
                if (redirectUrl) {
                    setTimeout(() => {
                        window.location.href = redirectUrl;
                    }, 1000);
                }
            }

            if (result.status === 'missing_requirements' && result.error) {
                setFormError(result.error?.message);
            }
        } catch (error) {
            const authError = error instanceof Error ? error : new Error('Sign up failed');
            setFormError(authError.message);
            onError?.(authError);
        }
    }, [
        state, collectFields, requireTerms, signUp, invitationData?.organizationId,
        initialOrganizationId, invitationToken, onSuccess, onError, redirectUrl
    ]);

    // Handle OAuth success
    const handleOAuthSuccess = useCallback((provider: string, result: any) => {
        setState(prev => ({ ...prev, step: 'success' }));
        onSuccess?.(result);
    }, [onSuccess]);

    // Handle Magic Link success
    const handleMagicLinkSuccess = useCallback((result: any) => {
        setState(prev => ({ ...prev, step: 'verification' }));
        onSuccess?.(result);
    }, [onSuccess]);

    // Handle Passkey registration
    const handlePasskeySignUp = useCallback(async () => {
        try {
            const result = await registerPasskey('Sign-up passkey');
            setState(prev => ({ ...prev, step: 'success' }));
            onSuccess?.(result);
        } catch (error) {
            const authError = error instanceof Error ? error : new Error('Passkey registration failed');
            setFormError(authError.message);
            onError?.(authError);
        }
    }, [registerPasskey, onSuccess, onError]);

    // Success step
    if (state.step === 'success') {
        return (
            <div className="text-center space-y-4">
                <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className="mx-auto w-16 h-16 bg-success-100 dark:bg-success-900/30 rounded-full flex items-center justify-center"
                >
                    <CheckIcon className="w-8 h-8 text-success-600 dark:text-success-400" />
                </motion.div>

                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Welcome aboard!
                    </h3>
                    <p className="text-default-500 text-sm">
                        Your account has been created successfully.
                    </p>
                </div>

                {redirectUrl && (
                    <div className="flex items-center justify-center gap-2 text-sm text-default-500">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                        <span>Setting up your account...</span>
                    </div>
                )}
            </div>
        );
    }

    // Verification step
    if (state.step === 'verification') {
        return (
            <div className="text-center space-y-4">
                <div className="mx-auto w-16 h-16 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center">
                    <EnvelopeIcon className="w-8 h-8 text-primary-600 dark:text-primary-400" />
                </div>

                <div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                        Check your email
                    </h3>
                    <p className="text-default-500 text-sm">
                        We've sent a verification link to {state.email}
                    </p>
                </div>

                <Button
                    variant="light"
                    size="sm"
                    onPress={() => setState(prev => ({ ...prev, step: 'form' }))}
                >
                    Use a different email
                </Button>
            </div>
        );
    }

    // Main form
    return (
        <FormWrapper
            size={size}
            radius={radius}
            variant={'flat'}
            disableAnimations
            className={`space-y-6 ${className}`}
            footer={footer}
            header={header}
            title={finalTitle}
            onSubmit={handleSubmit}
            subtitle={finalSubtitle}
            desc={invitationData && (
                <div className="bg-primary-50 dark:bg-primary-900/20 rounded-lg p-3 text-sm">
                    <p className="text-primary-600 dark:text-primary-400">
                        You're joining as: <strong>{invitationData.role}</strong>
                    </p>
                </div>
            )}
            showCard={false}
            logo={showBranding && organizationSettings?.branding?.logoUrl ? (
                <img
                    src={organizationSettings.branding.logoUrl}
                    alt="Organization Logo"
                    className="h-8 w-auto mx-auto mb-4"
                />
            ) : undefined}

        >

            {/* OAuth Buttons */}
            {availableMethods.includes('oauth') && (
                <>
                    <OAuthButtons
                        onSuccess={handleOAuthSuccess}
                        onError={onError}
                        redirectUrl={redirectUrl}
                        organizationId={invitationData?.organizationId || initialOrganizationId}
                        disabled={disabled}
                        size={size}
                        radius={radius}
                    />

                    {(availableMethods.includes('password') || availableMethods.includes('magic-link')) && (
                        <div className="relative">
                            <Divider className="my-4" />
                            <div className="absolute inset-0 flex items-center justify-center">
                                <span className="bg-background px-2 text-sm text-default-500">or</span>
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* Passkey Registration */}
            {availableMethods.includes('passkey') && (
                <>
                    <Button
                        variant="bordered"
                        size={size}
                        radius={radius}
                        className="w-full"
                        startContent={<LockClosedIcon className="w-4 h-4" />}
                        onPress={handlePasskeySignUp}
                        isDisabled={disabled || isLoading}
                    >
                        Sign up with passkey
                    </Button>

                    {(availableMethods.includes('password') || availableMethods.includes('magic-link')) && (
                        <div className="relative">
                            <Divider className="my-4" />
                            <div className="absolute inset-0 flex items-center justify-center">
                                <span className="bg-background px-2 text-sm text-default-500">or</span>
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* Password Form */}
            {availableMethods.includes('password') && (
                <div className="space-y-4">
                    {/* Name Fields */}
                    {(collectFields.includes('firstName') || collectFields.includes('lastName')) && (
                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                            {collectFields.includes('firstName') && (
                                <Input
                                    type="text"
                                    label="First Name"
                                    placeholder="Enter your first name"
                                    value={state.firstName}
                                    onChange={(e) => handleFieldChange('firstName', e.target.value)}
                                    startContent={<UserIcon className="w-4 h-4 text-default-400" />}
                                    size={size}
                                    radius={radius}
                                    required
                                    disabled={disabled || isLoading}
                                    isRequired
                                    isDisabled={disabled || isLoading}
                                    isInvalid={!!state.fieldErrors.firstName}
                                    errorMessage={state.fieldErrors.firstName}
                                    autoFocus={autoFocus}
                                    variant="bordered"
                                />
                            )}

                            {collectFields.includes('lastName') && (
                                <Input
                                    type="text"
                                    label="Last Name"
                                    placeholder="Enter your last name"
                                    value={state.lastName}
                                    onChange={(e) => handleFieldChange('lastName', e.target.value)}
                                    startContent={<UserIcon className="w-4 h-4 text-default-400" />}
                                    size={size}
                                    radius={radius}
                                    required
                                    disabled={disabled || isLoading}
                                    isRequired
                                    isDisabled={disabled || isLoading}
                                    isInvalid={!!state.fieldErrors.lastName}
                                    errorMessage={state.fieldErrors.lastName}
                                    autoFocus={autoFocus && !collectFields.includes('firstName')}
                                    variant="bordered"
                                />
                            )}
                        </div>
                    )}

                    {/* Email Field */}
                    <EmailField
                        label="Email"
                        placeholder="Enter your email"
                        value={state.email}
                        onChange={(e) => handleFieldChange('email', e)}
                        startContent={<EnvelopeIcon className="w-4 h-4 text-default-400" />}
                        size={size}
                        radius={radius}
                        required
                        disabled={disabled || isLoading}
                        error={state.fieldErrors.email}
                        autoFocus={autoFocus && collectFields.length === 0}
                        variant="bordered"
                    />

                    {/* Username Field */}
                    {collectFields.includes('username') && (
                        <Input
                            type="text"
                            label="Username"
                            placeholder="Choose a username"
                            value={state.username}
                            onChange={(e) => handleFieldChange('username', e.target.value)}
                            startContent={<span className="text-default-400 text-sm">@</span>}
                            size={size}
                            radius={radius}
                            required
                            disabled={disabled || isLoading}
                            isDisabled={disabled || isLoading}
                            isInvalid={!!state.fieldErrors.username}
                            errorMessage={state.fieldErrors.username}
                            variant="bordered"
                        />
                    )}

                    {/* Phone Number Field */}
                    {collectFields.includes('phoneNumber') && (
                        <Input
                            type="tel"
                            label="Phone Number"
                            placeholder="Enter your phone number"
                            value={state.phoneNumber}
                            onChange={(e) => handleFieldChange('phoneNumber', e.target.value)}
                            startContent={<PhoneIcon className="w-4 h-4 text-default-400" />}
                            size={size}
                            radius={radius}
                            disabled={disabled || isLoading}
                            isDisabled={disabled || isLoading}
                            isInvalid={!!state.fieldErrors.phoneNumber}
                            errorMessage={state.fieldErrors.phoneNumber}
                            variant="bordered"
                        />
                    )}

                    {/* Password Field */}
                    <div className="space-y-2">
                        <PasswordField
                            label="Password"
                            placeholder="Create a password"
                            value={state.password}
                            onChange={(e) => handleFieldChange('password', e)}
                            endContent={
                                <button
                                    type="button"
                                    onClick={() => setState(prev => ({ ...prev, showPassword: !prev.showPassword }))}
                                    className="focus:outline-none"
                                >
                                    {state.showPassword ? (
                                        <EyeSlashIcon className="w-4 h-4 text-default-400" />
                                    ) : (
                                        <EyeIcon className="w-4 h-4 text-default-400" />
                                    )}
                                </button>
                            }
                            size={size}
                            radius={radius}
                            required
                            advanceRequirements={passwordRequirements}
                            disabled={disabled || isLoading}
                            isInvalid={!!state.fieldErrors.password}
                            errorMessage={state.fieldErrors.password}
                            variant="bordered"
                        />

                        {/* Password Suggestions */}
                        {state.passwordSuggestions.length > 0 && (
                            <div className="space-y-2">
                                <div className="text-xs text-default-500">
                                    Suggested passwords:
                                </div>
                                <div className="space-y-1">
                                    {state.passwordSuggestions.map((suggestion, index) => (
                                        <button
                                            key={index}
                                            type="button"
                                            onClick={() => {
                                                handleFieldChange('password', suggestion);
                                                handleFieldChange('confirmPassword', suggestion);
                                            }}
                                            className="text-xs font-mono text-primary-600 hover:text-primary-800 hover:underline block"
                                        >
                                            {suggestion}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Confirm Password Field */}
                    <Input
                        type={state.showConfirmPassword ? "text" : "password"}
                        label="Confirm Password"
                        placeholder="Confirm your password"
                        value={state.confirmPassword}
                        onChange={(e) => handleFieldChange('confirmPassword', e.target.value)}
                        startContent={<LockClosedIcon className="w-4 h-4 text-default-400" />}
                        endContent={
                            <button
                                type="button"
                                onClick={() => setState(prev => ({ ...prev, showConfirmPassword: !prev.showConfirmPassword }))}
                                className="focus:outline-none"
                            >
                                {state.showConfirmPassword ? (
                                    <EyeSlashIcon className="w-4 h-4 text-default-400" />
                                ) : (
                                    <EyeIcon className="w-4 h-4 text-default-400" />
                                )}
                            </button>
                        }
                        size={size}
                        isRequired
                        isDisabled={disabled || isLoading}
                        isInvalid={!!state.fieldErrors.confirmPassword}
                        errorMessage={state.fieldErrors.confirmPassword}
                        variant="bordered"
                    />

                    {/* Terms and Privacy */}
                    <div className="space-y-3">
                        {requireTerms && (
                            <Checkbox
                                isSelected={state.acceptTerms}
                                onValueChange={(checked) => setState(prev => ({ ...prev, acceptTerms: checked }))}
                                size="sm"
                                isDisabled={disabled || isLoading}
                                isRequired
                            >
                                <span className="text-sm">
                                    I agree to the{' '}
                                    <Link href={termsUrl} size="sm" color="primary" isExternal>
                                        Terms of Service
                                    </Link>
                                    {' '}and{' '}
                                    <Link href={privacyUrl} size="sm" color="primary" isExternal>
                                        Privacy Policy
                                    </Link>
                                </span>
                            </Checkbox>
                        )}

                        <Checkbox
                            isSelected={state.acceptMarketing}
                            onValueChange={(checked) => setState(prev => ({ ...prev, acceptMarketing: checked }))}
                            size="sm"
                            isDisabled={disabled || isLoading}
                        >
                            <span className="text-sm text-default-500">
                                I'd like to receive product updates and marketing emails
                            </span>
                        </Checkbox>
                    </div>

                    {/* Error Display */}
                    {formError && (
                        <div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
                            {formError}
                        </div>
                    )}

                    {/* Submit Button */}
                    <Button
                        type="submit"
                        color="primary"
                        size={size}
                        radius={radius}
                        className="w-full"
                        isLoading={isLoading}
                        isDisabled={disabled || !state.email || !state.password || !state.acceptTerms}
                    >
                        {isLoading ? 'Creating account...' : 'Create account'}
                    </Button>
                </div>
            )}

            {/* Magic Link Only */}
            {availableMethods.includes('magic-link') && !availableMethods.includes('password') && (
                <div className="space-y-4">
                    <Input
                        type="email"
                        label="Email"
                        placeholder="Enter your email"
                        value={state.email}
                        onChange={(e) => handleFieldChange('email', e.target.value)}
                        startContent={<EnvelopeIcon className="w-4 h-4 text-default-400" />}
                        size={size}
                        isRequired
                        isDisabled={disabled || isLoading}
                        autoFocus
                        variant="bordered"
                    />

                    <Button
                        variant="bordered"
                        size={size}
                        radius={radius}
                        className="w-full"
                        startContent={<EnvelopeIcon className="w-4 h-4" />}
                        isDisabled={disabled || isLoading || !state.email}
                        isLoading={isLoading}
                    >
                        Send magic link
                    </Button>
                </div>
            )}

            {/* Sign In Link */}
            {showSignInLink && features.signIn && (
                <div className="text-center text-sm">
                    <span className="text-default-500">Already have an account? </span>
                    <Link href={linksPath?.signIn} color="primary">
                        Sign in
                    </Link>
                </div>
            )}

            {/* Custom Footer */}
            {footer}
        </FormWrapper>
    );
}

// ============================================================================
// Provider Icons (same as sign-in)
// ============================================================================

function GoogleIcon() {
    return (
        <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
        </svg>
    );
}

function GitHubIcon() {
    return (
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
        </svg>
    );
}

function MicrosoftIcon() {
    return (
        <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#f25022" d="M1 1h10v10H1z"/>
            <path fill="#00a4ef" d="M13 1h10v10H13z"/>
            <path fill="#7fba00" d="M1 13h10v10H1z"/>
            <path fill="#ffb900" d="M13 13h10v10H13z"/>
        </svg>
    );
}

function AppleIcon() {
    return (
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
        </svg>
    );
}

export default SignUpForm;