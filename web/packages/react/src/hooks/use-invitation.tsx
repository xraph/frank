/**
 * @frank-auth/react - Verification & Invitation Hooks
 *
 * Custom React hooks for identity verification and organization invitations.
 * These hooks provide state management and API integration for the new components.
 */

import {useCallback, useEffect, useState} from 'react';
import {useAuth} from './use-auth';

// ============================================================================
// Identity Verification Hook
// ============================================================================

export interface UseIdentityVerificationOptions {
    email?: string;
    phoneNumber?: string;
    userId?: string;
    organizationId?: string;
    methods?: ('email' | 'phone')[];
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
}

export interface IdentityVerificationState {
    // Current verification method
    activeMethod: 'email' | 'phone' | null;

    // Verification status for each method
    emailStatus: 'idle' | 'sending' | 'sent' | 'verifying' | 'verified' | 'error' | 'expired';
    phoneStatus: 'idle' | 'sending' | 'sent' | 'verifying' | 'verified' | 'error' | 'expired';

    // Input codes
    emailCode: string;
    phoneCode: string;

    // Error states
    emailError: string | null;
    phoneError: string | null;

    // Resend attempts
    emailResendAttempts: number;
    phoneResendAttempts: number;

    // Timers
    emailTimeRemaining: number;
    phoneTimeRemaining: number;

    // Overall verification state
    isVerified: boolean;
    verifiedMethods: ('email' | 'phone')[];
}

export function useIdentityVerification(options: UseIdentityVerificationOptions) {
    const { client } = useAuth();
    const {
        email,
        phoneNumber,
        userId,
        organizationId,
        methods = ['email', 'phone'],
        autoSubmit = true,
        codeLength = 6,
        resendDelay = 30,
        maxResendAttempts = 3,
        expirationTime = 300
    } = options;

    const [state, setState] = useState<IdentityVerificationState>({
        activeMethod: null,
        emailStatus: 'idle',
        phoneStatus: 'idle',
        emailCode: '',
        phoneCode: '',
        emailError: null,
        phoneError: null,
        emailResendAttempts: 0,
        phoneResendAttempts: 0,
        emailTimeRemaining: 0,
        phoneTimeRemaining: 0,
        isVerified: false,
        verifiedMethods: []
    });

    // Timer effects
    useEffect(() => {
        if (state.emailTimeRemaining > 0) {
            const timer = setTimeout(() => {
                setState(prev => ({ ...prev, emailTimeRemaining: prev.emailTimeRemaining - 1 }));
            }, 1000);
            return () => clearTimeout(timer);
        }
    }, [state.emailTimeRemaining]);

    useEffect(() => {
        if (state.phoneTimeRemaining > 0) {
            const timer = setTimeout(() => {
                setState(prev => ({ ...prev, phoneTimeRemaining: prev.phoneTimeRemaining - 1 }));
            }, 1000);
            return () => clearTimeout(timer);
        }
    }, [state.phoneTimeRemaining]);

    // Auto-submit effects
    useEffect(() => {
        if (autoSubmit && state.emailCode.length === codeLength && state.emailStatus === 'sent') {
            verifyEmail();
        }
    }, [state.emailCode, codeLength, autoSubmit, state.emailStatus]);

    useEffect(() => {
        if (autoSubmit && state.phoneCode.length === codeLength && state.phoneStatus === 'sent') {
            verifyPhone();
        }
    }, [state.phoneCode, codeLength, autoSubmit, state.phoneStatus]);

    const sendEmailCode = useCallback(async () => {
        if (!email || !userId || !organizationId) {
            setState(prev => ({ ...prev, emailError: 'Missing required parameters for email verification' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, emailStatus: 'sending', emailError: null }));

            const response = await client.mfa.sendEmailCode({
                orgId: organizationId,
                userId: userId
            });

            if (response.success) {
                setState(prev => ({
                    ...prev,
                    emailStatus: 'sent',
                    emailTimeRemaining: resendDelay,
                    activeMethod: 'email'
                }));
            } else {
                throw new Error(response.message || 'Failed to send email verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send email verification code');
            setState(prev => ({
                ...prev,
                emailStatus: 'error',
                emailError: error.message
            }));
        }
    }, [email, userId, organizationId, client, resendDelay]);

    const sendPhoneCode = useCallback(async () => {
        if (!phoneNumber || !userId || !organizationId) {
            setState(prev => ({ ...prev, phoneError: 'Missing required parameters for phone verification' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, phoneStatus: 'sending', phoneError: null }));

            const response = await client.mfa.sendSMSCode({
                orgId: organizationId,
                userId: userId
            });

            if (response.success) {
                setState(prev => ({
                    ...prev,
                    phoneStatus: 'sent',
                    phoneTimeRemaining: resendDelay,
                    activeMethod: 'phone'
                }));
            } else {
                throw new Error(response.message || 'Failed to send SMS verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to send SMS verification code');
            setState(prev => ({
                ...prev,
                phoneStatus: 'error',
                phoneError: error.message
            }));
        }
    }, [phoneNumber, userId, organizationId, client, resendDelay]);

    const verifyEmail = useCallback(async () => {
        if (!state.emailCode || state.emailCode.length !== codeLength) {
            setState(prev => ({ ...prev, emailError: 'Please enter a valid verification code' }));
            return;
        }

        if (!userId || !organizationId) {
            setState(prev => ({ ...prev, emailError: 'Missing required parameters for verification' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, emailStatus: 'verifying', emailError: null }));

            const response = await client.mfa.verifyEmailCode({
                orgId: organizationId,
                userId: userId,
                verifyEmailRequestBody: {
                    code: state.emailCode
                }
            });

            if (response.verified) {
                setState(prev => ({
                    ...prev,
                    emailStatus: 'verified',
                    verifiedMethods: [...prev.verifiedMethods.filter(m => m !== 'email'), 'email'],
                    isVerified: prev.verifiedMethods.includes('phone') || methods.length === 1
                }));
            } else {
                throw new Error('Invalid verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Email verification failed');
            setState(prev => ({
                ...prev,
                emailStatus: 'error',
                emailError: error.message
            }));
        }
    }, [state.emailCode, codeLength, userId, organizationId, client, methods]);

    const verifyPhone = useCallback(async () => {
        if (!state.phoneCode || state.phoneCode.length !== codeLength) {
            setState(prev => ({ ...prev, phoneError: 'Please enter a valid verification code' }));
            return;
        }

        if (!phoneNumber) {
            setState(prev => ({ ...prev, phoneError: 'Phone number is required for verification' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, phoneStatus: 'verifying', phoneError: null }));

            const response = await client.authentication.verifyPhone({
                verificationRequest: {
                    phoneNumber: phoneNumber,
                    code: state.phoneCode
                }
            });

            if (response.verified) {
                setState(prev => ({
                    ...prev,
                    phoneStatus: 'verified',
                    verifiedMethods: [...prev.verifiedMethods.filter(m => m !== 'phone'), 'phone'],
                    isVerified: prev.verifiedMethods.includes('email') || methods.length === 1
                }));
            } else {
                throw new Error('Invalid verification code');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Phone verification failed');
            setState(prev => ({
                ...prev,
                phoneStatus: 'error',
                phoneError: error.message
            }));
        }
    }, [state.phoneCode, codeLength, phoneNumber, client, methods]);

    const resendEmailCode = useCallback(async () => {
        if (state.emailResendAttempts >= maxResendAttempts) {
            setState(prev => ({ ...prev, emailError: 'Maximum resend attempts reached' }));
            return;
        }

        setState(prev => ({ ...prev, emailResendAttempts: prev.emailResendAttempts + 1 }));
        await sendEmailCode();
    }, [state.emailResendAttempts, maxResendAttempts, sendEmailCode]);

    const resendPhoneCode = useCallback(async () => {
        if (state.phoneResendAttempts >= maxResendAttempts) {
            setState(prev => ({ ...prev, phoneError: 'Maximum resend attempts reached' }));
            return;
        }

        setState(prev => ({ ...prev, phoneResendAttempts: prev.phoneResendAttempts + 1 }));
        await sendPhoneCode();
    }, [state.phoneResendAttempts, maxResendAttempts, sendPhoneCode]);

    const setEmailCode = useCallback((code: string) => {
        setState(prev => ({ ...prev, emailCode: code }));
    }, []);

    const setPhoneCode = useCallback((code: string) => {
        setState(prev => ({ ...prev, phoneCode: code }));
    }, []);

    const reset = useCallback(() => {
        setState({
            activeMethod: null,
            emailStatus: 'idle',
            phoneStatus: 'idle',
            emailCode: '',
            phoneCode: '',
            emailError: null,
            phoneError: null,
            emailResendAttempts: 0,
            phoneResendAttempts: 0,
            emailTimeRemaining: 0,
            phoneTimeRemaining: 0,
            isVerified: false,
            verifiedMethods: []
        });
    }, []);

    return {
        ...state,
        sendEmailCode,
        sendPhoneCode,
        verifyEmail,
        verifyPhone,
        resendEmailCode,
        resendPhoneCode,
        setEmailCode,
        setPhoneCode,
        reset,
        canResendEmail: state.emailTimeRemaining === 0 && state.emailResendAttempts < maxResendAttempts,
        canResendPhone: state.phoneTimeRemaining === 0 && state.phoneResendAttempts < maxResendAttempts,
        availableMethods: methods,
        isLoading: state.emailStatus === 'sending' || state.emailStatus === 'verifying' ||
            state.phoneStatus === 'sending' || state.phoneStatus === 'verifying'
    };
}

// ============================================================================
// Invitation Management Hook
// ============================================================================

export interface UseInvitationOptions {
    token?: string;
    autoValidate?: boolean;
}

export interface InvitationState {
    invitation: any | null;
    status: 'idle' | 'validating' | 'valid' | 'accepting' | 'declining' | 'accepted' | 'declined' | 'expired' | 'invalid' | 'error';
    error: string | null;
    isLoading: boolean;
}

export function useInvitation(options: UseInvitationOptions = {}) {
    const { client, user } = useAuth();
    const { token, autoValidate = true } = options;

    const [state, setState] = useState<InvitationState>({
        invitation: null,
        status: 'idle',
        error: null,
        isLoading: false
    });

    const validateInvitation = useCallback(async (invitationToken: string) => {
        try {
            setState(prev => ({ ...prev, status: 'validating', isLoading: true, error: null }));

            const response = await client.invitations.validateInvitation({
                invitationValidationRequest: {
                    token: invitationToken
                }
            });

            if (response.valid && response.invitation) {
                // Check if invitation is expired
                const expiresAt = new Date(response.invitation.expiresAt);
                if (expiresAt < new Date()) {
                    setState(prev => ({
                        ...prev,
                        status: 'expired',
                        error: 'This invitation has expired',
                        isLoading: false
                    }));
                } else {
                    setState(prev => ({
                        ...prev,
                        invitation: response.invitation,
                        status: 'valid',
                        isLoading: false
                    }));
                }
            } else {
                setState(prev => ({
                    ...prev,
                    status: 'invalid',
                    error: response.message || 'Invalid invitation token',
                    isLoading: false
                }));
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to validate invitation');
            setState(prev => ({
                ...prev,
                status: 'error',
                error: error.message,
                isLoading: false
            }));
        }
    }, [client]);

    const acceptInvitation = useCallback(async (userData?: { firstName?: string; lastName?: string; password?: string }) => {
        if (!state.invitation) {
            setState(prev => ({ ...prev, error: 'No invitation data available' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, status: 'accepting', isLoading: true, error: null }));

            const acceptRequest: any = {
                token: state.invitation.token
            };

            // Add user data if provided (for sign-up flow)
            if (userData) {
                acceptRequest.userData = userData;
            }

            const response = await client.invitations.acceptInvitation({
                acceptInvitationRequest: acceptRequest
            });

            if (response.success) {
                setState(prev => ({
                    ...prev,
                    status: 'accepted',
                    isLoading: false
                }));

                // Handle redirect if specified
                if (state.invitation.redirectUrl) {
                    setTimeout(() => {
                        window.location.href = state.invitation.redirectUrl;
                    }, 2000);
                }

                return {
                    organizationId: state.invitation.organizationId,
                    userId: response.userId || user?.id || ''
                };
            } else {
                throw new Error(response.message || 'Failed to accept invitation');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to accept invitation');
            setState(prev => ({
                ...prev,
                status: 'error',
                error: error.message,
                isLoading: false
            }));
            throw error;
        }
    }, [state.invitation, client, user]);

    const declineInvitation = useCallback(async () => {
        if (!state.invitation) {
            setState(prev => ({ ...prev, error: 'No invitation data available' }));
            return;
        }

        try {
            setState(prev => ({ ...prev, status: 'declining', isLoading: true, error: null }));

            const response = await client.invitations.declineInvitation({
                declineInvitationRequest: {
                    token: state.invitation.token
                }
            });

            if (response.success) {
                setState(prev => ({
                    ...prev,
                    status: 'declined',
                    isLoading: false
                }));
            } else {
                throw new Error(response.message || 'Failed to decline invitation');
            }
        } catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to decline invitation');
            setState(prev => ({
                ...prev,
                status: 'error',
                error: error.message,
                isLoading: false
            }));
        }
    }, [state.invitation, client]);

    const reset = useCallback(() => {
        setState({
            invitation: null,
            status: 'idle',
            error: null,
            isLoading: false
        });
    }, []);

    // Auto-validate when token is provided
    useEffect(() => {
        if (token && autoValidate && state.status === 'idle') {
            validateInvitation(token);
        }
    }, [token, autoValidate, state.status, validateInvitation]);

    // Extract token from URL if not provided
    useEffect(() => {
        if (!token && autoValidate && typeof window !== 'undefined' && state.status === 'idle') {
            const urlParams = new URLSearchParams(window.location.search);
            const urlToken = urlParams.get('invitation_token') || urlParams.get('invite');

            if (urlToken) {
                validateInvitation(urlToken);
            }
        }
    }, [token, autoValidate, state.status, validateInvitation]);

    return {
        ...state,
        validateInvitation,
        acceptInvitation,
        declineInvitation,
        reset
    };
}

// ============================================================================
// Export Hook Index
// ============================================================================

export const VerificationHooks = {
    useIdentityVerification
};

export const InvitationHooks = {
    useInvitation
};