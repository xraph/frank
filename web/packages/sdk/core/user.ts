import {
    AuthenticationApi,
    type ChangePasswordRequest,
    type InitOverrideFunction,
    type ListMFAMethodsRequest,
    type ListPasskeysRequest,
    MFAApi,
    type MFABackCodes,
    type MFASetupResponse,
    type MFASetupVerifyResponse,
    type PaginatedOutputMFAMethod,
    type PaginatedOutputPasskeySummary,
    type PasskeyRegistrationBeginRequest,
    type PasskeyRegistrationBeginResponse,
    type PasskeyRegistrationFinishRequest,
    type PasskeyRegistrationFinishResponse,
    PasskeysApi,
    type PasskeySummary,
    type ResendVerificationResponse,
    type SetupMFARequest,
    type UpdatePasskeyRequest,
    type User,
    type UserProfileUpdateRequest,
    UsersApi,
    type VerifyMFASetupRequest,
} from '@frank-auth/client';

import {type FrankAuthConfig, FrankAuthError, BaseFrankAPI} from './index';
import {handleError} from "./errors";

export class FrankUser extends BaseFrankAPI {
    private usersApi: UsersApi;
    private authApi: AuthenticationApi;
    private mfaApi: MFAApi;
    private passkeyApi: PasskeysApi;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        super(config, accessToken);

        this.usersApi = new UsersApi(super.config);
        this.authApi = new AuthenticationApi(super.config);
        this.mfaApi = new MFAApi(super.config);
        this.passkeyApi = new PasskeysApi(super.config);
    }

    // Profile management
    async getProfile(): Promise<User> {
        try {
            return await this.usersApi.getUserProfile(this.mergeHeaders());
        } catch (error) {
            throw await handleError(error)
        }
    }

    async updateProfile(request: UserProfileUpdateRequest): Promise<User> {
        try {
            return await this.usersApi.updateUserProfile(
                {userProfileUpdateRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async changePassword(request: ChangePasswordRequest): Promise<void> {
        try {
            await this.usersApi.changePassword(
                {changePasswordRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Email verification
    async resendEmailVerification(email?: string): Promise<ResendVerificationResponse> {
        try {
            return await this.authApi.resendVerification(
                {resendVerificationRequest: {email, type: 'email'}},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async resendPhoneVerification(phone?: string): Promise<ResendVerificationResponse> {
        try {
            return await this.authApi.resendVerification(
                {resendVerificationRequest: {phoneNumber: phone, type: 'sms'}},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    // MFA management
    async getMFAMethods(requestParameters: ListMFAMethodsRequest, initOverrides?: RequestInit | InitOverrideFunction): Promise<PaginatedOutputMFAMethod> {
        try {
            return await this.mfaApi.listMFAMethods(
                requestParameters,
                this.mergeHeaders(initOverrides)
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async setupMFA(request: SetupMFARequest): Promise<MFASetupResponse> {
        try {
            return await this.authApi.setupMFA(
                {setupMFARequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async verifyMFASetup(request: VerifyMFASetupRequest): Promise<MFASetupVerifyResponse> {
        try {
            return await this.authApi.verifyMFASetup(
                {verifyMFASetupRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async disableMFA(): Promise<void> {
        try {
            await this.authApi.disableMFA(this.mergeHeaders());
        } catch (error) {
            throw await handleError(error)
        }
    }

    async getBackupCodes(regenerate = false): Promise<MFABackCodes> {
        try {
            return await this.authApi.getMFABackupCodes(
                {generateBackupCodesRequest: {count: regenerate ? 1 : undefined}},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Passkey management
    async getPasskeys(requestParameters: ListPasskeysRequest, initOverrides?: RequestInit | InitOverrideFunction): Promise<PaginatedOutputPasskeySummary> {
        try {
            return await this.authApi.listPasskeys(
                requestParameters,
                this.mergeHeaders(initOverrides)
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async createPasskey(request: PasskeyRegistrationBeginRequest): Promise<{
        beginResponse: PasskeyRegistrationBeginResponse;
        finishRegistration: (finishRequest: PasskeyRegistrationFinishRequest) => Promise<PasskeyRegistrationFinishResponse>;
    }> {
        try {
            const beginResponse = await this.passkeyApi.beginPasskeyRegistration(
                {passkeyRegistrationBeginRequest: request},
                this.mergeHeaders()
            );

            return {
                beginResponse,
                finishRegistration: async (finishRequest: PasskeyRegistrationFinishRequest) => {
                    return await this.passkeyApi.finishPasskeyRegistration(
                        {passkeyRegistrationFinishRequest: finishRequest},
                        this.mergeHeaders()
                    );
                }
            };
        } catch (error) {
            throw await handleError(error)
        }
    }

    async deletePasskey(passkeyId: string): Promise<void> {
        try {
            await this.authApi.deletePasskey(
                {id: passkeyId},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error)
        }
    }

    async updatePasskey(passkeyId: string, request: UpdatePasskeyRequest): Promise<PasskeySummary> {
        try {
            // Note: This endpoint might not exist in the current API
            // For now, we'll throw an error or implement a workaround
            throw new FrankAuthError('Update passkey not implemented', 'NOT_IMPLEMENTED');
        } catch (error) {
            throw await handleError(error)
        }
    }

    // User statistics and insights
    async getUserStats(): Promise<{
        totalSessions: number;
        totalPasskeys: number;
        mfaEnabled: boolean;
        lastLoginAt?: Date;
        accountCreatedAt?: Date;
        emailVerified: boolean;
        phoneVerified: boolean;
    }> {
        try {
            const [profile, sessions, passkeys] = await Promise.all([
                this.getProfile(),
                // Note: We'd need to import FrankSession or use the sessions API directly
                Promise.resolve({data: []}), // Placeholder
                this.getPasskeys({
                    fields: null
                }),
            ]);

            return {
                totalSessions: sessions.data?.length || 0,
                totalPasskeys: passkeys.pagination?.totalPages || 0,
                mfaEnabled: profile.mfaEnabled || false,
                // lastLoginAt: profile.lastLoginAt ? new Date(profile.lastLoginAt) : undefined,
                accountCreatedAt: profile.createdAt ? new Date(profile.createdAt) : undefined,
                emailVerified: profile.emailVerified || false,
                phoneVerified: profile.phoneVerified || false,
            };
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Security utilities
    async getSecuritySummary(): Promise<{
        securityScore: number;
        recommendations: string[];
        risks: string[];
        mfaEnabled: boolean;
        passkeyCount: number;
        recentSuspiciousActivity: boolean;
    }> {
        try {
            const [profile, passkeys] = await Promise.all([
                this.getProfile(),
                this.getPasskeys({
                    fields: null,
                }),
            ]);

            const recommendations: string[] = [];
            const risks: string[] = [];
            let securityScore = 100;

            // Check MFA
            if (!profile.mfaEnabled) {
                recommendations.push('Enable multi-factor authentication for better security');
                risks.push('Account not protected by MFA');
                securityScore -= 30;
            }

            // Check passkeys
            const passkeyCount = passkeys.pagination?.totalCount || 0;
            if (passkeyCount === 0) {
                recommendations.push('Set up passkeys for passwordless authentication');
                securityScore -= 20;
            }

            // Check email verification
            if (!profile.emailVerified) {
                recommendations.push('Verify your email address');
                risks.push('Email address not verified');
                securityScore -= 15;
            }

            // Check password strength (if applicable)
            if (!profile.passwordless && !profile.mfaEnabled) {
                risks.push('Account relies only on password authentication');
                securityScore -= 20;
            }

            return {
                securityScore: Math.max(0, securityScore),
                recommendations,
                risks,
                mfaEnabled: profile.mfaEnabled || false,
                passkeyCount,
                recentSuspiciousActivity: false, // This would require session analysis
            };
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Profile validation
    validateProfile(profile: Partial<UserProfileUpdateRequest>): {
        isValid: boolean;
        errors: Record<string, string[]>;
    } {
        const errors: Record<string, string[]> = {};

        if (profile.email && !this.isValidEmail(profile.email)) {
            errors.email = ['Please provide a valid email address'];
        }

        if (profile.phone && !this.isValidPhone(profile.phone)) {
            errors.phone = ['Please provide a valid phone number'];
        }

        if (profile.firstName && profile.firstName.length < 1) {
            errors.firstName = ['First name is required'];
        }

        if (profile.lastName && profile.lastName.length < 1) {
            errors.lastName = ['Last name is required'];
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors,
        };
    }

    // Utility methods
    private isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    private isValidPhone(phone: string): boolean {
        const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
        return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
    }
}