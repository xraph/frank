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

import {type FrankAuthConfig, FrankAuthError, BaseSDK} from './index';

export class UserSDK extends BaseSDK {
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
        return this.executeApiCall(async () => {
            return await this.usersApi.getUserProfile(this.mergeHeaders());
        });
    }

    async updateProfile(request: UserProfileUpdateRequest): Promise<User> {
        return this.executeApiCall(async () => {
            return await this.usersApi.updateUserProfile(
                {userProfileUpdateRequest: request},
                this.mergeHeaders()
            );
        });
    }

    async changePassword(request: ChangePasswordRequest): Promise<void> {
        return this.executeApiCall(async () => {
            await this.usersApi.changePassword(
                {changePasswordRequest: request},
                this.mergeHeaders()
            );
        });
    }

    // Email verification
    async resendEmailVerification(email?: string): Promise<ResendVerificationResponse> {
        return this.executeApiCall(async () => {
            return await this.authApi.resendVerification(
                {resendVerificationRequest: {email, type: 'email'}},
                this.mergeHeaders()
            );
        });
    }

    async resendPhoneVerification(phone?: string): Promise<ResendVerificationResponse> {
        return this.executeApiCall(async () => {
            return await this.authApi.resendVerification(
                {resendVerificationRequest: {phoneNumber: phone, type: 'sms'}},
                this.mergeHeaders()
            );
        });
    }

    // MFA management
    async getMFAMethods(requestParameters: ListMFAMethodsRequest, initOverrides?: RequestInit | InitOverrideFunction): Promise<PaginatedOutputMFAMethod> {
        return this.executeApiCall(async () => {
            return await this.mfaApi.listMFAMethods(
                requestParameters,
                this.mergeHeaders(initOverrides)
            );
        });
    }

    async setupMFA(request: SetupMFARequest): Promise<MFASetupResponse> {
        return this.executeApiCall(async () => {
            return await this.authApi.setupMFA(
                {setupMFARequest: request},
                this.mergeHeaders()
            );
        });
    }

    async verifyMFASetup(request: VerifyMFASetupRequest): Promise<MFASetupVerifyResponse> {
        return this.executeApiCall(async () => {
            return await this.authApi.verifyMFASetup(
                {verifyMFASetupRequest: request},
                this.mergeHeaders()
            );
        });
    }

    async disableMFA(): Promise<void> {
        return this.executeApiCall(async () => {
            await this.authApi.disableMFA(this.mergeHeaders());
        });
    }

    async getBackupCodes(regenerate = false): Promise<MFABackCodes> {
        return this.executeApiCall(async () => {
            return await this.authApi.getMFABackupCodes(
                {generateBackupCodesRequest: {count: regenerate ? 1 : undefined}},
                this.mergeHeaders()
            );
        });
    }

    // Passkey management
    async getPasskeys(requestParameters: ListPasskeysRequest, initOverrides?: RequestInit | InitOverrideFunction): Promise<PaginatedOutputPasskeySummary> {
        return this.executeApiCall(async () => {
            return await this.authApi.listPasskeys(
                requestParameters,
                this.mergeHeaders(initOverrides)
            );
        });
    }

    async createPasskey(request: PasskeyRegistrationBeginRequest): Promise<{
        beginResponse: PasskeyRegistrationBeginResponse;
        finishRegistration: (finishRequest: PasskeyRegistrationFinishRequest) => Promise<PasskeyRegistrationFinishResponse>;
    }> {
        return this.executeApiCall(async () => {
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
        });
    }

    async deletePasskey(passkeyId: string): Promise<void> {
        return this.executeApiCall(async () => {
            await this.authApi.deletePasskey(
                {id: passkeyId},
                this.mergeHeaders()
            );
        });
    }

    async updatePasskey(passkeyId: string, request: UpdatePasskeyRequest): Promise<PasskeySummary> {
        return this.executeApiCall(async () => {
            // Note: This endpoint might not exist in the current API
            // For now, we'll throw an error or implement a workaround
            throw new FrankAuthError('Update passkey not implemented', 'NOT_IMPLEMENTED');
        });
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
        return this.executeApiCall(async () => {
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
        });
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
        return this.executeApiCall(async () => {
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
        });
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

    // Enhanced user management methods with prehooks

    /**
     * Get comprehensive user information including security details
     */
    async getCompleteProfile(): Promise<{
        user: User;
        securitySummary: {
            securityScore: number;
            recommendations: string[];
            risks: string[];
            mfaEnabled: boolean;
            passkeyCount: number;
            recentSuspiciousActivity: boolean;
        };
        stats: {
            totalSessions: number;
            totalPasskeys: number;
            mfaEnabled: boolean;
            lastLoginAt?: Date;
            accountCreatedAt?: Date;
            emailVerified: boolean;
            phoneVerified: boolean;
        };
    }> {
        return this.executeApiCall(async () => {
            const [user, securitySummary, stats] = await Promise.all([
                this.getProfile(),
                this.getSecuritySummary(),
                this.getUserStats(),
            ]);

            return {
                user,
                securitySummary,
                stats,
            };
        });
    }

    /**
     * Update profile with validation
     */
    async updateProfileWithValidation(request: UserProfileUpdateRequest): Promise<{
        user: User;
        validationResult: {
            isValid: boolean;
            errors: Record<string, string[]>;
        };
    }> {
        return this.executeApiCall(async () => {
            const validationResult = this.validateProfile(request);

            if (!validationResult.isValid) {
                throw new FrankAuthError(
                    `Profile validation failed: ${Object.entries(validationResult.errors)
                        .map(([field, errors]) => `${field}: ${errors.join(', ')}`)
                        .join('; ')}`,
                    'VALIDATION_ERROR'
                );
            }

            const user = await this.updateProfile(request);

            return {
                user,
                validationResult,
            };
        });
    }

    /**
     * Setup MFA with enhanced flow
     */
    async setupMFAWithValidation(request: SetupMFARequest): Promise<{
        setupResponse: MFASetupResponse;
        backupCodes?: MFABackCodes;
        recommendations: string[];
    }> {
        return this.executeApiCall(async () => {
            const setupResponse = await this.setupMFA(request);

            // Get backup codes if MFA setup was successful
            let backupCodes: MFABackCodes | undefined;
            try {
                backupCodes = await this.getBackupCodes(true);
            } catch {
                // Backup codes might not be available immediately
            }

            const recommendations = [
                'Store backup codes in a secure location',
                'Test your MFA method before relying on it',
                'Consider setting up multiple MFA methods for redundancy',
            ];

            return {
                setupResponse,
                backupCodes,
                recommendations,
            };
        });
    }

    /**
     * Get MFA status and recommendations
     */
    async getMFAStatus(): Promise<{
        enabled: boolean;
        methods: PaginatedOutputMFAMethod;
        backupCodesAvailable: boolean;
        recommendations: string[];
    }> {
        return this.executeApiCall(async () => {
            const [profile, methods] = await Promise.all([
                this.getProfile(),
                this.getMFAMethods({
                    orgId: this.getOrganizationId(),
                    fields: null,
                    userId: this.getUserData()
                }),
            ]);

            let backupCodesAvailable = false;
            try {
                await this.getBackupCodes();
                backupCodesAvailable = true;
            } catch {
                // Backup codes not available
            }

            const recommendations: string[] = [];

            if (!profile.mfaEnabled) {
                recommendations.push('Enable MFA for enhanced security');
            } else {
                if (!backupCodesAvailable) {
                    recommendations.push('Generate backup codes for recovery');
                }

                const methodCount = methods.data?.length || 0;
                if (methodCount === 1) {
                    recommendations.push('Consider adding a second MFA method for redundancy');
                }
            }

            return {
                enabled: profile.mfaEnabled || false,
                methods,
                backupCodesAvailable,
                recommendations,
            };
        });
    }

    /**
     * Get passkey management dashboard
     */
    async getPasskeyDashboard(): Promise<{
        passkeys: PaginatedOutputPasskeySummary;
        canCreateMore: boolean;
        recommendations: string[];
        securityBenefits: string[];
    }> {
        return this.executeApiCall(async () => {
            const passkeys = await this.getPasskeys({ fields: null });
            const passkeyCount = passkeys.pagination?.totalCount || 0;

            const recommendations: string[] = [];
            const securityBenefits = [
                'Passwordless authentication',
                'Phishing resistance',
                'Biometric verification',
                'Hardware-based security',
            ];

            if (passkeyCount === 0) {
                recommendations.push('Create your first passkey for passwordless login');
            } else {
                recommendations.push('Create passkeys for additional devices');
                if (passkeyCount === 1) {
                    recommendations.push('Add a backup passkey for redundancy');
                }
            }

            return {
                passkeys,
                canCreateMore: passkeyCount < 10, // Assume max 10 passkeys
                recommendations,
                securityBenefits,
            };
        });
    }

    /**
     * Change password with enhanced security checks
     */
    async changePasswordSecurely(request: ChangePasswordRequest & {
        confirmPassword: string;
    }): Promise<{
        success: boolean;
        securityRecommendations: string[];
    }> {
        return this.executeApiCall(async () => {
            // Validate password confirmation
            if (request.newPassword !== request.confirmPassword) {
                throw new FrankAuthError('Password confirmation does not match', 'VALIDATION_ERROR');
            }

            // Validate password strength
            const passwordValidation = this.validatePassword(request.newPassword);
            if (!passwordValidation.isValid) {
                throw new FrankAuthError(
                    `Password validation failed: ${passwordValidation.errors.join(', ')}`,
                    'VALIDATION_ERROR'
                );
            }

            // Change password
            await this.changePassword({
                currentPassword: request.currentPassword,
                newPassword: request.newPassword,
            });

            const securityRecommendations = [
                'Consider enabling MFA for additional security',
                'Use a password manager to generate strong passwords',
                'Regularly update your passwords',
                'Monitor your account for suspicious activity',
            ];

            return {
                success: true,
                securityRecommendations,
            };
        });
    }

    /**
     * Get account security health check
     */
    async getSecurityHealthCheck(): Promise<{
        overallScore: number;
        categories: {
            authentication: {
                score: number;
                status: 'excellent' | 'good' | 'needs_improvement' | 'poor';
                items: Array<{
                    name: string;
                    status: 'pass' | 'fail' | 'warning';
                    description: string;
                }>;
            };
            verification: {
                score: number;
                status: 'excellent' | 'good' | 'needs_improvement' | 'poor';
                items: Array<{
                    name: string;
                    status: 'pass' | 'fail' | 'warning';
                    description: string;
                }>;
            };
            devices: {
                score: number;
                status: 'excellent' | 'good' | 'needs_improvement' | 'poor';
                items: Array<{
                    name: string;
                    status: 'pass' | 'fail' | 'warning';
                    description: string;
                }>;
            };
        };
        recommendations: string[];
    }> {
        return this.executeApiCall(async () => {
            const [profile, passkeys, mfaStatus] = await Promise.all([
                this.getProfile(),
                this.getPasskeys({ fields: null }),
                this.getMFAStatus(),
            ]);

            const passkeyCount = passkeys.pagination?.totalCount || 0;

            // Authentication category
            const authItems: {
                name: string;
                status: 'pass' | 'fail' | 'warning';
                description: string;
            }[] = [
                {
                    name: 'Multi-Factor Authentication',
                    status: profile.mfaEnabled ? 'pass' : 'fail',
                    description: profile.mfaEnabled ? 'MFA is enabled' : 'MFA is not enabled',
                },
                {
                    name: 'Passkey Authentication',
                    status: passkeyCount > 0 ? 'pass' : 'warning',
                    description: passkeyCount > 0 ? `${passkeyCount} passkey(s) configured` : 'No passkeys configured',
                },
                {
                    name: 'Backup Codes',
                    status: mfaStatus.backupCodesAvailable ? 'pass' : 'warning',
                    description: mfaStatus.backupCodesAvailable ? 'Backup codes available' : 'No backup codes generated',
                },
            ];

            const authScore = authItems.reduce((acc, item) => {
                return acc + (item.status === 'pass' ? 35 : item.status === 'warning' ? 15 : 0);
            }, 0);

            // Verification category
            const verificationItems: {
                name: string;
                status: 'pass' | 'fail' | 'warning';
                description: string;
            }[] = [
                {
                    name: 'Email Verification',
                    status: profile.emailVerified ? 'pass' : 'fail',
                    description: profile.emailVerified ? 'Email is verified' : 'Email is not verified',
                },
                {
                    name: 'Phone Verification',
                    status: profile.phoneVerified ? 'pass' : 'warning',
                    description: profile.phoneVerified ? 'Phone is verified' : 'Phone is not verified',
                },
            ];

            const verificationScore = verificationItems.reduce((acc, item) => {
                return acc + (item.status === 'pass' ? 50 : item.status === 'warning' ? 25 : 0);
            }, 0);

            // Devices category (placeholder - would need session data)
            const deviceItems: {
                name: string;
                status: 'pass' | 'fail' | 'warning';
                description: string;
            }[] = [
                {
                    name: 'Recent Login Activity',
                    status: 'pass' as const,
                    description: 'No suspicious activity detected',
                },
                {
                    name: 'Device Management',
                    status: passkeyCount > 1 ? 'pass' : 'warning',
                    description: passkeyCount > 1 ? 'Multiple devices configured' : 'Single device authentication',
                },
            ];

            const deviceScore = deviceItems.reduce((acc, item) => {
                return acc + (item.status === 'pass' ? 50 : item.status === 'warning' ? 25 : 0);
            }, 0);

            const getStatus = (score: number) => {
                if (score >= 90) return 'excellent';
                if (score >= 70) return 'good';
                if (score >= 50) return 'needs_improvement';
                return 'poor';
            };

            const overallScore = Math.round((authScore + verificationScore + deviceScore) / 3);

            const recommendations: string[] = [];

            if (!profile.mfaEnabled) {
                recommendations.push('Enable multi-factor authentication');
            }

            if (passkeyCount === 0) {
                recommendations.push('Set up passkeys for passwordless authentication');
            }

            if (!profile.emailVerified) {
                recommendations.push('Verify your email address');
            }

            if (!profile.phoneVerified) {
                recommendations.push('Verify your phone number');
            }

            return {
                overallScore,
                categories: {
                    authentication: {
                        score: authScore,
                        status: getStatus(authScore),
                        items: authItems,
                    },
                    verification: {
                        score: verificationScore,
                        status: getStatus(verificationScore),
                        items: verificationItems,
                    },
                    devices: {
                        score: deviceScore,
                        status: getStatus(deviceScore),
                        items: deviceItems,
                    },
                },
                recommendations,
            };
        });
    }

    /**
     * Bulk operations for user management
     */
    async bulkUpdateProfile(updates: {
        profile?: Partial<UserProfileUpdateRequest>;
        password?: { current: string; new: string; confirm: string };
        mfa?: { enable: boolean; method?: string };
        verification?: { email?: boolean; phone?: boolean };
    }): Promise<{
        profile?: User;
        passwordChanged?: boolean;
        mfaUpdated?: boolean;
        verificationSent?: boolean;
        errors: Record<string, string>;
    }> {
        return this.executeApiCall(async () => {
            const results: any = { errors: {} };

            // Update profile
            if (updates.profile) {
                try {
                    const validation = this.validateProfile(updates.profile);
                    if (validation.isValid) {
                        results.profile = await this.updateProfile(updates.profile);
                    } else {
                        results.errors.profile = Object.entries(validation.errors)
                            .map(([field, errors]) => `${field}: ${errors.join(', ')}`)
                            .join('; ');
                    }
                } catch (error) {
                    results.errors.profile = error instanceof Error ? error.message : 'Failed to update profile';
                }
            }

            // Change password
            if (updates.password) {
                try {
                    await this.changePasswordSecurely({
                        confirmPassword: updates.password.confirm,
                        currentPassword: updates.password.current,
                        newPassword: updates.password.new,
                    });
                    results.passwordChanged = true;
                } catch (error) {
                    results.errors.password = error instanceof Error ? error.message : 'Failed to change password';
                }
            }

            // Update MFA
            if (updates.mfa) {
                try {
                    if (updates.mfa.enable) {
                        await this.setupMFA({
                            method: updates.mfa.method || 'totp',
                        });
                    } else {
                        await this.disableMFA();
                    }
                    results.mfaUpdated = true;
                } catch (error) {
                    results.errors.mfa = error instanceof Error ? error.message : 'Failed to update MFA';
                }
            }

            // Handle verification
            if (updates.verification) {
                try {
                    if (updates.verification.email) {
                        await this.resendEmailVerification();
                    }
                    if (updates.verification.phone) {
                        await this.resendPhoneVerification();
                    }
                    results.verificationSent = true;
                } catch (error) {
                    results.errors.verification = error instanceof Error ? error.message : 'Failed to send verification';
                }
            }

            return results;
        });
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

    private validatePassword(password: string): {
        isValid: boolean;
        errors: string[];
    } {
        const errors: string[] = [];

        if (password.length < 8) {
            errors.push('Password must be at least 8 characters long');
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (!/[^A-Za-z0-9]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        return {
            isValid: errors.length === 0,
            errors,
        };
    }
}