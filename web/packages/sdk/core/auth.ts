import {
    AcceptInvitationRequest,
    AcceptInvitationResponse,
    AuthenticationApi,
    AuthProvider,
    AuthStatus,
    Configuration,
    DeclineInvitationRequest,
    InitOverrideFunction,
    InvitationsApi,
    InvitationValidationRequest,
    InvitationValidationResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    MagicLinkRequest,
    MagicLinkResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    PasskeyAuthenticationBeginRequest,
    PasskeyAuthenticationBeginResponse,
    PasskeyAuthenticationFinishRequest,
    PasskeyAuthenticationFinishResponse,
    PasskeyRegistrationBeginRequest,
    PasskeyRegistrationBeginResponse,
    PasskeyRegistrationFinishRequest,
    PasskeyRegistrationFinishResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequest,
    PasswordResetResponse,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResendVerificationResponse,
    SetupMFARequest,
    SSOApi,
    SSOCallbackRequest,
    SSOCallbackResponse,
    SSOLoginRequest,
    SSOLoginResponse,
    ValidateTokenInputBody,
    ValidateTokenResponse,
    VerificationRequest,
    VerificationResponse,
} from '@frank-auth/client';

import {FrankAuthConfig, FrankAuthError} from './index';
import {handleError} from "./errors";
import {BaseFrankAPI} from "./base";

export class FrankAuth extends BaseFrankAPI {
    private authApi: AuthenticationApi;
    private invitationsApi: InvitationsApi;
    private ssoApi: SSOApi;

    constructor(config: FrankAuthConfig) {
        super(config)

        this.authApi = new AuthenticationApi(this.config);
        this.ssoApi = new SSOApi(this.config);
        this.invitationsApi = new InvitationsApi(this.config);

        // Load tokens from storage
        this.loadTokensFromStorage();
    }

    // Authentication methods
    async signIn(request: LoginRequest): Promise<LoginResponse> {
        try {
            const response = await this.authApi.login(
                {loginRequest: request},
                this.mergeHeaders()
            );
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async signUp(request: RegisterRequest): Promise<RegisterResponse> {
        try {
            const response = await this.authApi.register(
                {registerRequest: request},
                this.mergeHeaders()
            );
            if (response.accessToken) {
                await this.handleAuthResponse(response);
            }
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async signOut(request: LogoutRequest): Promise<LogoutResponse> {
        try {
            const response = await this.authApi.logout(
                {logoutRequest: request},
                this.mergeHeaders()
            );
            await this.clearTokens();
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async refreshSession(token?: string, initOverrides?: RequestInit | InitOverrideFunction): Promise<RefreshTokenResponse> {
        if (!this.refreshToken && !token) {
            throw new FrankAuthError('No refresh token available');
        }

        try {
            const response = await this.authApi.refreshToken(
                {refreshTokenRequest: {refreshToken: (token || this.refreshToken) as any}},
                this.mergeHeaders(initOverrides)
            );
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            await this.clearTokens();
            throw await handleError(error);
        }
    }

    async getAuthStatus(initOverrides?: RequestInit | InitOverrideFunction): Promise<AuthStatus> {
        try {
            return await this.authApi.authStatus(this.mergeHeaders(initOverrides));
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Password reset methods
    async requestPasswordReset(request: PasswordResetRequest): Promise<PasswordResetResponse> {
        try {
            return await this.authApi.forgotPassword(
                {passwordResetRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async resetPassword(request: PasswordResetConfirmRequest): Promise<PasswordResetConfirmResponse> {
        try {
            return await this.authApi.resetPassword(
                {passwordResetConfirmRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Magic link methods
    async sendMagicLink(request: MagicLinkRequest): Promise<MagicLinkResponse> {
        try {
            return await this.authApi.magicLink(
                {magicLinkRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyMagicLink(token: string): Promise<LoginResponse> {
        try {
            const response = await this.authApi.verifyMagicLink(
                {token},
                this.mergeHeaders()
            );
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Resend verification methods
    async validateToken(request: Omit<ValidateTokenInputBody, '$schema'>, initOverrides?: RequestInit | InitOverrideFunction): Promise<ValidateTokenResponse> {
        try {
            return await this.authApi.validateToken(
                {validateTokenInputBody: request},
                this.mergeHeaders(initOverrides)
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async resendVerification(request: ResendVerificationRequest): Promise<ResendVerificationResponse> {
        try {
            return await this.authApi.resendVerification(
                {resendVerificationRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Email verification methods
    async verifyEmail(request: VerificationRequest): Promise<VerificationResponse> {
        try {
            return await this.authApi.verifyEmail(
                {verificationRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyPhone(request: VerificationRequest): Promise<VerificationResponse> {
        try {
            return await this.authApi.verifyPhone(
                {verificationRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    // MFA methods
    async setupMFA(request: SetupMFARequest): Promise<MFASetupResponse> {
        try {
            return await this.authApi.setupMFA(
                {setupMFARequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyMFA(request: MFAVerifyRequest): Promise<MFAVerifyResponse> {
        try {
            const response = await this.authApi.verifyMFAAuth(
                {mFAVerifyRequest: request},
                this.mergeHeaders()
            );
            if (response.loginData) {
                await this.handleAuthResponse(response);
            }
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async disableMFA(): Promise<void> {
        try {
            await this.authApi.disableMFA(this.mergeHeaders());
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Passkey methods
    async beginPasskeyRegistration(request: PasskeyRegistrationBeginRequest): Promise<PasskeyRegistrationBeginResponse> {
        try {
            return await this.authApi.beginPasskeyRegistrationAuth(
                {passkeyRegistrationBeginRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async finishPasskeyRegistration(request: PasskeyRegistrationFinishRequest): Promise<PasskeyRegistrationFinishResponse> {
        try {
            return await this.authApi.finishPasskeyRegistrationAuth(
                {passkeyRegistrationFinishRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async beginPasskeyAuthentication(request: PasskeyAuthenticationBeginRequest): Promise<PasskeyAuthenticationBeginResponse> {
        try {
            return await this.authApi.beginPasskeyAuthenticationAuth(
                {passkeyAuthenticationBeginRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async finishPasskeyAuthentication(request: PasskeyAuthenticationFinishRequest): Promise<PasskeyAuthenticationFinishResponse> {
        try {
            const response = await this.authApi.finishPasskeyAuthenticationAuth(
                {passkeyAuthenticationFinishRequest: request},
                this.mergeHeaders()
            );
            if (response.accessToken) {
                await this.handleAuthResponse(response);
            }
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // OAuth methods
    async getOAuthProviders(): Promise<AuthProvider[]> {
        try {
            return await this.authApi.listOAuthProviders(this.mergeHeaders());
        } catch (error) {
            throw await handleError(error);
        }
    }

    async redirectToOAuth(provider: string, redirectUrl?: string): Promise<void> {
        const state = redirectUrl ? btoa(JSON.stringify({redirectUrl})) : undefined;
        const url = `${this.options.apiUrl}/api/v1/public/auth/oauth/${provider}/authorize${state ? `?state=${state}` : ''}`;
        window.location.href = url;
    }

    async handleOAuthCallback(provider: string, code: string, state?: string): Promise<LoginResponse> {
        try {
            const response = await this.authApi.oauthCallback(
                {provider, code, state},
                this.mergeHeaders()
            );
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // SSO methods
    async initiateSSOLogin(request: SSOLoginRequest): Promise<SSOLoginResponse> {
        try {
            return await this.ssoApi.initiateSSOLogin(
                {sSOLoginRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async handleSSOCallback(request: SSOCallbackRequest): Promise<SSOCallbackResponse> {
        try {
            const response = await this.ssoApi.handleSSOCallback(
                {sSOCallbackRequest: request},
                this.mergeHeaders()
            );
            if (response.accessToken) {
                await this.handleAuthResponse(response);
            }
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Invitation methods
    async validateInvitation(request: InvitationValidationRequest): Promise<InvitationValidationResponse> {
        try {
            return await this.invitationsApi.validateInvitation(
                {invitationValidationRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    async acceptInvitation(request: AcceptInvitationRequest): Promise<AcceptInvitationResponse> {
        try {
            const response = await this.invitationsApi.acceptInvitation(
                {acceptInvitationRequest: request},
                this.mergeHeaders()
            );
            if (response.accessToken) {
                await this.handleAuthResponse(response);
            }
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async declineInvitation(request: DeclineInvitationRequest): Promise<void> {
        try {
            await this.invitationsApi.declineInvitation(
                {declineInvitationRequest: request},
                this.mergeHeaders()
            );
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Private methods
    private async handleAuthResponse(response: LoginResponse): Promise<void> {
        if (response.accessToken) {
            this.accessToken = response.accessToken;
            await this.saveToStorage('accessToken', response.accessToken);
        }
        if (response.refreshToken) {
            this.refreshToken = response.refreshToken;
            await this.saveToStorage('refreshToken', response.refreshToken);
        }
    }

    private async clearTokens(): Promise<void> {
        this.resetTokens();
        await this.removeFromStorage('accessToken');
        await this.removeFromStorage('refreshToken');
    }

    private loadTokensFromStorage(): void {
        if (typeof window === 'undefined') return;

        this.accessToken = localStorage.getItem(`${this.options.storageKeyPrefix}accessToken`);
        this.refreshToken = localStorage.getItem(`${this.options.storageKeyPrefix}refreshToken`);
    }

    private async saveToStorage(key: string, value: string): Promise<void> {
        if (typeof window === 'undefined') return;

        localStorage.setItem(`${this.options.storageKeyPrefix}${key}`, value);
    }

    private async removeFromStorage(key: string): Promise<void> {
        if (typeof window === 'undefined') return;

        localStorage.removeItem(`${this.options.storageKeyPrefix}${key}`);
    }
}