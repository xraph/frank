import {
    AcceptInvitationRequest,
    AcceptInvitationResponse,
    AuthenticationApi,
    AuthProvider,
    AuthStatus,
    Configuration,
    DeclineInvitationRequest,
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
    SetupMFARequest,
    SSOApi,
    SSOCallbackRequest,
    SSOCallbackResponse,
    SSOLoginRequest,
    SSOLoginResponse,
    VerificationRequest,
    VerificationResponse,
} from '@frank-auth/client';

import {FrankAuthConfig, FrankAuthError} from './index';
import {handleError} from "./errors";

export class FrankAuth {
    private config: FrankAuthConfig;
    private authApi: AuthenticationApi;
    private invitationsApi: InvitationsApi;
    private ssoApi: SSOApi;
    private accessToken: string | null = null;
    private refreshToken: string | null = null;

    constructor(config: FrankAuthConfig) {
        this.config = config;

        const configuration = new Configuration({
            basePath: config.apiUrl,
            accessToken: () => this.accessToken || '',
            credentials: 'include',
            headers: {
                'X-Publishable-Key': config.publishableKey,
            },
        });

        this.authApi = new AuthenticationApi(configuration);
        this.ssoApi = new SSOApi(configuration);
        this.invitationsApi = new InvitationsApi(configuration);

        // Load tokens from storage
        this.loadTokensFromStorage();
    }

    // Authentication methods
    async signIn(request: LoginRequest): Promise<LoginResponse> {
        try {
            const response = await this.authApi.login({ loginRequest: request });
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async signUp(request: RegisterRequest): Promise<RegisterResponse> {
        try {
            const response = await this.authApi.register({ registerRequest: request });
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
            const response = await this.authApi.logout({ logoutRequest: request });
            await this.clearTokens();
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    async refreshSession(): Promise<RefreshTokenResponse> {
        if (!this.refreshToken) {
            throw new FrankAuthError('No refresh token available');
        }

        try {
            const response = await this.authApi.refreshToken({
                refreshTokenRequest: { refreshToken: this.refreshToken },
            });
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            await this.clearTokens();
            throw await handleError(error);
        }
    }

    async getAuthStatus(): Promise<AuthStatus> {
        try {
            return await this.authApi.authStatus();
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Password reset methods
    async requestPasswordReset(request: PasswordResetRequest): Promise<PasswordResetResponse> {
        try {
            return await this.authApi.forgotPassword({ passwordResetRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async resetPassword(request: PasswordResetConfirmRequest): Promise<PasswordResetConfirmResponse> {
        try {
            return await this.authApi.resetPassword({ passwordResetConfirmRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Magic link methods
    async sendMagicLink(request: MagicLinkRequest): Promise<MagicLinkResponse> {
        try {
            return await this.authApi.magicLink({ magicLinkRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyMagicLink(token: string): Promise<LoginResponse> {
        try {
            const response = await this.authApi.verifyMagicLink({ token });
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Email verification methods
    async verifyEmail(request: VerificationRequest): Promise<VerificationResponse> {
        try {
            return await this.authApi.verifyEmail({ verificationRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyPhone(request: VerificationRequest): Promise<VerificationResponse> {
        try {
            return await this.authApi.verifyPhone({ verificationRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    // MFA methods
    async setupMFA(request: SetupMFARequest): Promise<MFASetupResponse> {
        try {
            return await this.authApi.setupMFA({ setupMFARequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async verifyMFA(request: MFAVerifyRequest): Promise<MFAVerifyResponse> {
        try {
            const response = await this.authApi.verifyMFAAuth({ mFAVerifyRequest: request });
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
            await this.authApi.disableMFA();
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Passkey methods
    async beginPasskeyRegistration(request: PasskeyRegistrationBeginRequest): Promise<PasskeyRegistrationBeginResponse> {
        try {
            return await this.authApi.beginPasskeyRegistrationAuth({ passkeyRegistrationBeginRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async finishPasskeyRegistration(request: PasskeyRegistrationFinishRequest): Promise<PasskeyRegistrationFinishResponse> {
        try {
            return await this.authApi.finishPasskeyRegistrationAuth({ passkeyRegistrationFinishRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async beginPasskeyAuthentication(request: PasskeyAuthenticationBeginRequest): Promise<PasskeyAuthenticationBeginResponse> {
        try {
            return await this.authApi.beginPasskeyAuthenticationAuth({ passkeyAuthenticationBeginRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async finishPasskeyAuthentication(request: PasskeyAuthenticationFinishRequest): Promise<PasskeyAuthenticationFinishResponse> {
        try {
            const response = await this.authApi.finishPasskeyAuthenticationAuth({ passkeyAuthenticationFinishRequest: request });
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
            return await this.authApi.listOAuthProviders();
        } catch (error) {
            throw await handleError(error);
        }
    }

    async redirectToOAuth(provider: string, redirectUrl?: string): Promise<void> {
        const state = redirectUrl ? btoa(JSON.stringify({ redirectUrl })) : undefined;
        const url = `${this.config.apiUrl}/api/v1/public/auth/oauth/${provider}/authorize${state ? `?state=${state}` : ''}`;
        window.location.href = url;
    }

    async handleOAuthCallback(provider: string, code: string, state?: string): Promise<LoginResponse> {
        try {
            const response = await this.authApi.oauthCallback({ provider, code, state });
            await this.handleAuthResponse(response);
            return response;
        } catch (error) {
            throw await handleError(error);
        }
    }

    // SSO methods
    async initiateSSOLogin(request: SSOLoginRequest): Promise<SSOLoginResponse> {
        try {
            return await this.ssoApi.initiateSSOLogin({ sSOLoginRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async handleSSOCallback(request: SSOCallbackRequest): Promise<SSOCallbackResponse> {
        try {
            const response = await this.ssoApi.handleSSOCallback({ sSOCallbackRequest: request });
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
            return await this.invitationsApi.validateInvitation({ invitationValidationRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    async acceptInvitation(request: AcceptInvitationRequest): Promise<AcceptInvitationResponse> {
        try {
            const response = await this.invitationsApi.acceptInvitation({ acceptInvitationRequest: request });
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
            await this.invitationsApi.declineInvitation({ declineInvitationRequest: request });
        } catch (error) {
            throw await handleError(error);
        }
    }

    // Utility methods
    isSignedIn(): boolean {
        return !!this.accessToken;
    }

    getAccessToken(): string | null {
        return this.accessToken;
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
        this.accessToken = null;
        this.refreshToken = null;
        await this.removeFromStorage('accessToken');
        await this.removeFromStorage('refreshToken');
    }

    private loadTokensFromStorage(): void {
        if (typeof window === 'undefined') return;

        this.accessToken = localStorage.getItem(`${this.config.storageKeyPrefix}accessToken`);
        this.refreshToken = localStorage.getItem(`${this.config.storageKeyPrefix}refreshToken`);
    }

    private async saveToStorage(key: string, value: string): Promise<void> {
        if (typeof window === 'undefined') return;

        localStorage.setItem(`${this.config.storageKeyPrefix}${key}`, value);
    }

    private async removeFromStorage(key: string): Promise<void> {
        if (typeof window === 'undefined') return;

        localStorage.removeItem(`${this.config.storageKeyPrefix}${key}`);
    }
}