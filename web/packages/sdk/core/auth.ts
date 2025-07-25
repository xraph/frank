import {
	type AcceptInvitationRequest,
	type AcceptInvitationResponse,
	type AuthProvider,
	type AuthStatus,
	AuthenticationApi,
	Configuration,
	type DeclineInvitationRequest,
	type InitOverrideFunction,
	type InvitationValidationRequest,
	type InvitationValidationResponse,
	InvitationsApi,
	type LoginRequest,
	type LoginResponse,
	type LogoutRequest,
	type LogoutResponse,
	type MFASetupResponse,
	type MFAVerifyRequest,
	type MFAVerifyResponse,
	type MagicLinkRequest,
	type MagicLinkResponse,
	type PasskeyAuthenticationBeginRequest,
	type PasskeyAuthenticationBeginResponse,
	type PasskeyAuthenticationFinishRequest,
	type PasskeyAuthenticationFinishResponse,
	type PasskeyRegistrationBeginRequest,
	type PasskeyRegistrationBeginResponse,
	type PasskeyRegistrationFinishRequest,
	type PasskeyRegistrationFinishResponse,
	type PasswordResetConfirmRequest,
	type PasswordResetConfirmResponse,
	type PasswordResetRequest,
	type PasswordResetResponse,
	type RefreshTokenResponse,
	type RegisterRequest,
	type RegisterResponse,
	type ResendVerificationRequest,
	type ResendVerificationResponse,
	SSOApi,
	type SSOCallbackRequest,
	type SSOCallbackResponse,
	type SSOLoginRequest,
	type SSOLoginResponse,
	type SetupMFARequest,
	type ValidateTokenInputBody,
	type ValidateTokenResponse,
	type VerificationRequest,
	type VerificationResponse,
} from "@frank-auth/client";

import { BaseSDK } from "./base";
import { handleError } from "./errors";
import { type FrankAuthConfig, FrankAuthError } from "./index";

/**
 * The FrankAuth class provides a comprehensive authentication system that extends from the BaseFrankAPI.
 * It implements multiple authentication mechanisms, including email/password-based login, OAuth, SSO,
 * magic links, password resets, multifactor authentication (MFA), passkey authentication, and token validation.
 * The class manages APIs for authorization, SSO, and invitations and provides methods for handling authentication workflows.
 */
export class AuthSDK extends BaseSDK {
	private authApi: AuthenticationApi;
	private invitationsApi: InvitationsApi;
	private ssoApi: SSOApi;

	constructor(config: FrankAuthConfig) {
		if (!config) {
			throw new FrankAuthError("Missing configuration");
		}

		if (!config.storageKeyPrefix) {
			config.storageKeyPrefix = "frank_auth";
		}

		super(config);

		this.authApi = new AuthenticationApi(super.config);
		this.ssoApi = new SSOApi(this.config);
		this.invitationsApi = new InvitationsApi(this.config);
	}

	// Authentication methods with prehook execution
	async signIn(request: LoginRequest): Promise<LoginResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.login(
				{ loginRequest: request },
				this.mergeHeaders(),
			);
			await this.handleAuthResponse(response);
			return response;
		});
	}

	async signUp(request: RegisterRequest): Promise<RegisterResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.register(
				{ registerRequest: request },
				this.mergeHeaders(),
			);
			if (response.accessToken) {
				await this.handleAuthResponse(response);
			}
			return response;
		});
	}

	async signOut(request: LogoutRequest): Promise<LogoutResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.logout(
				{ logoutRequest: request },
				this.mergeHeaders(),
			);
			await this.clearTokens();
			return response;
		});
	}

	async refreshSession(
		token?: string,
		initOverrides?: RequestInit | InitOverrideFunction,
	): Promise<RefreshTokenResponse> {
		if (!this.refreshToken && !token) {
			throw new FrankAuthError("No refresh token available");
		}

		return this.executeApiCall(async () => {
			const response = await this.authApi.refreshToken(
				{
					refreshTokenRequest: {
						// biome-ignore lint/suspicious/noExplicitAny: <explanation>
						refreshToken: (token || this.refreshToken) as any,
					},
				},
				this.mergeHeaders(initOverrides),
			);
			await this.handleAuthResponse(response);
			return response;
		});
	}

	async getAuthStatus(
		initOverrides?: RequestInit | InitOverrideFunction,
	): Promise<AuthStatus> {
		return this.executeApiCall(async () => {
			return await this.authApi.authStatus(this.mergeHeaders(initOverrides));
		});
	}

	// Password reset methods
	async requestPasswordReset(
		request: PasswordResetRequest,
	): Promise<PasswordResetResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.forgotPassword(
				{ passwordResetRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async resetPassword(
		request: PasswordResetConfirmRequest,
	): Promise<PasswordResetConfirmResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.resetPassword(
				{ passwordResetConfirmRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	// Magic link methods
	async sendMagicLink(request: MagicLinkRequest): Promise<MagicLinkResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.magicLink(
				{ magicLinkRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async verifyMagicLink(token: string): Promise<LoginResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.verifyMagicLink(
				{ token },
				this.mergeHeaders(),
			);
			await this.handleAuthResponse(response);
			return response;
		});
	}

	// Token validation methods
	async validateToken(
		request: Omit<ValidateTokenInputBody, "$schema">,
		initOverrides?: RequestInit | InitOverrideFunction,
	): Promise<ValidateTokenResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.validateToken(
				{ validateTokenInputBody: request },
				this.mergeHeaders(initOverrides),
			);
		});
	}

	async resendVerification(
		request: ResendVerificationRequest,
	): Promise<ResendVerificationResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.resendVerification(
				{ resendVerificationRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	// Email verification methods
	async verifyEmail(
		request: VerificationRequest,
	): Promise<VerificationResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.verifyEmail(
				{ verificationRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async verifyPhone(
		request: VerificationRequest,
	): Promise<VerificationResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.verifyPhone(
				{ verificationRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	// MFA methods
	async setupMFA(request: SetupMFARequest): Promise<MFASetupResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.setupMFA(
				{ setupMFARequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async verifyMFA(request: MFAVerifyRequest): Promise<MFAVerifyResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.verifyMFAAuth(
				{ mFAVerifyRequest: request },
				this.mergeHeaders(),
			);
			if (response.loginData) {
				await this.handleAuthResponse(response);
			}
			return response;
		});
	}

	async disableMFA(): Promise<void> {
		return this.executeApiCall(async () => {
			await this.authApi.disableMFA(this.mergeHeaders());
		});
	}

	// Passkey methods
	async beginPasskeyRegistration(
		request: PasskeyRegistrationBeginRequest,
	): Promise<PasskeyRegistrationBeginResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.beginPasskeyRegistrationAuth(
				{ passkeyRegistrationBeginRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async finishPasskeyRegistration(
		request: PasskeyRegistrationFinishRequest,
	): Promise<PasskeyRegistrationFinishResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.finishPasskeyRegistrationAuth(
				{ passkeyRegistrationFinishRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async beginPasskeyAuthentication(
		request: PasskeyAuthenticationBeginRequest,
	): Promise<PasskeyAuthenticationBeginResponse> {
		return this.executeApiCall(async () => {
			return await this.authApi.beginPasskeyAuthenticationAuth(
				{ passkeyAuthenticationBeginRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async finishPasskeyAuthentication(
		request: PasskeyAuthenticationFinishRequest,
	): Promise<PasskeyAuthenticationFinishResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.finishPasskeyAuthenticationAuth(
				{ passkeyAuthenticationFinishRequest: request },
				this.mergeHeaders(),
			);
			if (response.accessToken) {
				await this.handleAuthResponse(response);
			}
			return response;
		});
	}

	// OAuth methods
	async getOAuthProviders(): Promise<AuthProvider[]> {
		return this.executeApiCall(async () => {
			return await this.authApi.listOAuthProviders(this.mergeHeaders());
		});
	}

	async redirectToOAuth(provider: string, redirectUrl?: string): Promise<void> {
		// Execute prehooks before redirect (to ensure latest tokens are loaded)
		await this.executePrehooks();

		const state = redirectUrl
			? btoa(JSON.stringify({ redirectUrl }))
			: undefined;
		const url = `${this.options.apiUrl}/api/v1/public/auth/oauth/${provider}/authorize${state ? `?state=${state}` : ""}`;
		window.location.href = url;
	}

	async handleOAuthCallback(
		provider: string,
		code: string,
		state?: string,
	): Promise<LoginResponse> {
		return this.executeApiCall(async () => {
			const response = await this.authApi.oauthCallback(
				{ provider, code, state },
				this.mergeHeaders(),
			);
			await this.handleAuthResponse(response);
			return response;
		});
	}

	// SSO methods
	async initiateSSOLogin(request: SSOLoginRequest): Promise<SSOLoginResponse> {
		return this.executeApiCall(async () => {
			return await this.ssoApi.initiateSSOLogin(
				{ sSOLoginRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async handleSSOCallback(
		request: SSOCallbackRequest,
	): Promise<SSOCallbackResponse> {
		return this.executeApiCall(async () => {
			const response = await this.ssoApi.handleSSOCallback(
				{ sSOCallbackRequest: request },
				this.mergeHeaders(),
			);
			if (response.accessToken) {
				await this.handleAuthResponse(response);
			}
			return response;
		});
	}

	// Invitation methods
	async validateInvitation(
		request: InvitationValidationRequest,
	): Promise<InvitationValidationResponse> {
		return this.executeApiCall(async () => {
			return await this.invitationsApi.validateInvitation(
				{ invitationValidationRequest: request },
				this.mergeHeaders(),
			);
		});
	}

	async acceptInvitation(
		request: AcceptInvitationRequest,
	): Promise<AcceptInvitationResponse> {
		return this.executeApiCall(async () => {
			const response = await this.invitationsApi.acceptInvitation(
				{ acceptInvitationRequest: request },
				this.mergeHeaders(),
			);
			if (response.accessToken) {
				await this.handleAuthResponse(response);
			}
			return response;
		});
	}

	async declineInvitation(request: DeclineInvitationRequest): Promise<void> {
		return this.executeApiCall(async () => {
			await this.invitationsApi.declineInvitation(
				{ declineInvitationRequest: request },
				this.mergeHeaders(),
			);
		});
	}
}
