import {
	AuthenticationApi,
	Configuration,
	type InitOverrideFunction,
	type LoginResponse,
	type RefreshTokenResponse,
} from "@frank-auth/client";

import { convertError } from "./errors";
import {
	type AuthStorage,
	AuthStorageUtils,
	type FrankAuthConfig,
	FrankAuthError,
	HybridAuthStorage,
	type StorageAdapter,
	type StorageManager,
} from "./index";
import {
	type ConfigValidationError,
	type ValidationResult,
	createError,
	validateApiUrl,
	validateProjectId,
	validatePublishableKey,
	validateSecretKey,
	validateSessionCookieName,
	validateStorageKeyPrefix,
	validateUserType,
} from "./validation";

// Type for prehook functions
type PrehookFunction = () => Promise<void> | void;

/**
 * Interface for JWT token payload
 */
interface JWTPayload {
	exp?: number; // Expiration time (seconds since epoch)
	iat?: number; // Issued at time
	[key: string]: any;
}

/**
 * Token expiration check result
 */
interface TokenExpirationResult {
	isExpired: boolean;
	isValid: boolean;
	expiresAt?: Date;
	expiresIn?: number; // seconds until expiration
	error?: string;
}

/**
 * FrankOrganization - Organization Management SDK
 *
 * Provides comprehensive organization management capabilities including:
 * - Organization CRUD operations
 * - Member management and invitations
 * - Domain verification and management
 * - Billing and subscription management
 * - Feature management and statistics
 * - Settings and configuration
 *
 * Supports multi-tenant architecture with organization-scoped operations
 */
export class BaseSDK {
	private readonly _storage: StorageManager;
	private readonly _hybridAuthStorage: HybridAuthStorage;
	private readonly _authStorage: AuthStorage;
	private readonly _options: FrankAuthConfig;
	private readonly _config: Configuration;
	private readonly _validationResult: ValidationResult;
	private readonly _prehooks: Set<PrehookFunction> = new Set();

	private readonly internalAuthApi: AuthenticationApi;

	private _accessToken: string | null = null;
	private _refreshToken: string | null = null;
	private _activeSessionId: string | null = null;

	// Token expiration buffer (in seconds) - refresh token if it expires within this time
	private readonly TOKEN_REFRESH_BUFFER = 300; // 5 minutes

	constructor(config: FrankAuthConfig, accessToken?: string) {
		this._hybridAuthStorage =
			config.storage ??
			new HybridAuthStorage(
				config.storageKeyPrefix ? `${config.storageKeyPrefix}_` : "frank_auth_",
			);
		this._authStorage = this._hybridAuthStorage.store;
		this._storage = this._authStorage.adapter;
		this._options = config;
		this._accessToken = accessToken || null;
		this.internalAuthApi = new AuthenticationApi(this.config);

		// Validate configuration
		this._validationResult = this.validateConfig(config);

		const headers = {
			"X-Publishable-Key": this._options.publishableKey,
			"X-User-Type": this._options.userType,
			"Content-Type": "application/json",
		} as Record<string, string>;

		if (this._options.secretKey) {
			headers["X-API-Key"] = this._options.secretKey;
		}

		if (this._options.secretKey) {
			headers["X-API-Key"] = this._options.secretKey;
		}

		if (this._accessToken) {
			headers["Authorization"] = `Bearer ${this._accessToken}`;
		}

		this._config = new Configuration({
			basePath: config.apiUrl,
			accessToken: () => this.accessToken || "",
			credentials: "include",
			headers,
		});

		this._storage.on(AuthStorageUtils.accessTokenKey, () => {
			this.loadTokensFromStorage();
		});

		this._storage.on(AuthStorageUtils.refreshTokenKey, () => {
			this.loadTokensFromStorage();
		});

		// Add the default prehook to load tokens from storage
		this.addPrehook(() => this.loadTokensFromStorage());

		// Add prehook to check and renew tokens before API calls
		this.addPrehook(() => this.checkAndRenewTokens());

		// Load tokens from storage initially
		this.loadTokensFromStorage();
	}

	// ================================
	// Token Expiration & Renewal
	// ================================

	/**
	 * Decode JWT token payload without verification
	 * @param token JWT token string
	 * @returns Decoded payload or null if invalid
	 */
	private decodeJWTPayload(token: string): JWTPayload | null {
		try {
			// Split the token into parts
			const parts = token.split(".");
			if (parts.length !== 3) {
				return null;
			}

			// Decode the payload (second part)
			const payload = parts[1];

			// Add padding if needed for base64 decoding
			const paddedPayload =
				payload + "=".repeat((4 - (payload.length % 4)) % 4);

			// Decode base64
			const decoded = atob(paddedPayload.replace(/-/g, "+").replace(/_/g, "/"));

			// Parse JSON
			return JSON.parse(decoded) as JWTPayload;
		} catch (error) {
			console.warn("Failed to decode JWT token:", error);
			return null;
		}
	}

	/**
	 * Check if a token is expired
	 * @param token JWT token string
	 * @param bufferSeconds Buffer time in seconds (default: 5 minutes)
	 * @returns Token expiration result
	 */
	public checkTokenExpiration(
		token: string | null,
		bufferSeconds: number = this.TOKEN_REFRESH_BUFFER,
	): TokenExpirationResult {
		if (!token) {
			return {
				isExpired: true,
				isValid: false,
				error: "Token is null or undefined",
			};
		}

		const payload = this.decodeJWTPayload(token);
		if (!payload) {
			return {
				isExpired: true,
				isValid: false,
				error: "Invalid token format",
			};
		}

		if (!payload.exp) {
			return {
				isExpired: false,
				isValid: true,
				error: "Token has no expiration time",
			};
		}

		const now = Math.floor(Date.now() / 1000); // Current time in seconds
		const expiresAt = new Date(payload.exp * 1000);
		const expiresIn = payload.exp - now;
		const isExpired = payload.exp - bufferSeconds <= now;

		return {
			isExpired,
			isValid: true,
			expiresAt,
			expiresIn,
		};
	}

	/**
	 * Check if access token is expired
	 * @param bufferSeconds Buffer time in seconds
	 * @returns Token expiration result
	 */
	public isAccessTokenExpired(
		bufferSeconds: number = this.TOKEN_REFRESH_BUFFER,
	): TokenExpirationResult {
		return this.checkTokenExpiration(this._accessToken, bufferSeconds);
	}

	/**
	 * Check if refresh token is expired
	 * @param bufferSeconds Buffer time in seconds
	 * @returns Token expiration result
	 */
	public isRefreshTokenExpired(
		bufferSeconds: number = this.TOKEN_REFRESH_BUFFER,
	): TokenExpirationResult {
		return this.checkTokenExpiration(this._refreshToken, bufferSeconds);
	}

	/**
	 * Check if refresh token is valid and not expired
	 * @returns boolean indicating if refresh token is valid
	 */
	public isRefreshTokenValid(): boolean {
		const result = this.isRefreshTokenExpired(0); // Check without buffer
		return result.isValid && !result.isExpired;
	}

	/**
	 * Check if access token is valid and not expired
	 * @returns boolean indicating if access token is valid
	 */
	public isAccessTokenValid(): boolean {
		const result = this.isAccessTokenExpired(0); // Check without buffer
		return result.isValid && !result.isExpired;
	}

	/**
	 * Verify refresh token and renew if needed
	 * @param forceRenew Force renewal even if token is not expired
	 * @returns Promise that resolves when verification/renewal is complete
	 */
	public async verifyAndRenewRefreshToken(forceRenew = false): Promise<{
		renewed: boolean;
		wasExpired: boolean;
		newTokens?: {
			accessToken: string;
			refreshToken: string;
		};
	}> {
		const refreshTokenResult = this.isRefreshTokenExpired();

		if (!refreshTokenResult.isValid) {
			throw new FrankAuthError(
				"Invalid refresh token",
				"INVALID_REFRESH_TOKEN",
			);
		}

		const shouldRenew = forceRenew || refreshTokenResult.isExpired;

		if (!shouldRenew) {
			return {
				renewed: false,
				wasExpired: refreshTokenResult.isExpired,
			};
		}

		if (!this._refreshToken) {
			throw new FrankAuthError(
				"No refresh token available",
				"NO_REFRESH_TOKEN",
			);
		}

		try {
			const response = await this.renewRefreshToken();

			return {
				renewed: true,
				wasExpired: refreshTokenResult.isExpired,
				newTokens: {
					accessToken: response.accessToken || "",
					refreshToken: response.refreshToken || "",
				},
			};
		} catch (error) {
			throw new FrankAuthError(
				"Failed to renew refresh token",
				"REFRESH_TOKEN_RENEWAL_FAILED",
				{ originalError: error },
			);
		}
	}

	/**
	 * Check and renew tokens automatically (used in prehooks)
	 * @returns Promise that resolves when check/renewal is complete
	 */
	public async checkAndRenewTokens(): Promise<void> {
		try {
			// Check if we have tokens
			if (!this._accessToken || !this._refreshToken) {
				return;
			}

			// Check if access token is expired or about to expire
			const accessTokenResult = this.isAccessTokenExpired();

			if (accessTokenResult.isExpired && accessTokenResult.isValid) {
				// Access token is expired, try to renew using refresh token
				const refreshTokenResult = this.isRefreshTokenExpired();

				if (!refreshTokenResult.isExpired && refreshTokenResult.isValid) {
					// Refresh token is still valid, renew tokens
					await this.verifyAndRenewRefreshToken();
				} else {
					// Both tokens are expired, clear them
					await this.clearTokens();
				}
			}
		} catch (error) {
			console.warn("Failed to check and renew tokens:", error);
			// Don't throw error to avoid breaking API calls
		}
	}

	/**
	 * Get token expiration information
	 * @returns Object with expiration details for both tokens
	 */
	public getTokenExpirationInfo(): {
		accessToken: TokenExpirationResult;
		refreshToken: TokenExpirationResult;
	} {
		return {
			accessToken: this.isAccessTokenExpired(),
			refreshToken: this.isRefreshTokenExpired(),
		};
	}

	/**
	 * Set token refresh buffer time
	 * @param bufferSeconds Buffer time in seconds
	 */
	public setTokenRefreshBuffer(bufferSeconds: number): void {
		if (bufferSeconds < 0) {
			throw new Error("Token refresh buffer must be non-negative");
		}
		// We can't modify the readonly property, but we can add this for future use
		// For now, methods will use the provided buffer parameter
	}

	/**
	 * Get current token refresh buffer
	 * @returns Buffer time in seconds
	 */
	public getTokenRefreshBuffer(): number {
		return this.TOKEN_REFRESH_BUFFER;
	}

	/**
	 * Execute an API call with automatic 401 error handling and token refresh
	 * @param apiCall The API call to execute
	 * @param options Options for the API call execution
	 * @returns Promise that resolves to the API call result
	 */
	public async executeApiCallWithRetry<T>(
		apiCall: () => Promise<T>,
		options: {
			skipPrehooks?: boolean;
			retryOn401?: boolean;
			maxRetries?: number;
		} = {},
	): Promise<T> {
		const { skipPrehooks = false, retryOn401 = true, maxRetries = 1 } = options;

		try {
			// Execute prehooks unless explicitly skipped
			if (!skipPrehooks) {
				await this.executePrehooks();
			}

			// Use retry logic for 401 errors if enabled
			if (retryOn401) {
				return await this.refreshTokenAndRetry(apiCall, maxRetries);
			}
			return await apiCall();
		} catch (error) {
			throw await this.handleError(error);
		}
	}

	/**
	 * Check if the last API call failed due to token issues
	 * @param error The error from the API call
	 * @returns Information about the token-related error
	 */
	public analyzeTokenError(error: any): {
		is401Error: boolean;
		isTokenExpired: boolean;
		isRefreshTokenExpired: boolean;
		recommendedAction: "refresh" | "reauth" | "retry" | "none";
	} {
		const is401 = this.is401Error(error);
		const accessTokenResult = this.isAccessTokenExpired(0);
		const refreshTokenResult = this.isRefreshTokenExpired(0);

		let recommendedAction: "refresh" | "reauth" | "retry" | "none" = "none";

		if (is401) {
			if (refreshTokenResult.isExpired || !refreshTokenResult.isValid) {
				recommendedAction = "reauth";
			} else if (accessTokenResult.isExpired || !accessTokenResult.isValid) {
				recommendedAction = "refresh";
			} else {
				// Token appears valid but getting 401 - try refresh
				recommendedAction = "refresh";
			}
		} else if (
			accessTokenResult.isExpired &&
			refreshTokenResult.isValid &&
			!refreshTokenResult.isExpired
		) {
			recommendedAction = "refresh";
		} else if (accessTokenResult.isExpired && refreshTokenResult.isExpired) {
			recommendedAction = "reauth";
		}

		return {
			is401Error: is401,
			isTokenExpired: accessTokenResult.isExpired,
			isRefreshTokenExpired: refreshTokenResult.isExpired,
			recommendedAction,
		};
	}

	/**
	 * Refresh token and retry API call on 401 errors
	 * @param apiCall The API call to retry
	 * @param maxRetries Maximum number of retry attempts
	 * @returns Promise that resolves to the API call result
	 */
	private async refreshTokenAndRetry<T>(
		apiCall: () => Promise<T>,
		maxRetries = 1,
	): Promise<T> {
		let retryCount = 0;

		while (retryCount <= maxRetries) {
			try {
				return await apiCall();
			} catch (error) {
				// If this is not a 401 error, or we've exceeded retries, throw the error
				if (!this.is401Error(error) || retryCount >= maxRetries) {
					throw error;
				}

				// Attempt to handle 401 error by refreshing token
				const tokenRefreshed = await this.handle401Error(error);

				if (!tokenRefreshed) {
					// If token refresh failed, throw the original error
					throw error;
				}

				retryCount++;
				console.log(
					`Retrying API call after token refresh (attempt ${retryCount}/${maxRetries})`,
				);
			}
		}

		// This shouldn't be reached, but just in case
		throw new Error("Maximum retry attempts exceeded");
	}

	/**
	 * Handle 401 errors by attempting token refresh
	 * @param error The error that occurred
	 * @returns Promise that resolves to true if token was refreshed, false otherwise
	 */
	private async handle401Error(error: any): Promise<boolean> {
		try {
			// Check if this is a 401 error
			if (!this.is401Error(error)) {
				return false;
			}

			// Check if we have a refresh token
			if (!this._refreshToken) {
				return false;
			}

			// Check if refresh token is still valid
			const refreshTokenResult = this.isRefreshTokenExpired();
			if (refreshTokenResult.isExpired || !refreshTokenResult.isValid) {
				// Refresh token is also expired/invalid, clear tokens
				await this.clearTokens();
				return false;
			}

			// Attempt to refresh tokens
			await this.verifyAndRenewRefreshToken(true); // Force renewal
			return true;
		} catch (refreshError) {
			console.warn("Failed to refresh token after 401 error:", refreshError);
			// Clear tokens if refresh fails
			await this.clearTokens();
			return false;
		}
	}

	/**
	 * Check if an error is a 401 Unauthorized error
	 * @param error The error to check
	 * @returns True if it's a 401 error
	 */
	private is401Error(error: any): boolean {
		// Check different possible error structures
		return (
			error?.status === 401 ||
			error?.response?.status === 401 ||
			error?.statusCode === 401 ||
			(error?.message && error.message.includes("401")) ||
			error?.response?.data?.status === 401
		);
	}

	// ================================
	// Prehook Management
	// ================================

	/**
	 * Add a prehook function that will be called before every API request
	 */
	public addPrehook(prehook: PrehookFunction): void {
		this._prehooks.add(prehook);
	}

	/**
	 * Remove a prehook function
	 */
	public removePrehook(prehook: PrehookFunction): void {
		this._prehooks.delete(prehook);
	}

	/**
	 * Clear all prehooks
	 */
	public clearPrehooks(): void {
		this._prehooks.clear();
	}

	/**
	 * Execute all prehooks
	 */
	protected async executePrehooks(): Promise<void> {
		for (const prehook of this._prehooks) {
			await prehook();
		}
	}

	/**
	 * Add a custom prehook to be executed before every API call
	 * @param prehook Function to execute before API calls
	 */
	public addCustomPrehook(prehook: () => Promise<void> | void): void {
		this.addPrehook(prehook);
	}

	/**
	 * Remove a custom prehook
	 * @param prehook Function to remove from prehooks
	 */
	public removeCustomPrehook(prehook: () => Promise<void> | void): void {
		this.removePrehook(prehook);
	}

	/**
	 * Manually execute all prehooks (useful for debugging)
	 */
	public async executePrehooksManually(): Promise<void> {
		await this.executePrehooks();
	}

	/**
	 * Get the current count of active prehooks
	 */
	public getPrehookCount(): number {
		return this.getDiagnostics().prehooksCount;
	}

	// ================================
	// Getters & Configuration Access
	// ================================

	get config() {
		return this._config;
	}

	get options() {
		return this._options;
	}

	get accessToken(): string | null {
		return this._accessToken;
	}

	get refreshToken(): string | null {
		return this._refreshToken;
	}

	get activeSessionId(): string | null {
		return this._activeSessionId;
	}

	get authStorage(): AuthStorage {
		return this._authStorage;
	}

	get storage(): StorageAdapter {
		return this._storage;
	}

	// ================================
	// Token Management
	// ================================

	/**
	 * Update access token (called by FrankAuth when token changes)
	 */
	set accessToken(token: string | null) {
		this._accessToken = token;
	}

	/**
	 * Update refresh token (called by FrankAuth when token changes)
	 */
	set refreshToken(token: string | null) {
		this._refreshToken = token;
	}

	/**
	 * Reset all tokens
	 */
	resetTokens() {
		this._accessToken = null;
		this._refreshToken = null;
	}

	/**
	 * Update active session (called by FrankAuth when session changes)
	 */
	set activeSession(session: string | null) {
		this._activeSessionId = session;
	}

	/**
	 * Check if user is currently signed in
	 */
	isSignedIn(): boolean {
		return !!this.accessToken;
	}

	// Update access token (called by FrankAuth when token changes)
	setProjectId(id: string): void {
		this._options.projectId = id;
	}

	public getOrganizationId() {
		return this._options.projectId ?? "project-id-not-set";
	}

	public getUserData() {
		return this._options.projectId ?? "project-id-not-set";
	}

	protected get dynamicHeaders() {
		const h = {
			"X-Publishable-Key": this.options.publishableKey,
			"X-User-Type": this._options.userType,
			"Content-Type": "application/json",
		} as Record<string, string>;

		if (this.options.projectId) {
			h["X-Org-ID"] = this.options.projectId;
		}

		if (this.options.secretKey) {
			h["X-API-Key"] = this.options.secretKey;
		}

		if (this._accessToken) {
			h["Authorization"] = `Bearer ${this._accessToken}`;
		}

		return h;
	}

	protected async clearTokens(): Promise<void> {
		this.resetTokens();
		this._authStorage.clearAll();
	}

	protected loadTokensFromStorage(): void {
		this.accessToken = this._authStorage.getAccessToken();
		this.refreshToken = this._authStorage.getRefreshToken();
	}

	protected async saveToStorage(key: string, value: string): Promise<void> {
		this._storage.set(key, value);
	}

	protected async removeFromStorage(key: string): Promise<void> {
		this._storage.remove(key);
	}

	/**
	 * Enhanced helper method to merge dynamic headers with existing initOverrides
	 * This method also executes prehooks before preparing headers
	 */
	protected mergeHeaders(
		initOverrides?: RequestInit | InitOverrideFunction,
	): RequestInit | InitOverrideFunction {
		if (!initOverrides) {
			return {
				headers: this.dynamicHeaders,
				// Add prehook execution as a custom property that will be handled in API calls
				...(this._prehooks.size > 0 && {
					[Symbol.for("executePrehooks")]: () => this.executePrehooks(),
				}),
			};
		}

		if (typeof initOverrides === "function") {
			const originalFn = initOverrides;
			return async (context) => {
				// Execute prehooks before calling the original function
				await this.executePrehooks();
				const result = await originalFn(context);
				return {
					...result,
					headers: {
						...this.dynamicHeaders,
						...result?.headers,
					},
				};
			};
		}

		console.log("initOverrides", JSON.stringify(initOverrides, null, 2));

		return {
			...initOverrides,
			headers: {
				...this.dynamicHeaders,
				...initOverrides.headers,
			},
			// Store prehook execution function for manual execution if needed
			...(this._prehooks.size > 0 && {
				[Symbol.for("executePrehooks")]: () => this.executePrehooks(),
			}),
		};
	}

	/**
	 * Wrapper method for API calls that ensures prehooks are executed
	 * Use this method for all API calls to ensure consistent prehook execution
	 */
	protected async executeApiCall<T>(
		apiCall: () => Promise<T>,
		skipPrehooks = false,
		retryOn401 = true,
	): Promise<T> {
		try {
			// Execute prehooks unless explicitly skipped
			if (!skipPrehooks) {
				await this.executePrehooks();
			}

			// Use retry logic for 401 errors if enabled
			if (retryOn401) {
				return await this.refreshTokenAndRetry(apiCall);
			}
			return await apiCall();
		} catch (error) {
			throw await this.handleError(error);
		}
	}

	/**
	 * Alternative approach: Create a wrapper for the Configuration that automatically executes prehooks
	 */
	protected createConfigWithPrehooks(): Configuration {
		const originalConfig = this._config;

		// Create a proxy that intercepts all method calls
		return new Proxy(originalConfig, {
			get: (target, prop) => {
				const originalMethod = target[prop as keyof Configuration];

				if (typeof originalMethod === "function") {
					return async (...args: any[]) => {
						// Execute prehooks before any API call
						await this.executePrehooks();
						// @ts-ignore
						return originalMethod.apply(target, args);
					};
				}

				return originalMethod;
			},
		});
	}

	private async renewRefreshToken(
		token?: string,
		initOverrides?: RequestInit | InitOverrideFunction,
	): Promise<RefreshTokenResponse> {
		if (!this.refreshToken && !token) {
			throw new FrankAuthError("No refresh token available");
		}

		// Don't use executeApiCall here to avoid recursive 401 handling during token refresh
		try {
			const response = await this.internalAuthApi.refreshToken(
				{
					refreshTokenRequest: {
						refreshToken: (token || this.refreshToken) as any,
					},
				},
				this.mergeHeaders(initOverrides),
			);
			await this.handleAuthResponse(response);
			return response;
		} catch (error) {
			throw await this.handleError(error);
		}
	}

	// Private methods
	protected async handleAuthResponse(response: LoginResponse): Promise<void> {
		if (response.accessToken) {
			this.accessToken = response.accessToken;
			this.authStorage.setAccessToken(response.accessToken);
		}
		if (response.refreshToken) {
			this.refreshToken = response.refreshToken;
			this.authStorage.setRefreshToken(response.refreshToken);
		}
	}

	// ================================
	// Configuration Validation
	// ================================

	/**
	 * Validates the complete Frank Auth configuration
	 */
	public validateConfig(config: FrankAuthConfig): ValidationResult {
		const allErrors: ConfigValidationError[] = [];

		// Validate each configuration field
		allErrors.push(...validatePublishableKey(config.publishableKey));
		allErrors.push(...validateApiUrl(config.apiUrl));
		allErrors.push(...validateUserType(config.userType));
		allErrors.push(...validateSecretKey(config.secretKey));
		allErrors.push(...validateProjectId(config.projectId));
		allErrors.push(...validateStorageKeyPrefix(config.storageKeyPrefix));
		allErrors.push(...validateSessionCookieName(config.sessionCookieName));

		// Validate key consistency (test vs live)
		allErrors.push(...this.validateKeyConsistency(config));

		// Separate errors and warnings
		const errors = allErrors.filter((e) => e.severity === "error");
		const warnings = allErrors.filter((e) => e.severity === "warning");

		return {
			isValid: errors.length === 0,
			errors,
			warnings,
		};
	}

	/**
	 * Validates that publishable and secret keys are consistent (both test or both live)
	 */
	private validateKeyConsistency(
		config: FrankAuthConfig,
	): ConfigValidationError[] {
		const errors: ConfigValidationError[] = [];

		if (!config.secretKey) {
			return errors; // Skip if no secret key provided
		}

		const pubKeyEnv = config.publishableKey.startsWith("pk_test_")
			? "test"
			: config.publishableKey.startsWith("pk_live_")
				? "live"
				: "unknown";
		const secretKeyEnv = config.secretKey.startsWith("sk_test_")
			? "test"
			: config.secretKey.startsWith("sk_live_")
				? "live"
				: "unknown";

		if (
			pubKeyEnv !== secretKeyEnv &&
			pubKeyEnv !== "unknown" &&
			secretKeyEnv !== "unknown"
		) {
			errors.push(
				createError(
					"keyConsistency",
					`Publishable key (${pubKeyEnv}) and secret key (${secretKeyEnv}) environments don't match`,
					{ publishableKey: pubKeyEnv, secretKey: secretKeyEnv },
				),
			);
		}

		return errors;
	}

	/**
	 * Handles validation results - throws on errors, logs warnings
	 */
	private handleValidationResult(result: ValidationResult): void {
		// Log warnings
		if (result.warnings.length > 0) {
			console.warn("Frank Auth Configuration Warnings:", result.warnings);
		}

		// Throw on errors
		if (!result.isValid) {
			const errorMessages = result.errors
				.map((e) => `${e.field}: ${e.message}`)
				.join("\n");
			throw new FrankAuthError(
				`Invalid Frank Auth configuration:\n${errorMessages}`,
				"INVALID_CONFIG",
				{
					originalError: result.errors,
				},
			);
		}
	}

	/**
	 * Re-validates current configuration
	 */
	public revalidateConfig(): ValidationResult {
		return this.validateConfig(this._options);
	}

	/**
	 * Gets the current validation result
	 */
	public getValidationResult(): ValidationResult {
		return this._validationResult;
	}

	/**
	 * Checks if configuration is valid
	 */
	public isConfigValid(): boolean {
		return this._validationResult.isValid;
	}

	/**
	 * Gets configuration warnings
	 */
	public getConfigWarnings(): ConfigValidationError[] {
		return this._validationResult.warnings;
	}

	/**
	 * Gets configuration errors
	 */
	public getConfigErrors(): ConfigValidationError[] {
		return this._validationResult.errors;
	}

	/**
	 * Validates a specific configuration field
	 */
	public validateField(
		field: keyof FrankAuthConfig,
		value: any,
	): ConfigValidationError[] {
		switch (field) {
			case "publishableKey":
				return validatePublishableKey(value);
			case "apiUrl":
				return validateApiUrl(value);
			case "userType":
				return validateUserType(value);
			case "secretKey":
				return validateSecretKey(value);
			case "projectId":
				return validateProjectId(value);
			case "storageKeyPrefix":
				return validateStorageKeyPrefix(value);
			case "sessionCookieName":
				return validateSessionCookieName(value);
			default:
				return [
					createError(field, `Unknown configuration field: ${field}`, value),
				];
		}
	}

	// ================================
	// Environment & Configuration Utilities
	// ================================

	/**
	 * Check if SDK is running in test mode
	 */
	public isTestMode(): boolean {
		return this.options.publishableKey.startsWith("pk_test_");
	}

	/**
	 * Check if SDK is running in live mode
	 */
	public isLiveMode(): boolean {
		return this.options.publishableKey.startsWith("pk_live_");
	}

	/**
	 * Get the current environment (test/live)
	 */
	public getEnvironment(): "test" | "live" | "unknown" {
		if (this.isTestMode()) return "test";
		if (this.isLiveMode()) return "live";
		return "unknown";
	}

	/**
	 * Check if secret key is available (server-side operations)
	 */
	public hasSecretKey(): boolean {
		return !!this.options.secretKey;
	}

	/**
	 * Check if project/organization ID is set
	 */
	public hasProjectId(): boolean {
		return !!this.options.projectId;
	}

	/**
	 * Get sanitized configuration for logging (removes sensitive data)
	 */
	public getSanitizedConfig(): Partial<FrankAuthConfig> {
		return {
			apiUrl: this.options.apiUrl,
			userType: this.options.userType,
			publishableKey: this.options.publishableKey
				? `${this.options.publishableKey.substring(0, 12)}...`
				: undefined,
			secretKey: this.options.secretKey ? "[REDACTED]" : undefined,
			projectId: this.options.projectId,
			storageKeyPrefix: this.options.storageKeyPrefix,
			sessionCookieName: this.options.sessionCookieName,
		};
	}

	// ================================
	// Error Handling
	// ================================

	public handleError(error: any): Promise<FrankAuthError> {
		return convertError(error);
	}

	// ================================
	// Debugging & Diagnostics
	// ================================

	/**
	 * Get diagnostic information about the SDK configuration
	 */
	public getDiagnostics(): {
		isConfigValid: boolean;
		environment: string;
		hasSecretKey: boolean;
		hasProjectId: boolean;
		isSignedIn: boolean;
		validationErrors: ConfigValidationError[];
		validationWarnings: ConfigValidationError[];
		sanitizedConfig: Partial<FrankAuthConfig>;
		prehooksCount: number;
		tokenExpiration: {
			accessToken: TokenExpirationResult;
			refreshToken: TokenExpirationResult;
		};
		tokenRefreshBuffer: number;
		canRefreshTokens: boolean;
	} {
		const tokenExpiration = this.getTokenExpirationInfo();
		const canRefreshTokens =
			this._refreshToken !== null &&
			tokenExpiration.refreshToken.isValid &&
			!tokenExpiration.refreshToken.isExpired;

		return {
			isConfigValid: this.isConfigValid(),
			environment: this.getEnvironment(),
			hasSecretKey: this.hasSecretKey(),
			hasProjectId: this.hasProjectId(),
			isSignedIn: this.isSignedIn(),
			validationErrors: this.getConfigErrors(),
			validationWarnings: this.getConfigWarnings(),
			sanitizedConfig: this.getSanitizedConfig(),
			prehooksCount: this._prehooks.size,
			tokenExpiration,
			tokenRefreshBuffer: this.TOKEN_REFRESH_BUFFER,
			canRefreshTokens,
		};
	}

	/**
	 * Log diagnostic information (useful for debugging)
	 */
	public logDiagnostics(): void {
		const diagnostics = this.getDiagnostics();
		console.log("Frank Auth SDK Diagnostics:", diagnostics);
	}
}
