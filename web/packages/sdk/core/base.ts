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
	type DebugConfig,
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
 * API call debug information
 */
interface ApiCallDebugInfo {
	method: string;
	url: string;
	headers: Record<string, string>;
	timestamp: number;
	requestId: string;
	duration?: number;
	statusCode?: number;
	error?: any;
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
 * Now with enhanced debugging capabilities for API calls, headers, and operations
 */
export class BaseSDK {
	private readonly _storage: StorageManager;
	private readonly _hybridAuthStorage: HybridAuthStorage;
	private readonly _authStorage: AuthStorage;
	private readonly _options: FrankAuthConfig;
	private readonly _config: Configuration;
	private readonly _validationResult: ValidationResult;
	private readonly _prehooks: Set<PrehookFunction> = new Set();
	private readonly _debugConfig: DebugConfig;

	private readonly internalAuthApi: AuthenticationApi;

	private _accessToken: string | null = null;
	private _refreshToken: string | null = null;
	private _activeSessionId: string | null = null;

	// Token expiration buffer (in seconds) - refresh token if it expires within this time
	private readonly TOKEN_REFRESH_BUFFER = 300; // 5 minutes

	// Debug tracking
	private readonly _apiCallHistory: ApiCallDebugInfo[] = [];
	private _requestCounter = 0;

	constructor(config: FrankAuthConfig, accessToken?: string) {
		this._hybridAuthStorage =
			config.storage ??
			new HybridAuthStorage(
				config.storageKeyPrefix ? `${config.storageKeyPrefix}_` : "frank_auth_",
				undefined,
				config.cookieOptions,
			);
		this._authStorage = this._hybridAuthStorage.store;
		this._storage = this._authStorage.adapter;
		this._options = config;
		this._accessToken = accessToken || null;

		// Initialize debug configuration
		this._debugConfig = {
			enabled: config.debug ?? false,
			logLevel: config.debugConfig?.logLevel ?? "info",
			logApiCalls: config.debugConfig?.logApiCalls ?? true,
			logHeaders: config.debugConfig?.logHeaders ?? true,
			logTokens: config.debugConfig?.logTokens ?? false, // Dangerous in production
			logStorage: config.debugConfig?.logStorage ?? true,
			logErrors: config.debugConfig?.logErrors ?? true,
			logPrehooks: config.debugConfig?.logPrehooks ?? false,
			prefix: config.debugConfig?.prefix ?? "[FrankAuth SDK]",
		};

		this.debugLog("info", "Initializing BaseSDK", {
			apiUrl: config.apiUrl,
			publishableKey: this.sanitizeKey(config.publishableKey),
			secretKey: config.secretKey ? "[PRESENT]" : "[NOT SET]",
			userType: config.userType,
			projectId: config.projectId,
			storageKeyPrefix: config.storageKeyPrefix,
			debugEnabled: this._debugConfig.enabled,
		});

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

		if (this._accessToken) {
			headers.Authorization = `Bearer ${this._accessToken}`;
		}

		this.debugLog("debug", "Initial headers configured", {
			headers: this.sanitizeHeaders(headers),
		});

		this._config = new Configuration({
			basePath: config.apiUrl,
			accessToken: () => this.accessToken || "",
			credentials: "include",
			headers,
		});

		this.internalAuthApi = new AuthenticationApi(this.config);

		this._storage.on(AuthStorageUtils.accessTokenKey, () => {
			this.debugLog("debug", "Access token changed in storage");
			this.loadTokensFromStorage();
		});

		this._storage.on(AuthStorageUtils.refreshTokenKey, () => {
			this.debugLog("debug", "Refresh token changed in storage");
			this.loadTokensFromStorage();
		});

		// Add the default prehook to load tokens from storage
		this.addPrehook(() => this.loadTokensFromStorage());

		// Add prehook to check and renew tokens before API calls
		this.addPrehook(() => this.checkAndRenewTokens());

		// Load tokens from storage initially
		this.loadTokensFromStorage();

		this.debugLog("info", "BaseSDK initialization complete");
	}

	// ================================
	// Debug Logging Methods
	// ================================

	/**
	 * Debug logger with configurable levels and formatting
	 */
	private debugLog(
		level: DebugConfig["logLevel"],
		message: string,
		data?: any,
	): void {
		if (!this._debugConfig.enabled) return;

		const logLevels = ["error", "warn", "info", "debug", "verbose"];
		const currentLevelIndex = logLevels.indexOf(this._debugConfig.logLevel);
		const messageLevelIndex = logLevels.indexOf(level);

		if (messageLevelIndex > currentLevelIndex) return;

		const timestamp = new Date().toISOString();
		const prefix = `${this._debugConfig.prefix} [${level.toUpperCase()}] ${timestamp}`;

		if (data) {
			console[level === "error" ? "error" : level === "warn" ? "warn" : "log"](
				`${prefix} ${message}`,
				data,
			);
		} else {
			console[level === "error" ? "error" : level === "warn" ? "warn" : "log"](
				`${prefix} ${message}`,
			);
		}
	}

	/**
	 * Log API call details for debugging
	 */
	private logApiCall(debugInfo: ApiCallDebugInfo): void {
		if (!this._debugConfig.logApiCalls) return;

		this.debugLog("debug", `API Call: ${debugInfo.method} ${debugInfo.url}`, {
			requestId: debugInfo.requestId,
			headers: this._debugConfig.logHeaders
				? this.sanitizeHeaders(debugInfo.headers)
				: "[HIDDEN]",
			timestamp: debugInfo.timestamp,
			duration: debugInfo.duration ? `${debugInfo.duration}ms` : "pending",
			statusCode: debugInfo.statusCode,
		});

		// Store in history for diagnostics
		this._apiCallHistory.push(debugInfo);

		// Keep only last 50 calls to prevent memory issues
		if (this._apiCallHistory.length > 50) {
			this._apiCallHistory.shift();
		}
	}

	/**
	 * Log token operations
	 */
	private logTokenOperation(operation: string, details?: any): void {
		if (!this._debugConfig.logTokens) return;

		this.debugLog("debug", `Token Operation: ${operation}`, details);
	}

	/**
	 * Log storage operations
	 */
	private logStorageOperation(
		operation: string,
		key: string,
		details?: any,
	): void {
		if (!this._debugConfig.logStorage) return;

		this.debugLog("debug", `Storage Operation: ${operation} - ${key}`, details);
	}

	/**
	 * Log prehook execution
	 */
	private logPrehookExecution(count: number, duration?: number): void {
		if (!this._debugConfig.logPrehooks) return;

		this.debugLog("debug", `Executed ${count} prehooks`, {
			duration: duration ? `${duration}ms` : undefined,
		});
	}

	/**
	 * Sanitize headers for logging (remove sensitive data)
	 */
	private sanitizeHeaders(
		headers: Record<string, string>,
	): Record<string, string> {
		const sanitized = { ...headers };

		if (sanitized.Authorization) {
			sanitized.Authorization = sanitized.Authorization.replace(
				/Bearer .+/,
				"Bearer [REDACTED]",
			);
		}

		if (sanitized["X-API-Key"]) {
			sanitized["X-API-Key"] = "[REDACTED]";
		}

		return sanitized;
	}

	/**
	 * Sanitize API key for logging
	 */
	private sanitizeKey(key: string): string {
		if (!key) return "[NOT SET]";
		if (key.length <= 12) return "[REDACTED]";
		return `${key.substring(0, 12)}...`;
	}

	/**
	 * Get API call history for debugging
	 */
	public getApiCallHistory(): ApiCallDebugInfo[] {
		return [...this._apiCallHistory];
	}

	/**
	 * Clear API call history
	 */
	public clearApiCallHistory(): void {
		this._apiCallHistory.length = 0;
		this.debugLog("debug", "API call history cleared");
	}

	/**
	 * Enable/disable debug mode at runtime
	 */
	public setDebugMode(enabled: boolean, config?: Partial<DebugConfig>): void {
		this._debugConfig.enabled = enabled;

		if (config) {
			Object.assign(this._debugConfig, config);
		}

		this.debugLog("info", `Debug mode ${enabled ? "enabled" : "disabled"}`, {
			config: this._debugConfig,
		});
	}

	/**
	 * Get current debug configuration
	 */
	public getDebugConfig(): DebugConfig {
		return { ...this._debugConfig };
	}

	// ================================
	// Enhanced API Call Wrapper
	// ================================

	/**
	 * Enhanced API call wrapper with comprehensive debugging
	 */
	protected async executeApiCallWithDebug<T>(
		apiCall: () => Promise<T>,
		callInfo: {
			method: string;
			endpoint: string;
			skipPrehooks?: boolean;
			retryOn401?: boolean;
			maxRetries?: number;
		},
	): Promise<T> {
		const requestId = `req_${++this._requestCounter}_${Date.now()}`;
		const startTime = Date.now();

		const debugInfo: ApiCallDebugInfo = {
			method: callInfo.method,
			url: `${this._config.basePath}${callInfo.endpoint}`,
			headers: this.dynamicHeaders,
			timestamp: startTime,
			requestId,
		};

		this.logApiCall(debugInfo);

		try {
			// Execute prehooks unless explicitly skipped
			if (!callInfo.skipPrehooks) {
				const prehookStart = Date.now();
				await this.executePrehooks();
				const prehookDuration = Date.now() - prehookStart;
				this.logPrehookExecution(this._prehooks.size, prehookDuration);
			}

			// Execute the actual API call
			let result: T;

			if (callInfo.retryOn401 !== false) {
				result = await this.refreshTokenAndRetry(
					apiCall,
					callInfo.maxRetries || 1,
				);
			} else {
				result = await apiCall();
			}

			// Log successful completion
			const duration = Date.now() - startTime;
			debugInfo.duration = duration;
			debugInfo.statusCode = 200; // Assume success if no error thrown

			this.debugLog(
				"debug",
				`API call completed successfully: ${callInfo.method} ${callInfo.endpoint}`,
				{
					requestId,
					duration: `${duration}ms`,
				},
			);

			return result;
		} catch (error) {
			const duration = Date.now() - startTime;
			debugInfo.duration = duration;
			debugInfo.error = error;

			// Determine status code from error
			if (error && typeof error === "object") {
				debugInfo.statusCode =
					(error as any).status ||
					(error as any).response?.status ||
					(error as any).statusCode ||
					500;
			}

			this.debugLog(
				"error",
				`API call failed: ${callInfo.method} ${callInfo.endpoint}`,
				{
					requestId,
					duration: `${duration}ms`,
					error: {
						message: error instanceof Error ? error.message : "Unknown error",
						status: debugInfo.statusCode,
						stack:
							this._debugConfig.logLevel === "verbose" && error instanceof Error
								? error.stack
								: undefined,
					},
				},
			);

			// Re-log the updated debug info
			this.logApiCall(debugInfo);

			throw await this.handleError(error);
		}
	}

	// ================================
	// Token Expiration & Renewal (Enhanced with Debug)
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
				this.debugLog(
					"warn",
					"Invalid JWT format: token does not have 3 parts",
				);
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
			const parsedPayload = JSON.parse(decoded) as JWTPayload;

			this.debugLog("verbose", "JWT token decoded successfully", {
				exp: parsedPayload.exp,
				iat: parsedPayload.iat,
				hasExpiration: !!parsedPayload.exp,
			});

			return parsedPayload;
		} catch (error) {
			this.debugLog("warn", "Failed to decode JWT token", {
				error: error instanceof Error ? error.message : error,
			});
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
			this.logTokenOperation("checkExpiration", { result: "token_null" });
			return {
				isExpired: true,
				isValid: false,
				error: "Token is null or undefined",
			};
		}

		const payload = this.decodeJWTPayload(token);
		if (!payload) {
			this.logTokenOperation("checkExpiration", { result: "invalid_format" });
			return {
				isExpired: true,
				isValid: false,
				error: "Invalid token format",
			};
		}

		if (!payload.exp) {
			this.logTokenOperation("checkExpiration", { result: "no_expiration" });
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

		this.logTokenOperation("checkExpiration", {
			expiresIn: `${expiresIn}s`,
			isExpired,
			bufferSeconds,
			expiresAt: expiresAt.toISOString(),
		});

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
		this.debugLog("info", "Verifying and renewing refresh token", {
			forceRenew,
		});

		const refreshTokenResult = this.isRefreshTokenExpired();

		if (!refreshTokenResult.isValid) {
			this.debugLog("error", "Invalid refresh token during renewal attempt");
			throw new FrankAuthError(
				"Invalid refresh token",
				"INVALID_REFRESH_TOKEN",
			);
		}

		const shouldRenew = forceRenew || refreshTokenResult.isExpired;

		if (!shouldRenew) {
			this.debugLog("debug", "Refresh token renewal not needed");
			return {
				renewed: false,
				wasExpired: refreshTokenResult.isExpired,
			};
		}

		if (!this._refreshToken) {
			this.debugLog("error", "No refresh token available for renewal");
			throw new FrankAuthError(
				"No refresh token available",
				"NO_REFRESH_TOKEN",
			);
		}

		try {
			this.debugLog("info", "Attempting to renew refresh token");
			const response = await this.renewRefreshToken();

			this.debugLog("info", "Refresh token renewal successful");
			return {
				renewed: true,
				wasExpired: refreshTokenResult.isExpired,
				newTokens: {
					accessToken: response.accessToken || "",
					refreshToken: response.refreshToken || "",
				},
			};
		} catch (error) {
			this.debugLog("error", "Failed to renew refresh token", { error });
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
				this.debugLog("debug", "No tokens available for renewal check");
				return;
			}

			// Check if access token is expired or about to expire
			const accessTokenResult = this.isAccessTokenExpired();

			if (accessTokenResult.isExpired && accessTokenResult.isValid) {
				this.debugLog("info", "Access token expired, attempting renewal");

				// Access token is expired, try to renew using refresh token
				const refreshTokenResult = this.isRefreshTokenExpired();

				if (!refreshTokenResult.isExpired && refreshTokenResult.isValid) {
					// Refresh token is still valid, renew tokens
					await this.verifyAndRenewRefreshToken();
				} else {
					// Both tokens are expired, clear them
					this.debugLog(
						"warn",
						"Both access and refresh tokens expired, clearing tokens",
					);
					// await this.clearTokens();
				}
			} else {
				this.debugLog("verbose", "Access token is still valid");
			}
		} catch (error) {
			this.debugLog("warn", "Failed to check and renew tokens", { error });
			// Don't clear tokens on network errors or temporary failures
			// Only clear on authentication errors (401, 403)
			if (this.isAuthenticationError(error)) {
				// await this.clearTokens();
			}
		}
	}

	// Add helper to identify authentication vs network errors
	private isAuthenticationError(error: any): boolean {
		const status =
			error?.status || error?.response?.status || error?.statusCode;
		return status === 401 || status === 403;
	}

	/**
	 * Get token expiration information
	 * @returns Object with expiration details for both tokens
	 */
	public getTokenExpirationInfo(): {
		accessToken: TokenExpirationResult;
		refreshToken: TokenExpirationResult;
	} {
		const result = {
			accessToken: this.isAccessTokenExpired(),
			refreshToken: this.isRefreshTokenExpired(),
		};

		this.debugLog("verbose", "Token expiration info retrieved", result);
		return result;
	}

	/**
	 * Set token refresh buffer time
	 * @param bufferSeconds Buffer time in seconds
	 */
	public setTokenRefreshBuffer(bufferSeconds: number): void {
		if (bufferSeconds < 0) {
			throw new Error("Token refresh buffer must be non-negative");
		}

		this.debugLog("info", "Token refresh buffer updated", { bufferSeconds });
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

		const result = {
			is401Error: is401,
			isTokenExpired: accessTokenResult.isExpired,
			isRefreshTokenExpired: refreshTokenResult.isExpired,
			recommendedAction,
		};

		this.debugLog("debug", "Token error analysis completed", result);
		return result;
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

				this.debugLog(
					"info",
					`Attempting to handle 401 error (retry ${retryCount + 1}/${maxRetries})`,
				);

				// Attempt to handle 401 error by refreshing token
				const tokenRefreshed = await this.handle401Error(error);

				if (!tokenRefreshed) {
					// If token refresh failed, throw the original error
					throw error;
				}

				retryCount++;
				this.debugLog(
					"info",
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
				this.debugLog(
					"warn",
					"Cannot handle 401 error: no refresh token available",
				);
				return false;
			}

			// Check if refresh token is still valid
			const refreshTokenResult = this.isRefreshTokenExpired();
			if (refreshTokenResult.isExpired || !refreshTokenResult.isValid) {
				// Refresh token is also expired/invalid, clear tokens
				this.debugLog(
					"warn",
					"Cannot handle 401 error: refresh token is expired/invalid",
				);
				// await this.clearTokens();
				return false;
			}

			// Attempt to refresh tokens
			this.debugLog("info", "Attempting to refresh tokens to handle 401 error");
			await this.verifyAndRenewRefreshToken(true); // Force renewal
			return true;
		} catch (refreshError) {
			this.debugLog("error", "Failed to refresh token after 401 error", {
				refreshError,
			});
			// Clear tokens if refresh fails
			// await this.clearTokens();
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
		const is401 =
			error?.status === 401 ||
			error?.response?.status === 401 ||
			error?.statusCode === 401 ||
			(error?.message && error.message.includes("401")) ||
			error?.response?.data?.status === 401;

		if (is401) {
			this.debugLog("debug", "401 error detected", {
				status: error?.status,
				responseStatus: error?.response?.status,
				statusCode: error?.statusCode,
				message: error?.message,
			});
		}

		return is401;
	}

	// ================================
	// Prehook Management (Enhanced with Debug)
	// ================================

	/**
	 * Add a prehook function that will be called before every API request
	 */
	public addPrehook(prehook: PrehookFunction): void {
		this._prehooks.add(prehook);
		this.debugLog("debug", "Prehook added", {
			totalPrehooks: this._prehooks.size,
		});
	}

	/**
	 * Remove a prehook function
	 */
	public removePrehook(prehook: PrehookFunction): void {
		this._prehooks.delete(prehook);
		this.debugLog("debug", "Prehook removed", {
			totalPrehooks: this._prehooks.size,
		});
	}

	/**
	 * Clear all prehooks
	 */
	public clearPrehooks(): void {
		const count = this._prehooks.size;
		this._prehooks.clear();
		this.debugLog("debug", "All prehooks cleared", { previousCount: count });
	}

	/**
	 * Execute all prehooks
	 */
	protected async executePrehooks(): Promise<void> {
		if (this._prehooks.size === 0) return;

		const startTime = Date.now();
		this.debugLog("verbose", `Executing ${this._prehooks.size} prehooks`);

		for (const prehook of this._prehooks) {
			try {
				await prehook();
			} catch (error) {
				this.debugLog("error", "Prehook execution failed", { error });
				throw error;
			}
		}

		const duration = Date.now() - startTime;
		this.logPrehookExecution(this._prehooks.size, duration);
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
		return this._prehooks.size;
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
	// Token Management (Enhanced with Debug)
	// ================================

	/**
	 * Update access token (called by FrankAuth when token changes)
	 */
	set accessToken(token: string | null) {
		const changed = this._accessToken !== token;
		this._accessToken = token;

		if (changed) {
			this.logTokenOperation("accessToken.set", {
				hasToken: !!token,
				tokenPrefix: token ? this.sanitizeKey(token) : null,
			});
		}
	}

	/**
	 * Update refresh token (called by FrankAuth when token changes)
	 */
	set refreshToken(token: string | null) {
		const changed = this._refreshToken !== token;
		this._refreshToken = token;

		if (changed) {
			this.logTokenOperation("refreshToken.set", {
				hasToken: !!token,
				tokenPrefix: token ? this.sanitizeKey(token) : null,
			});
		}
	}

	/**
	 * Reset all tokens
	 */
	resetTokens() {
		this.logTokenOperation("resetTokens");
		this._accessToken = null;
		this._refreshToken = null;
	}

	/**
	 * Update active session (called by FrankAuth when session changes)
	 */
	set activeSession(session: string | null) {
		const changed = this._activeSessionId !== session;
		this._activeSessionId = session;

		if (changed) {
			this.debugLog("debug", "Active session updated", {
				hasSession: !!session,
				sessionId: session ? `${session.substring(0, 8)}...` : null,
			});
		}
	}

	/**
	 * Check if user is currently signed in
	 */
	isSignedIn(): boolean {
		const signedIn = !!this.accessToken;
		this.debugLog("verbose", "Sign-in status checked", {
			isSignedIn: signedIn,
		});
		return signedIn;
	}

	// Update access token (called by FrankAuth when token changes)
	setProjectId(id: string): void {
		this._options.projectId = id;
		this.debugLog("debug", "Project ID updated", { projectId: id });
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
			h.Authorization = `Bearer ${this._accessToken}`;
		}

		return h;
	}

	protected async clearTokens(): Promise<void> {
		this.logTokenOperation("clearTokens");
		this.resetTokens();
		// this._authStorage.clearAll();
		this._authStorage.removeAccessToken();
		this._authStorage.removeRefreshToken();
		this._authStorage.removeSessionId();
	}

	// Add a method for complete sign out
	protected async clearAllAuthData(): Promise<void> {
		this.logTokenOperation("clearAllAuthData");
		this.resetTokens();
		this._authStorage.clearAll();
	}

	protected loadTokensFromStorage(): void {
		const accessToken = this._authStorage.getAccessToken();
		const refreshToken = this._authStorage.getRefreshToken();

		this.logStorageOperation("loadTokens", "tokens", {
			hasAccessToken: !!accessToken,
			hasRefreshToken: !!refreshToken,
		});

		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	protected async saveToStorage(key: string, value: string): Promise<void> {
		this.logStorageOperation("save", key);
		this._storage.set(key, value);
	}

	protected async removeFromStorage(key: string): Promise<void> {
		this.logStorageOperation("remove", key);
		this._storage.remove(key);
	}

	/**
	 * Enhanced helper method to merge dynamic headers with existing initOverrides
	 * This method also executes prehooks before preparing headers
	 */
	protected mergeHeaders(
		initOverrides?: RequestInit | InitOverrideFunction,
	): RequestInit | InitOverrideFunction {
		const headers = this.dynamicHeaders;

		this.debugLog("verbose", "Merging headers", {
			headers: this.sanitizeHeaders(headers),
			hasOverrides: !!initOverrides,
		});

		if (!initOverrides) {
			return {
				headers,
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
						...headers,
						...result?.headers,
					},
				};
			};
		}

		return {
			...initOverrides,
			headers: {
				...headers,
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
			this.debugLog("info", "Renewing refresh token");

			const response = await this.internalAuthApi.refreshToken(
				{
					refreshTokenRequest: {
						refreshToken: (token || this.refreshToken) as any,
					},
				},
				this.mergeHeaders(initOverrides),
			);

			await this.handleAuthResponse(response);
			this.debugLog("info", "Refresh token renewal completed successfully");
			return response;
		} catch (error) {
			this.debugLog("error", "Refresh token renewal failed", { error });
			throw await this.handleError(error);
		}
	}

	// Private methods
	protected async handleAuthResponse(response: LoginResponse): Promise<void> {
		this.debugLog("debug", "Handling auth response", {
			hasAccessToken: !!response.accessToken,
			hasRefreshToken: !!response.refreshToken,
		});

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

		const result = {
			isValid: errors.length === 0,
			errors,
			warnings,
		};

		this.debugLog("debug", "Configuration validation completed", {
			isValid: result.isValid,
			errorCount: errors.length,
			warningCount: warnings.length,
		});

		return result;
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
			: config.publishableKey.startsWith("pk_live_") ||
					config.publishableKey.startsWith("pk_standalone_")
				? "live"
				: "unknown";
		const secretKeyEnv = config.secretKey.startsWith("sk_test_")
			? "test"
			: config.secretKey.startsWith("sk_live_") ||
					config.secretKey.startsWith("sk_standalone_")
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
			this.debugLog(
				"warn",
				"Frank Auth Configuration Warnings",
				result.warnings,
			);
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
			debug: this.options.debug,
			debugConfig: this.options.debugConfig,
		};
	}

	// ================================
	// Error Handling (Enhanced with Debug)
	// ================================

	public async handleError(error: any): Promise<FrankAuthError> {
		if (this._debugConfig.logErrors) {
			this.debugLog("error", "Handling error", {
				message: error instanceof Error ? error.message : "Unknown error",
				status: error?.status || error?.response?.status || error?.statusCode,
				stack:
					this._debugConfig.logLevel === "verbose" && error instanceof Error
						? error.stack
						: undefined,
			});
		}

		return convertError(error);
	}

	// ================================
	// Enhanced Debugging & Diagnostics
	// ================================

	/**
	 * Get enhanced diagnostic information about the SDK configuration
	 */
	public getDiagnostics(): DiagnosisResult {
		const tokenExpiration = this.getTokenExpirationInfo();
		const canRefreshTokens =
			this._refreshToken !== null &&
			tokenExpiration.refreshToken.isValid &&
			!tokenExpiration.refreshToken.isExpired;

		// Calculate performance metrics
		const totalApiCalls = this._apiCallHistory.length;
		const completedCalls = this._apiCallHistory.filter(
			(call) => call.duration !== undefined,
		);
		const averageResponseTime =
			completedCalls.length > 0
				? Math.round(
						completedCalls.reduce(
							(sum, call) => sum + (call.duration || 0),
							0,
						) / completedCalls.length,
					)
				: 0;
		const errorCalls = this._apiCallHistory.filter((call) => call.error);
		const errorRate =
			totalApiCalls > 0
				? Math.round((errorCalls.length / totalApiCalls) * 100)
				: 0;

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
			debugConfig: this._debugConfig,
			apiCallHistory: this.getApiCallHistory(),
			performance: {
				totalApiCalls,
				averageResponseTime,
				errorRate,
			},
		};
	}

	/**
	 * Log comprehensive diagnostic information (useful for debugging)
	 */
	public logDiagnostics(): void {
		const diagnostics = this.getDiagnostics();
		this.debugLog("info", "Frank Auth SDK Diagnostics", diagnostics);
	}

	/**
	 * Get performance metrics for API calls
	 */
	public getPerformanceMetrics(): PerfResult {
		const calls = this._apiCallHistory;
		const completedCalls = calls.filter((call) => call.duration !== undefined);
		const errorCalls = calls.filter((call) => call.error);
		const successfulCalls = calls.filter(
			(call) => !call.error && call.duration !== undefined,
		);

		const averageResponseTime =
			completedCalls.length > 0
				? Math.round(
						completedCalls.reduce(
							(sum, call) => sum + (call.duration || 0),
							0,
						) / completedCalls.length,
					)
				: 0;

		const slowestCall = completedCalls.reduce(
			(slowest, call) =>
				!slowest || (call.duration || 0) > (slowest.duration || 0)
					? call
					: slowest,
			undefined as ApiCallDebugInfo | undefined,
		);

		const fastestCall = completedCalls.reduce(
			(fastest, call) =>
				!fastest || (call.duration || 0) < (fastest.duration || 0)
					? call
					: fastest,
			undefined as ApiCallDebugInfo | undefined,
		);

		const recentErrors = errorCalls
			.sort((a, b) => b.timestamp - a.timestamp)
			.slice(0, 5);

		return {
			totalCalls: calls.length,
			successfulCalls: successfulCalls.length,
			errorCalls: errorCalls.length,
			averageResponseTime,
			errorRate:
				calls.length > 0
					? Math.round((errorCalls.length / calls.length) * 100)
					: 0,
			slowestCall,
			fastestCall,
			recentErrors,
		};
	}

	/**
	 * Generate a debug report for troubleshooting
	 */
	public generateDebugReport(): string {
		const diagnostics = this.getDiagnostics();
		const performance = this.getPerformanceMetrics();
		const timestamp = new Date().toISOString();

		return `
# Frank Auth SDK Debug Report
Generated: ${timestamp}

## Configuration
- Environment: ${diagnostics.environment}
- API URL: ${diagnostics.sanitizedConfig.apiUrl}
- User Type: ${diagnostics.sanitizedConfig.userType}
- Project ID: ${diagnostics.sanitizedConfig.projectId || "Not set"}
- Debug Enabled: ${diagnostics.debugConfig.enabled}
- Config Valid: ${diagnostics.isConfigValid}

## Authentication Status
- Is Signed In: ${diagnostics.isSignedIn}
- Has Secret Key: ${diagnostics.hasSecretKey}
- Can Refresh Tokens: ${diagnostics.canRefreshTokens}
- Access Token Expired: ${diagnostics.tokenExpiration.accessToken.isExpired}
- Refresh Token Expired: ${diagnostics.tokenExpiration.refreshToken.isExpired}

## Performance Metrics
- Total API Calls: ${performance.totalCalls}
- Successful Calls: ${performance.successfulCalls}
- Error Calls: ${performance.errorCalls}
- Error Rate: ${performance.errorRate}%
- Average Response Time: ${performance.averageResponseTime}ms

## Prehooks
- Active Prehooks: ${diagnostics.prehooksCount}

## Configuration Issues
${
	diagnostics.validationErrors.length > 0
		? `Errors:\n${diagnostics.validationErrors.map((e) => `- ${e.field}: ${e.message}`).join("\n")}`
		: "No configuration errors"
}

${
	diagnostics.validationWarnings.length > 0
		? `Warnings:\n${diagnostics.validationWarnings.map((w) => `- ${w.field}: ${w.message}`).join("\n")}`
		: "No configuration warnings"
}

## Recent Errors
${
	performance.recentErrors.length > 0
		? performance.recentErrors
				.map(
					(error) =>
						`- ${error.method} ${error.url}: ${error.error?.message || "Unknown error"} (${new Date(error.timestamp).toISOString()})`,
				)
				.join("\n")
		: "No recent errors"
}
`.trim();
	}

	/**
	 * Export debug data for external analysis
	 */
	public exportDebugData(): {
		timestamp: string;
		diagnostics: DiagnosisResult;
		performance: PerfResult;
		apiCallHistory: ApiCallDebugInfo[];
		sdkVersion?: string;
	} {
		return {
			timestamp: new Date().toISOString(),
			diagnostics: this.getDiagnostics(),
			performance: this.getPerformanceMetrics(),
			apiCallHistory: this.getApiCallHistory(),
			sdkVersion: "1.0.0", // This should be injected at build time
		};
	}
}

interface DiagnosisResult {
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
	debugConfig: DebugConfig;
	apiCallHistory: ApiCallDebugInfo[];
	performance: {
		totalApiCalls: number;
		averageResponseTime: number;
		errorRate: number;
	};
}

interface PerfResult {
	totalCalls: number;
	successfulCalls: number;
	errorCalls: number;
	averageResponseTime: number;
	errorRate: number;
	slowestCall?: ApiCallDebugInfo;
	fastestCall?: ApiCallDebugInfo;
	recentErrors: ApiCallDebugInfo[];
}
