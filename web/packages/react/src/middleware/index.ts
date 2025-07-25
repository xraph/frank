// packages/react/src/middleware/index.ts
/**
 * @frank-auth/react - Next.js Middleware Plugin
 *
 * Comprehensive middleware solution for Next.js applications using Frank Auth.
 * Provides authentication routing, session management, and path protection.
 * Now integrated with the storage system for consistent token management.
 */

import type { AuthStatus, Session, User, UserType } from "@frank-auth/client";
import {
	AuthSDK,
	NextJSCookieContext,
	createHybridAuthStorage,
} from "@frank-auth/sdk";
import { NextRequest, NextResponse } from "next/server";
import type { FrankAuthConfig } from "../types";

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface MiddlewareConfig
	extends Omit<FrankAuthConfig, "enableDevMode"> {
	storageKeyPrefix?: string;
	sessionCookieName?: string;
	userType?: UserType;
	projectId?: string;
	secretKey?: string;

	/**
	 * Paths that are publicly accessible without authentication
	 * @default ['/sign-in', '/sign-up', '/forgot-password']
	 */
	publicPaths?: string[];

	/**
	 * Paths that require authentication (when allPathsPrivate is false)
	 * @default []
	 */
	privatePaths?: string[];

	/**
	 * Whether all paths are private by default (recommended)
	 * @default true
	 */
	allPathsPrivate?: boolean;

	/**
	 * Path to redirect to for sign in
	 * @default '/sign-in'
	 */
	signInPath?: string;

	/**
	 * Path to redirect to for sign up
	 * @default '/sign-up'
	 */
	signUpPath?: string;

	/**
	 * Path to redirect to after successful sign in
	 * @default '/dashboard'
	 */
	afterSignInPath?: string;

	/**
	 * Path to redirect to after successful sign up
	 * @default '/dashboard'
	 */
	afterSignUpPath?: string;

	/**
	 * Path to redirect to after sign out
	 * @default '/'
	 */
	afterSignOutPath?: string;

	/**
	 * Organization selection path for multi-tenant apps
	 * @default '/select-organization'
	 */
	orgSelectionPath?: string;

	/**
	 * Custom matcher function for protected routes
	 */
	matcher?: (path: string) => boolean;

	/**
	 * Enable debug logging
	 * @default false
	 */
	debug?: boolean;

	/**
	 * Custom domain for organization detection
	 */
	customDomain?: string;

	/**
	 * Enable organization-based routing
	 * @default false
	 */
	enableOrgRouting?: boolean;

	/**
	 * Ignore paths (will not be processed by middleware)
	 * @default ['/api', '/_next', '/favicon.ico']
	 */
	ignorePaths?: string[];

	/**
	 * Cookie options for session management
	 */
	cookieOptions?: {
		secure?: boolean;
		httpOnly?: boolean;
		sameSite?: "strict" | "lax" | "none";
		domain?: string;
		maxAge?: number;
	};

	/**
	 * Custom hooks for middleware lifecycle
	 */
	hooks?: MiddlewareHooks;

	/**
	 * Skip API calls on network errors (useful for development)
	 * @default false
	 */
	skipApiCallOnNetworkError?: boolean;

	/**
	 * Maximum number of retries for API calls
	 * @default 2
	 */
	maxRetries?: number;

	/**
	 * Timeout for API calls in milliseconds
	 * @default 5000
	 */
	apiTimeout?: number;

	/**
	 * Fallback to local token validation on network errors
	 * @default true
	 */
	fallbackToLocalTokens?: boolean;

	/**
	 * Custom API endpoint override for testing
	 */
	customApiEndpoint?: string;

	/**
	 * Enable offline mode (skip all API calls)
	 * @default false
	 */
	offlineMode?: boolean;
}

export interface MiddlewareHooks {
	/**
	 * Called before authentication check
	 */
	beforeAuth?: (req: NextRequest) => Promise<NextRequest | NextResponse>;

	/**
	 * Called after authentication check
	 */
	afterAuth?: (
		req: NextRequest,
		res: NextResponse,
		auth: AuthResult,
	) => Promise<NextRequest | NextResponse>;

	/**
	 * Called when user is authenticated
	 */
	onAuthenticated?: (
		req: NextRequest,
		user: User,
		session: Session,
	) => Promise<NextRequest | NextResponse>;

	/**
	 * Called when user is not authenticated
	 */
	onUnauthenticated?: (req: NextRequest) => Promise<NextRequest | NextResponse>;

	/**
	 * Called when organization is required but not selected
	 */
	onOrganizationRequired?: (
		req: NextRequest,
		user: User,
	) => Promise<NextRequest | NextResponse>;

	/**
	 * Called on authentication error
	 */
	onError?: (
		req: NextRequest,
		error: Error,
	) => Promise<NextRequest | NextResponse>;
}

export interface AuthResult {
	isAuthenticated: boolean;
	user: User | null;
	session: Session | null;
	organizationId: string | null;
	error: Error | null;
	tokenInfo?: {
		accessTokenExpired: boolean;
		refreshTokenExpired: boolean;
		canRefresh: boolean;
	};
}

export interface MiddlewareContext {
	req: NextRequest;
	config: Required<MiddlewareConfig>;
	auth: AuthResult;
	authSDK: AuthSDK;
	path: string;
	isPublicPath: boolean;
	isPrivatePath: boolean;
	isAuthPath: boolean;
	response: NextResponse;
}

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_MIDDLEWARE_CONFIG: Partial<MiddlewareConfig> = {
	apiUrl: "http://localhost:8990",
	sessionCookieName: "frank_sid",
	storageKeyPrefix: "frank_auth_",
	publicPaths: [
		"/sign-in",
		"/sign-up",
		"/forgot-password",
		"/verify-email",
		"/reset-password",
	],
	privatePaths: [],
	skipApiCallOnNetworkError: false,
	maxRetries: 2,
	apiTimeout: 5000,
	fallbackToLocalTokens: true,
	offlineMode: false,
	allPathsPrivate: true,
	signInPath: "/sign-in",
	signUpPath: "/sign-up",
	afterSignInPath: "/dashboard",
	afterSignUpPath: "/dashboard",
	afterSignOutPath: "/",
	orgSelectionPath: "/select-organization",
	debug: false,
	enableOrgRouting: false,
	ignorePaths: [
		"/api",
		"/_next",
		"/favicon.ico",
		"/images",
		"/static",
		"/_vercel",
	],
	cookieOptions: {
		secure: process.env.NODE_ENV === "production",
		httpOnly: true,
		sameSite: "lax",
		maxAge: 60 * 60 * 24 * 7, // 7 days
	},
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if a path matches any of the patterns
 */
function matchesPath(path: string, patterns: string[]): boolean {
	return patterns.some((pattern) => {
		if (pattern === path) return true;
		if (pattern.endsWith("*")) {
			const prefix = pattern.slice(0, -1);
			return path.startsWith(prefix);
		}
		if (pattern.startsWith("/") && pattern.endsWith("/")) {
			const regex = new RegExp(pattern.slice(1, -1));
			return regex.test(path);
		}
		return false;
	});
}

/**
 * Create a NextJS cookie context from request and response
 */
function createCookieContext(
	req: NextRequest,
	response: NextResponse,
	config: Required<MiddlewareConfig>,
): NextJSCookieContext {
	// Create a proper request object with cookies
	const cookies = req.cookies.getAll();
	const cookieReq = {
		cookies: {
			...Object.fromEntries(
				cookies.map((cookie) => [cookie.name, cookie.value]),
			),
			// Also provide a get method for Next.js cookie compatibility
			get: (name: string) => req.cookies.get(name),
			getAll: () => req.cookies.getAll(),
		},
	};

	// Create a response object that can handle Set-Cookie headers
	const cookieRes = {
		setHeader: (name: string, value: string | string[]) => {
			if (name === "Set-Cookie") {
				const cookies = Array.isArray(value) ? value : [value];
				for (const cookie of cookies) {
					// Parse the cookie string properly
					const [nameValue, ...optionParts] = cookie.split(";");
					const [cookieName, cookieValue] = nameValue.split("=");

					if (cookieName && cookieValue) {
						// Parse cookie options
						const options: any = {
							httpOnly: config.cookieOptions.httpOnly,
							secure: config.cookieOptions.secure,
							sameSite: config.cookieOptions.sameSite,
							maxAge: config.cookieOptions.maxAge,
							path: "/", // Ensure path is set
						};

						// Override with parsed options
						for (const optionPart of optionParts) {
							const [key, val] = optionPart.trim().split("=");
							switch (key.toLowerCase()) {
								case "max-age":
									options.maxAge = Number.parseInt(val, 10);
									break;
								case "expires":
									options.expires = new Date(val);
									break;
								case "path":
									options.path = val;
									break;
								case "domain":
									options.domain = val;
									break;
								case "secure":
									options.secure = true;
									break;
								case "httponly":
									options.httpOnly = true;
									break;
								case "samesite":
									options.sameSite = val as "strict" | "lax" | "none";
									break;
							}
						}

						// Set the cookie on the response
						response.cookies.set(
							cookieName.trim(),
							cookieValue.trim(),
							options,
						);
					}
				}
			} else {
				// Handle other headers
				response.headers.set(
					name,
					Array.isArray(value) ? value.join(", ") : value,
				);
			}
		},
		getHeader: (name: string) => {
			return response.headers.get(name);
		},
	};

	return new NextJSCookieContext(cookieReq, cookieRes);
}

/**
 * Create AuthSDK instance with proper storage and cookie context
 */
function createAuthSDK(
	config: Required<MiddlewareConfig>,
	req: NextRequest,
	response: NextResponse,
): AuthSDK {
	// Create cookie context
	const cookieContext = createCookieContext(req, response, config);

	// Create hybrid storage that works in server context
	const hybridStorage = createHybridAuthStorage(config.storageKeyPrefix, {
		req,
		res: {
			setHeader: (name: string, value: string | string[]) => {
				if (name === "Set-Cookie") {
					const cookies = Array.isArray(value) ? value : [value];
					for (const cookie of cookies) {
						// Parse and set cookies properly
						const [nameValue, ...optionParts] = cookie.split(";");
						const [cookieName, cookieValue] = nameValue.split("=");

						if (cookieName && cookieValue) {
							const options: any = {
								httpOnly: config.cookieOptions.httpOnly,
								secure: config.cookieOptions.secure,
								sameSite: config.cookieOptions.sameSite,
								maxAge: config.cookieOptions.maxAge,
							};

							// Parse additional options from cookie string
							for (const optionPart of optionParts) {
								const [key, val] = optionPart.trim().split("=");
								switch (key.toLowerCase()) {
									case "max-age":
										options.maxAge = Number.parseInt(val, 10);
										break;
									case "expires":
										options.expires = new Date(val);
										break;
									case "path":
										options.path = val;
										break;
									case "domain":
										options.domain = val;
										break;
									case "secure":
										options.secure = true;
										break;
									case "httponly":
										options.httpOnly = true;
										break;
									case "samesite":
										options.sameSite = val as "strict" | "lax" | "none";
										break;
								}
							}

							response.cookies.set(
								cookieName.trim(),
								cookieValue.trim(),
								options,
							);
						}
					}
				} else {
					response.headers.set(
						name,
						Array.isArray(value) ? value.join(", ") : value,
					);
				}
			},
			getHeader: (name: string) => {
				return response.headers.get(name);
			},
		},
	});

	debugLog(config, "Storage tokens:", {
		accessToken: hybridStorage.getAccessToken() ? "[PRESENT]" : "[MISSING]",
		refreshToken: hybridStorage.getRefreshToken() ? "[PRESENT]" : "[MISSING]",
		sessionId: hybridStorage.getSessionId() ? "[PRESENT]" : "[MISSING]",
		storageKeyPrefix: config.storageKeyPrefix,
		userType: config.userType,
		projectId: config.projectId,
		secretKey: config.secretKey,
		apiUrl: config.apiUrl,
	});

	// Create AuthSDK with proper configuration
	const authSDK = new AuthSDK({
		apiUrl: config.apiUrl,
		publishableKey: config.publishableKey,
		sessionCookieName: config.sessionCookieName,
		storageKeyPrefix: config.storageKeyPrefix,
		userType: config.userType,
		projectId: config.projectId,
		secretKey: config.secretKey,
		storage: hybridStorage,
		debug: config.debug,
		debugConfig: {
			logLevel: "debug",
		},
	});

	return authSDK;
}

/**
 * authentication validation using AuthSDK
 */
async function validateAuthentication(
	req: NextRequest,
	authSDK: AuthSDK,
	config: Required<MiddlewareConfig>,
): Promise<AuthResult> {
	try {
		debugLog(config, "Validating authentication using AuthSDK");

		// First check if we have tokens locally
		const hasAccessToken = !!authSDK.authStorage.getAccessToken();
		const hasRefreshToken = !!authSDK.authStorage.getRefreshToken();

		debugLog(config, "Local token status:", {
			hasAccessToken,
			hasRefreshToken,
		});

		// If no tokens at all, return unauthenticated immediately
		if (!hasAccessToken && !hasRefreshToken) {
			debugLog(config, "No tokens found, skipping API call");
			return {
				isAuthenticated: false,
				user: null,
				session: null,
				organizationId: null,
				error: null,
				tokenInfo: {
					accessTokenExpired: true,
					refreshTokenExpired: true,
					canRefresh: false,
				},
			};
		}

		// Get token expiration info
		const tokenInfo = authSDK.getTokenExpirationInfo();

		debugLog(config, "Token expiration info:", {
			accessToken: {
				isExpired: tokenInfo.accessToken.isExpired,
				expiresIn: tokenInfo.accessToken.expiresIn,
			},
			refreshToken: {
				isExpired: tokenInfo.refreshToken.isExpired,
				expiresIn: tokenInfo.refreshToken.expiresIn,
			},
		});

		// Skip API call if running in development mode with network issues**
		if (
			config.skipApiCallOnNetworkError &&
			process.env.NODE_ENV === "development"
		) {
			debugLog(
				config,
				"Skipping API call due to development mode network configuration",
			);

			// Trust local tokens if they exist and aren't expired
			if (hasAccessToken && !tokenInfo.accessToken.isExpired) {
				return {
					isAuthenticated: true,
					user: null, // We don't have user data without API call
					session: null,
					organizationId: config.projectId || null,
					error: null,
					tokenInfo: {
						accessTokenExpired: tokenInfo.accessToken.isExpired,
						refreshTokenExpired: tokenInfo.refreshToken.isExpired,
						canRefresh: !tokenInfo.refreshToken.isExpired,
					},
				};
			}
		}

		//  Enhanced request configuration**
		const authStatusWithTimeout = async (): Promise<AuthStatus> => {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 5000); // Reduced timeout

			try {
				//  Add proper headers and fetch configuration**
				const authStatus = await authSDK.getAuthStatus({
					signal: controller.signal,
					headers: {
						"User-Agent": "FrankAuth-Middleware/1.0",
						Accept: "application/json",
						"Content-Type": "application/json",
						// Copy essential headers only
						"X-Forwarded-For": req.headers.get("x-forwarded-for") || "",
						"X-Real-IP": req.headers.get("x-real-ip") || "",
					},
					// Add retry configuration**
					cache: "no-cache",
					keepalive: false,
				});
				clearTimeout(timeoutId);
				return authStatus;
			} catch (error) {
				clearTimeout(timeoutId);
				throw error;
			}
		};

		// Enhanced retry logic with exponential backoff**
		let authStatus: AuthStatus;
		let lastError: Error | null = null;
		const maxRetries = config.maxRetries || 2; // Reduced retries

		for (let attempt = 1; attempt <= maxRetries; attempt++) {
			try {
				debugLog(config, `Auth status attempt ${attempt}/${maxRetries}`);
				authStatus = await authStatusWithTimeout();
				break; // Success, exit retry loop
			} catch (error: any) {
				lastError = error as Error;
				debugLog(config, `Auth status attempt ${attempt} failed:`, {
					name: error.name,
					message: error.message,
					code: error.code,
				});

				//  More intelligent retry logic**
				if (attempt === maxRetries) {
					// Last attempt failed - check if we can fall back to local tokens
					if (hasAccessToken && !tokenInfo.accessToken.isExpired) {
						debugLog(
							config,
							"API failed but local token is valid, trusting local state",
						);
						return {
							isAuthenticated: true,
							user: null,
							session: null,
							organizationId: config.projectId || null,
							error: error as Error,
							tokenInfo: {
								accessTokenExpired: tokenInfo.accessToken.isExpired,
								refreshTokenExpired: tokenInfo.refreshToken.isExpired,
								canRefresh: !tokenInfo.refreshToken.isExpired,
							},
						};
					}
					throw error;
				}

				// Don't retry on certain error types
				if (!isRetryableError(error)) {
					throw error;
				}

				// Exponential backoff with jitter
				const backoffMs = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
				const jitter = Math.random() * 0.1 * backoffMs;
				await new Promise((resolve) => setTimeout(resolve, backoffMs + jitter));
			}
		}

		debugLog(config, "Auth status received:", {
			isAuthenticated: authStatus!.isAuthenticated,
			hasUser: !!authStatus!.user,
			organizationId: authStatus!.organizationId,
		});

		return {
			isAuthenticated: authStatus!.isAuthenticated,
			user: authStatus!.user || null,
			session: authStatus!.session || null,
			organizationId: authStatus!.organizationId || null,
			error: null,
			tokenInfo: {
				accessTokenExpired: tokenInfo.accessToken.isExpired,
				refreshTokenExpired: tokenInfo.refreshToken.isExpired,
				canRefresh: !tokenInfo.refreshToken.isExpired,
			},
		};
	} catch (error) {
		debugLog(config, "Authentication validation error:", {
			name: error.name,
			message: error.message,
			code: error.code,
		});

		// **FIX 7: Better error handling - don't mark tokens as expired on network errors**
		const tokenInfo = authSDK.getTokenExpirationInfo();

		return {
			isAuthenticated: false,
			user: null,
			session: null,
			organizationId: null,
			error: error as Error,
			tokenInfo: {
				// Don't mark tokens as expired just because of network errors
				accessTokenExpired: tokenInfo.accessToken.isExpired,
				refreshTokenExpired: tokenInfo.refreshToken.isExpired,
				canRefresh:
					!tokenInfo.refreshToken.isExpired && tokenInfo.refreshToken.isValid,
			},
		};
	}
}

//  Enhanced error type checking**
function isRetryableError(error: any): boolean {
	const retryableErrors = [
		"NETWORK_ERROR",
		"ECONNREFUSED",
		"ENOTFOUND",
		"ECONNRESET",
		"ETIMEDOUT",
		"AbortError",
	];

	return (
		(error?.code && retryableErrors.includes(error.code)) ||
		error?.name === "FrankAuthNetworkError" ||
		error?.message?.includes("fetch failed") ||
		error?.message?.includes("network") ||
		error?.name === "AbortError"
	);
}

function isNetworkError(error: any): boolean {
	return (
		error?.name === "FrankAuthNetworkError" ||
		error?.code === "NETWORK_ERROR" ||
		error?.message?.includes("fetch failed") ||
		error?.message?.includes("network") ||
		error?.message?.includes("interceptors did not return") ||
		error?.cause?.code === "ECONNREFUSED" ||
		error?.cause?.code === "ENOTFOUND" ||
		error?.cause?.code === "ECONNRESET" ||
		error?.cause?.code === "ETIMEDOUT" ||
		error?.name === "AbortError"
	);
}

/**
 * Extract organization from subdomain or custom domain
 */
function extractOrganization(
	req: NextRequest,
	config: Required<MiddlewareConfig>,
): string | null {
	if (!config.enableOrgRouting) return null;

	const hostname = req.nextUrl.hostname;

	if (config.customDomain && hostname === config.customDomain) {
		return req.nextUrl.searchParams.get("org") || null;
	}

	const parts = hostname.split(".");
	if (parts.length > 2) {
		return parts[0];
	}

	return null;
}

/**
 * Debug logger
 */
function debugLog(
	config: Required<MiddlewareConfig>,
	message: string,
	data?: any,
) {
	if (config.debug) {
		console.log(`[FrankAuth Middleware] ${message}`, data ? data : "");
	}
}

// ============================================================================
// Core Middleware Logic
// ============================================================================

/**
 * Process authentication and routing
 */
async function processRequest(
	req: NextRequest,
	config: Required<MiddlewareConfig>,
): Promise<NextResponse> {
	const path = req.nextUrl.pathname;

	debugLog(config, `Processing request: ${path}`);

	// Check if path should be ignored
	if (matchesPath(path, config.ignorePaths)) {
		debugLog(config, `Ignoring path: ${path}`);
		return NextResponse.next();
	}

	// Create response early to capture all cookies and headers
	const response = NextResponse.next();

	// Execute beforeAuth hook
	if (config.hooks?.beforeAuth) {
		const hookResult = await config.hooks.beforeAuth(req);
		if (hookResult instanceof NextResponse) return hookResult;
		if (hookResult instanceof NextRequest) req = hookResult;
	}

	// Create AuthSDK instance with proper storage context
	const authSDK = createAuthSDK(config, req, response);

	// Determine path types
	const isPublicPath = matchesPath(path, config.publicPaths);
	const isAuthPath = path === config.signInPath || path === config.signUpPath;

	// Determine if path is private based on configuration
	let isPrivatePath: boolean;
	if (config.allPathsPrivate) {
		isPrivatePath = !isPublicPath && !isAuthPath;
	} else {
		isPrivatePath = matchesPath(path, config.privatePaths);
	}

	debugLog(config, "Path analysis:", {
		isPublicPath,
		isPrivatePath,
		isAuthPath,
		allPathsPrivate: config.allPathsPrivate,
	});

	// Validate authentication using AuthSDK
	const auth = await validateAuthentication(req, authSDK, config);

	debugLog(config, "Authentication result:", {
		isAuthenticated: auth.isAuthenticated,
		hasUser: !!auth.user,
		organizationId: auth.organizationId,
		tokenInfo: auth.tokenInfo,
	});

	// Create middleware context
	const context: MiddlewareContext = {
		req,
		config,
		auth,
		authSDK,
		path,
		isPublicPath,
		isPrivatePath,
		isAuthPath,
		response,
	};

	// Execute authentication logic
	const finalResponse = await handleAuthentication(context);

	// Execute afterAuth hook
	if (config.hooks?.afterAuth) {
		const hookResult = await config.hooks.afterAuth(req, finalResponse, auth);
		if (hookResult instanceof NextResponse) return hookResult;
	}

	return finalResponse;
}

/**
 * Handle authentication logic based on context
 */
async function handleAuthentication(
	context: MiddlewareContext,
): Promise<NextResponse> {
	const {
		req,
		config,
		auth,
		authSDK,
		path,
		isPublicPath,
		isPrivatePath,
		isAuthPath,
		response,
	} = context;

	try {
		// Handle authenticated users
		if (auth.isAuthenticated && auth.user) {
			debugLog(config, "User is authenticated");

			// Execute onAuthenticated hook
			if (config.hooks?.onAuthenticated && auth.session) {
				const hookResult = await config.hooks.onAuthenticated(
					req,
					auth.user,
					auth.session,
				);
				if (hookResult instanceof NextResponse) return hookResult;
			}

			// Redirect away from auth pages
			if (isAuthPath) {
				const redirectTo =
					req.nextUrl.searchParams.get("redirect_url") ||
					config.afterSignInPath;
				debugLog(
					config,
					`Redirecting authenticated user from auth page to: ${redirectTo}`,
				);
				const redirectResponse = NextResponse.redirect(
					new URL(redirectTo, req.url),
				);

				// Copy cookies from the original response
				copyResponseCookies(response, redirectResponse);
				return redirectResponse;
			}

			// Check organization requirement
			if (
				config.enableOrgRouting &&
				!auth.organizationId &&
				path !== config.orgSelectionPath
			) {
				debugLog(config, "Organization required but not selected");

				if (config.hooks?.onOrganizationRequired) {
					const hookResult = await config.hooks.onOrganizationRequired(
						req,
						auth.user,
					);
					if (hookResult instanceof NextResponse) return hookResult;
				}

				const redirectResponse = NextResponse.redirect(
					new URL(config.orgSelectionPath, req.url),
				);
				copyResponseCookies(response, redirectResponse);
				return redirectResponse;
			}

			// Allow access to all paths for authenticated users
			return response;
		}

		// Handle unauthenticated users
		debugLog(config, "User is not authenticated");

		// Execute onUnauthenticated hook
		if (config.hooks?.onUnauthenticated) {
			const hookResult = await config.hooks.onUnauthenticated(req);
			if (hookResult instanceof NextResponse) return hookResult;
		}

		// Allow access to public paths and auth pages
		if (isPublicPath || isAuthPath) {
			debugLog(config, "Allowing access to public/auth path");
			return response;
		}

		// Redirect to sign in for private paths
		if (isPrivatePath) {
			const signInUrl = new URL(config.signInPath, req.url);
			signInUrl.searchParams.set(
				"redirect_url",
				req.nextUrl.pathname + req.nextUrl.search,
			);

			debugLog(config, `Redirecting to sign in: ${signInUrl.toString()}`);
			const redirectResponse = NextResponse.redirect(signInUrl);
			copyResponseCookies(response, redirectResponse);
			return redirectResponse;
		}

		return response;
	} catch (error) {
		debugLog(config, "Error in authentication handling:", error);

		// Execute onError hook
		if (config.hooks?.onError) {
			const hookResult = await config.hooks.onError(req, error as Error);
			if (hookResult instanceof NextResponse) return hookResult;
		}

		// Default error handling - redirect to sign in
		const signInUrl = new URL(config.signInPath, req.url);
		signInUrl.searchParams.set("error", "auth_error");
		const redirectResponse = NextResponse.redirect(signInUrl);
		copyResponseCookies(response, redirectResponse);
		return redirectResponse;
	}
}

/**
 * Copy cookies from source response to target response
 */
function copyResponseCookies(source: NextResponse, target: NextResponse): void {
	try {
		// Copy Set-Cookie headers
		const setCookieHeaders = source.headers.getSetCookie();
		if (setCookieHeaders.length > 0) {
			for (const cookie of setCookieHeaders) {
				target.headers.append("Set-Cookie", cookie);
			}
		}

		// Copy individual cookies with validation
		for (const cookie of source.cookies.getAll()) {
			// Only copy valid cookies
			if (cookie.name && cookie.value) {
				target.cookies.set(cookie.name, cookie.value, {
					domain: cookie.domain,
					expires: cookie.expires,
					httpOnly: cookie.httpOnly,
					maxAge: cookie.maxAge,
					path: cookie.path || "/", // Ensure path is always set
					secure: cookie.secure,
					sameSite: cookie.sameSite,
				});
			}
		}
	} catch (error) {
		console.error("Error copying response cookies:", error);
		// Don't throw - this should not break the request flow
	}
}

// ============================================================================
// Main Middleware Factory
// ============================================================================

/**
 * Create Frank Auth middleware for Next.js
 */
export function createFrankAuthMiddleware(userConfig: MiddlewareConfig) {
	const config = {
		...DEFAULT_MIDDLEWARE_CONFIG,
		...userConfig,
	} as Required<MiddlewareConfig>;

	// Validate required configuration
	if (!config.publishableKey) {
		throw new Error("publishableKey is required for Frank Auth middleware");
	}

	if (!config.storageKeyPrefix) {
		config.storageKeyPrefix = "frank_auth";
	}

	debugLog(config, "Frank Auth middleware initialized with config:", {
		publicPaths: config.publicPaths,
		privatePaths: config.privatePaths,
		allPathsPrivate: config.allPathsPrivate,
		signInPath: config.signInPath,
		enableOrgRouting: config.enableOrgRouting,
		storageKeyPrefix: config.storageKeyPrefix,
	});

	return async function middleware(req: NextRequest): Promise<NextResponse> {
		return processRequest(req, config);
	};
}

// ============================================================================
// Middleware Utilities
// ============================================================================

/**
 * Create a custom matcher function for complex routing logic
 */
export function createMatcher(patterns: {
	include?: string[];
	exclude?: string[];
	custom?: (path: string) => boolean;
}) {
	return function matcher(path: string): boolean {
		if (patterns.custom) {
			return patterns.custom(path);
		}

		if (patterns.exclude && matchesPath(path, patterns.exclude)) {
			return false;
		}

		if (patterns.include && matchesPath(path, patterns.include)) {
			return true;
		}

		return false;
	};
}

/**
 * Utility to check if user has specific permission in middleware
 */
export async function checkPermission(
	req: NextRequest,
	permission: string,
	config: MiddlewareConfig,
): Promise<boolean> {
	try {
		const response = NextResponse.next();
		const authSDK = createAuthSDK(
			config as Required<MiddlewareConfig>,
			req,
			response,
		);

		// This would require implementing a permissions check method in AuthSDK
		// For now, we'll return true if user is authenticated
		const authStatus = await authSDK.getAuthStatus();
		return authStatus.isAuthenticated;
	} catch {
		return false;
	}
}

/**
 * Utility to get organization from request
 */
export function getOrganizationFromRequest(
	req: NextRequest,
	config: MiddlewareConfig,
): string | null {
	return extractOrganization(req, config as Required<MiddlewareConfig>);
}

/**
 * Utility to get AuthSDK instance in middleware context
 */
export function getAuthSDKFromRequest(
	req: NextRequest,
	config: MiddlewareConfig,
): AuthSDK {
	const response = NextResponse.next();
	return createAuthSDK(config as Required<MiddlewareConfig>, req, response);
}

/**
 * Utility to check authentication status without redirecting
 */
export async function checkAuthStatus(
	req: NextRequest,
	config: MiddlewareConfig,
): Promise<AuthResult> {
	const response = NextResponse.next();
	const authSDK = createAuthSDK(
		config as Required<MiddlewareConfig>,
		req,
		response,
	);
	return validateAuthentication(authSDK, config as Required<MiddlewareConfig>);
}
