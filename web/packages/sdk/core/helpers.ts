import {
	AuthStorage,
	ClientCookieContext,
	type CookieContext,
	type CookieOptions,
	NextJSCookieContext,
	type StorageManager,
	createCookieStorage,
	memoryStorage,
} from "./storage";

export const createAuthStorageForEnvironment = (
	environment: "client" | "server",
	prefix = "frank_auth_",
	context?: any,
	cookieOptions?: CookieOptions,
): AuthStorage => {
	let storage: StorageManager;

	switch (environment) {
		case "client":
			if (typeof window !== "undefined") {
				// Browser environment - use client cookie storage
				const clientCookieContext = new ClientCookieContext();
				storage = createCookieStorage(clientCookieContext, {
					prefix,
					cookieOptions: {
						secure: process.env.NODE_ENV === "production",
						sameSite: "strict",
						maxAge: 24 * 60 * 60, // 1 day
						...cookieOptions,
					},
				});
			} else {
				// SSR - use memory storage as fallback
				storage = memoryStorage;
			}
			break;

		case "server":
			if (context) {
				// Server environment with request/response context
				const serverCookieContext = new NextJSCookieContext(
					context.req,
					context.res,
				);
				storage = createCookieStorage(serverCookieContext, {
					prefix,
					cookieOptions: {
						httpOnly: false,
						secure: process.env.NODE_ENV === "production",
						sameSite: "strict",
						maxAge: 7 * 24 * 60 * 60, // 7 days for server-side
					},
				});
			} else {
				storage = memoryStorage;
			}
			break;

		default:
			storage = memoryStorage;
	}

	return new AuthStorage(storage);
};

export const SecureTokenStorage = {
	// Store access token in HTTP-only cookie (server-side)
	setAccessTokenSecure: (
		token: string,
		cookieContext: CookieContext,
		ttl: number = 15 * 60 * 1000, // 15 minutes
	) => {
		const storage = createCookieStorage(cookieContext, {
			prefix: "secure_",
			cookieOptions: {
				httpOnly: false,
				secure: true,
				sameSite: "strict",
				maxAge: ttl / 1000,
			},
		});

		storage.setString("access_token", token, { ttl });
	},

	// Store refresh token in HTTP-only cookie with longer TTL
	setRefreshTokenSecure: (
		token: string,
		cookieContext: CookieContext,
		ttl: number = 7 * 24 * 60 * 60 * 1000, // 7 days
	) => {
		const storage = createCookieStorage(cookieContext, {
			prefix: "secure_",
			cookieOptions: {
				httpOnly: false,
				secure: true,
				sameSite: "strict",
				maxAge: ttl / 1000,
			},
		});

		storage.setString("refresh_token", token, { ttl });
	},

	// Store non-sensitive data in regular cookies (accessible to client)
	setUserPreferences: (preferences: any, cookieContext: CookieContext) => {
		const storage = createCookieStorage(cookieContext, {
			prefix: "prefs_",
			cookieOptions: {
				secure: true,
				sameSite: "strict",
				maxAge: 30 * 24 * 60 * 60, // 30 days
			},
		});

		storage.setObject("user_preferences", preferences);
	},
};

export class HybridAuthStorage {
	private clientStorage?: AuthStorage;
	private readonly serverStorage?: AuthStorage;
	private currentStorage: AuthStorage;

	constructor(
		prefix?: string,
		serverContext?: { req: any; res: any },
		cookieOptions?: CookieOptions,
	) {
		if (serverContext) {
			// Server-side: Use cookies with HTTP-only security
			this.serverStorage = createAuthStorageForEnvironment(
				"server",
				prefix,
				serverContext,
				cookieOptions,
			);
			this.currentStorage = this.serverStorage;
		} else if (typeof window !== "undefined") {
			// Client-side: Use regular cookies (accessible to JS)
			this.clientStorage = createAuthStorageForEnvironment(
				"client",
				prefix,
				undefined,
				cookieOptions,
			);
			this.currentStorage = this.clientStorage;
		} else {
			// Fallback: Memory storage
			this.currentStorage = new AuthStorage(memoryStorage);
		}
	}

	get store() {
		return this.currentStorage;
	}

	// Delegate all methods to current storage
	getAccessToken(): string | null {
		return this.currentStorage.getAccessToken();
	}

	setAccessToken(token: string, ttl?: number): void {
		this.currentStorage.setAccessToken(token, ttl);
	}

	removeAccessToken(): void {
		this.currentStorage.removeAccessToken();
	}

	getRefreshToken(): string | null {
		return this.currentStorage.getRefreshToken();
	}

	setRefreshToken(token: string): void {
		this.currentStorage.setRefreshToken(token);
	}

	removeRefreshToken(): void {
		this.currentStorage.removeRefreshToken();
	}

	setSessionId(sessionId: string): void {
		this.currentStorage.setSessionId(sessionId);
	}

	getSessionId(): string | null {
		return this.currentStorage.getSessionId();
	}

	removeSessionId(): void {
		this.currentStorage.removeSessionId();
	}

	getUserData(): void {
		this.currentStorage.getUserData();
	}

	setUserData(userData: any): void {
		this.currentStorage.setUserData(userData);
	}

	removeUserData(): void {
		this.currentStorage.removeUserData();
	}

	getRememberMe(): void {
		this.currentStorage.getRememberMe();
	}

	setRememberMe(rememberMe: boolean): void {
		this.currentStorage.setRememberMe(rememberMe);
	}

	getDeviceFingerprint(): void {
		this.currentStorage.getDeviceFingerprint();
	}

	setDeviceFingerprint(deviceFingerprint: string): void {
		this.currentStorage.setDeviceFingerprint(deviceFingerprint);
	}

	clearAll(): void {
		this.currentStorage.clearAll();
	}

	// Method to sync between client and server (for hydration)
	syncWithClient(): void {
		if (typeof window !== "undefined" && this.serverStorage) {
			this.clientStorage = createAuthStorageForEnvironment("client");

			// Copy data from server storage to client storage
			const accessToken = this.serverStorage.getAccessToken();
			const refreshToken = this.serverStorage.getRefreshToken();

			if (accessToken) this.clientStorage.setAccessToken(accessToken);
			if (refreshToken) this.clientStorage.setRefreshToken(refreshToken);

			// Switch to client storage
			this.currentStorage = this.clientStorage;
		}
	}
}

// Factory for Hybrid Storage
export const createHybridAuthStorage = (
	prefix?: string,
	serverContext?: { req: any; res: any },
): HybridAuthStorage => {
	return new HybridAuthStorage(prefix, serverContext);
};
