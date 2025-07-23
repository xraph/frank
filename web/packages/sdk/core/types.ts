import type { Session, SessionInfo, User, UserType } from "@frank-auth/client";
import type { FrankAuthError } from "./errors";
import type { HybridAuthStorage } from "./helpers";
import type { StorageManager, StorageType } from "./storage";

// Re-export types from the generated client
export type {
	User,
	LoginRequest,
	LoginResponse,
	RegisterRequest,
	RegisterResponse,
	Session,
	SessionInfo,
	AuthStatus,
	MFASetupResponse,
	MFAVerifyRequest,
	MFAVerifyResponse,
	PasskeyRegistrationBeginResponse,
	PasskeyRegistrationFinishRequest,
	PasskeyAuthenticationBeginResponse,
	PasskeyAuthenticationFinishRequest,
	RefreshTokenRequest,
	RefreshTokenResponse,
	PasswordResetRequest,
	PasswordResetResponse,
	PasswordResetConfirmRequest,
	PasswordResetConfirmResponse,
	VerificationRequest,
	VerificationResponse,
	MagicLinkRequest,
	MagicLinkResponse,
	UserProfileUpdateRequest,
	ChangePasswordRequest,
	OAuthClient,
	AuthProvider,
} from "@frank-auth/client";

// Common utility types
export type XID = string; // Frank Auth uses XID format for all IDs
export type Timestamp = string; // ISO 8601 timestamp
export type JSONValue =
	| string
	| number
	| boolean
	| null
	| JSONObject
	| JSONArray;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];

// Configuration interface
export interface FrankAuthConfig {
	apiUrl?: string;
	publishableKey: string;
	secretKey?: string;
	projectId?: string;
	userType: UserType;
	enableDevMode?: boolean;
	sessionCookieName?: string;
	storageKeyPrefix?: string;
	// customStorageStore?: Storage;
	storageManager?: StorageManager;
	storage?: HybridAuthStorage;
	// storageType?: StorageType;
	/**
	 * Enable debug mode
	 * @default false
	 */
	debug?: boolean;

	/**
	 * Debug configuration options
	 */
	debugConfig?: Partial<DebugConfig>;
}

/**
 * Debug configuration options
 */
export interface DebugConfig {
	enabled: boolean;
	logLevel: "error" | "warn" | "info" | "debug" | "verbose";
	logApiCalls: boolean;
	logHeaders: boolean;
	logTokens: boolean; // Be careful with this in production
	logStorage: boolean;
	logErrors: boolean;
	logPrehooks: boolean;
	prefix: string;
}

// Default configuration
export const DEFAULT_CONFIG: Partial<FrankAuthConfig> = {
	apiUrl: "http://localhost:8080",
	sessionCookieName: "frank_session",
	storageKeyPrefix: "frank_auth_",
	enableDevMode: false,
};

// Auth state type
export interface AuthState {
	isLoaded: boolean;
	isSignedIn: boolean;
	user: User | null;
	session: Session | null;
	error: FrankAuthError | null;
}

// Session state type
export interface SessionState {
	isLoaded: boolean;
	sessions: SessionInfo[];
	currentSession: Session | null;
	error: FrankAuthError | null;
}

// User state type
export interface UserState {
	isLoaded: boolean;
	user: User | null;
	error: FrankAuthError | null;
}
