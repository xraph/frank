import {Session, SessionInfo, User} from '@frank-auth/client';
import {FrankAuthError} from "./errors";

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
} from '@frank-auth/client';

// Configuration interface
export interface FrankAuthConfig {
    apiUrl?: string;
    publishableKey: string;
    enableDevMode?: boolean;
    sessionCookieName?: string;
    storageKeyPrefix?: string;
}

// Default configuration
export const DEFAULT_CONFIG: Partial<FrankAuthConfig> = {
    apiUrl: 'http://localhost:8080',
    sessionCookieName: 'frank_session',
    storageKeyPrefix: 'frank_auth_',
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