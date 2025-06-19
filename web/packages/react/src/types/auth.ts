import type {FrankAuthError, JSONObject, LoadingState, Timestamp, XID} from './index';
import type {User} from './user';
import type {Session} from './session';
import type {Organization} from './organization';

// Authentication state
export interface AuthState {
    isLoaded: boolean;
    isSignedIn: boolean;
    user: User | null;
    session: Session | null;
    organization: Organization | null;
    error: FrankAuthError | null;
    loadingState: LoadingState;
}

// Authentication methods
export type AuthMethod =
    | 'email'
    | 'phone'
    | 'username'
    | 'oauth'
    | 'passkey'
    | 'magic_link'
    | 'mfa';

export interface AuthMethodConfig {
    enabled: boolean;
    required?: boolean;
    priority?: number;
    options?: JSONObject;
}

// Sign in types
export interface SignInRequest {
    identifier: string; // email, phone, or username
    password?: string;
    strategy: 'password' | 'oauth' | 'passkey' | 'magic_link';
    redirectUrl?: string;
    organizationId?: XID;
}

export interface SignInResponse {
    user: User;
    session: Session;
    organization?: Organization;
    requiresMfa?: boolean;
    mfaMethods?: MFAMethod[];
    redirectUrl?: string;
}

// Sign up types
export interface SignUpRequest {
    emailAddress?: string;
    phoneNumber?: string;
    username?: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    organizationId?: XID;
    invitationToken?: string;
    metadata?: JSONObject;
}

export interface SignUpResponse {
    user: User;
    session?: Session;
    organization?: Organization;
    requiresVerification?: boolean;
    verificationMethods?: VerificationMethod[];
}

// OAuth types
export type OAuthProvider =
    | 'google'
    | 'github'
    | 'microsoft'
    | 'facebook'
    | 'apple'
    | 'twitter'
    | 'linkedin'
    | 'discord'
    | 'slack'
    | 'spotify'
    | 'custom';

export interface OAuthOptions {
    provider: OAuthProvider;
    clientId: string;
    scopes?: string[];
    redirectUrl?: string;
    enabled: boolean;
    buttonText?: string;
    iconUrl?: string;
    style?: 'button' | 'icon' | 'text';
}

export interface OAuthRequest {
    provider: OAuthProvider;
    redirectUrl?: string;
    state?: string;
    organizationId?: XID;
}

// Multi-Factor Authentication
export type MFAMethodType = 'totp' | 'sms' | 'email' | 'backup_codes' | 'push';

export interface MFAMethod {
    id: XID;
    type: MFAMethodType;
    name: string;
    enabled: boolean;
    isPrimary: boolean;
    createdAt: Timestamp;
    lastUsedAt?: Timestamp;
    metadata?: JSONObject;
}

export interface MFAChallenge {
    id: XID;
    type: MFAMethodType;
    message?: string;
    expiresAt: Timestamp;
    attemptsRemaining: number;
}

export interface MFAVerifyRequest {
    challengeId: XID;
    code: string;
    rememberDevice?: boolean;
}

// Passkey (WebAuthn) types
export interface PasskeyCredential {
    id: XID;
    name: string;
    publicKey: string;
    counter: number;
    createdAt: Timestamp;
    lastUsedAt?: Timestamp;
    metadata?: JSONObject;
}

export interface PasskeyRegistrationOptions {
    challenge: string;
    rp: {
        id: string;
        name: string;
    };
    user: {
        id: string;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: Array<{
        type: 'public-key';
        alg: number;
    }>;
    timeout?: number;
    excludeCredentials?: Array<{
        id: string;
        type: 'public-key';
    }>;
}

export interface PasskeyAuthenticationOptions {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{
        id: string;
        type: 'public-key';
    }>;
}

// Verification types
export type VerificationMethod = 'email' | 'phone' | 'manual';

export interface VerificationRequest {
    identifier: string;
    method: VerificationMethod;
    template?: string;
    redirectUrl?: string;
}

export interface VerificationStatus {
    id: XID;
    identifier: string;
    method: VerificationMethod;
    status: 'pending' | 'verified' | 'expired' | 'failed';
    expiresAt: Timestamp;
    attemptsUsed: number;
    maxAttempts: number;
}

// Magic link types
export interface MagicLinkRequest {
    emailAddress: string;
    redirectUrl?: string;
    organizationId?: XID;
}

export interface MagicLinkResponse {
    id: XID;
    emailAddress: string;
    expiresAt: Timestamp;
    redirectUrl?: string;
}

// Password reset types
export interface PasswordResetRequest {
    emailAddress: string;
    redirectUrl?: string;
}

export interface PasswordResetResponse {
    id: XID;
    emailAddress: string;
    expiresAt: Timestamp;
}

// export interface PasswordUpdateRequest {
//     token: string;
//     newPassword: string;
// }

// Account recovery types
export interface AccountRecoveryOptions {
    email?: boolean;
    phone?: boolean;
    backupCodes?: boolean;
    adminOverride?: boolean;
}

// // Authentication events
// export type AuthEventType =
//     | 'sign_in'
//     | 'sign_out'
//     | 'sign_up'
//     | 'password_change'
//     | 'mfa_enabled'
//     | 'mfa_disabled'
//     | 'passkey_added'
//     | 'passkey_removed'
//     | 'account_locked'
//     | 'account_unlocked';

// export interface AuthEvent {
//     id: XID;
//     type: AuthEventType;
//     userId: XID;
//     sessionId?: XID;
//     timestamp: Timestamp;
//     ipAddress?: string;
//     userAgent?: string;
//     metadata?: JSONObject;
// }

// Authentication policies
export interface AuthPolicy {
    passwordPolicy: {
        minLength: number;
        requireUppercase: boolean;
        requireLowercase: boolean;
        requireNumbers: boolean;
        requireSymbols: boolean;
        preventReuse: number;
        maxAge?: number;
    };
    sessionPolicy: {
        maxDuration: number;
        inactivityTimeout: number;
        maxConcurrentSessions: number;
        requireReauth: boolean;
    };
    mfaPolicy: {
        required: boolean;
        methods: MFAMethodType[];
        gracePeriod?: number;
    };
    lockoutPolicy: {
        enabled: boolean;
        maxAttempts: number;
        lockoutDuration: number;
        progressiveDelay: boolean;
    };
}