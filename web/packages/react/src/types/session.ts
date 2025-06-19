import type {JSONObject, Timestamp, XID} from './index';
import type {User} from './user';
import type {Organization} from './organization';

// Session status
export type SessionStatus = 'active' | 'expired' | 'revoked' | 'replaced';

// Main session interface
export interface Session {
    // Core identification
    id: XID;
    userId: XID;
    organizationId?: XID;

    // Status and lifecycle
    status: SessionStatus;
    isActive: boolean;

    // Device and client information
    clientId?: string;
    userAgent?: string;
    deviceName?: string;
    deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
    operatingSystem?: string;
    browser?: string;

    // Network information
    ipAddress?: string;
    country?: string;
    city?: string;
    lastActiveIpAddress?: string;

    // Timestamps
    createdAt: Timestamp;
    updatedAt: Timestamp;
    lastActiveAt: Timestamp;
    expiresAt: Timestamp;

    // Authentication details
    authMethod: string;
    mfaVerified: boolean;
    mfaRequiredAt?: Timestamp;

    // Token information
    accessToken?: string;
    refreshToken?: string;
    tokenType: 'bearer' | 'jwt';

    // Session metadata
    metadata?: JSONObject;

    // Related entities (when included)
    user?: User;
    organization?: Organization;
}

// Session summary for lists
export interface SessionSummary {
    id: XID;
    deviceName?: string;
    deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
    browser?: string;
    operatingSystem?: string;
    ipAddress?: string;
    country?: string;
    city?: string;
    isCurrentSession: boolean;
    lastActiveAt: Timestamp;
    createdAt: Timestamp;
    status: SessionStatus;
}

// Session information (minimal for client-side)
export interface SessionInfo {
    id: XID;
    userId: XID;
    organizationId?: XID;
    isActive: boolean;
    lastActiveAt: Timestamp;
    expiresAt: Timestamp;
    mfaVerified: boolean;
}

// Session creation request
export interface CreateSessionRequest {
    userId: XID;
    organizationId?: XID;
    clientId?: string;
    userAgent?: string;
    ipAddress?: string;
    deviceName?: string;
    authMethod: string;
    expiresIn?: number;
    metadata?: JSONObject;
}

// Session refresh request
export interface RefreshSessionRequest {
    refreshToken: string;
    extendExpiry?: boolean;
}

// Session refresh response
export interface RefreshSessionResponse {
    accessToken: string;
    refreshToken?: string;
    expiresAt: Timestamp;
    session: Session;
}

// Session validation
export interface SessionValidationResult {
    valid: boolean;
    session?: Session;
    reason?: 'expired' | 'revoked' | 'invalid' | 'mfa_required';
    requiresMfa?: boolean;
    mfaMethods?: string[];
}

// Session device management
export interface SessionDevice {
    id: XID;
    sessionId: XID;
    deviceId?: string;
    deviceName?: string;
    deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
    operatingSystem?: string;
    browser?: string;
    userAgent?: string;
    fingerprint?: string;
    trusted: boolean;
    registeredAt: Timestamp;
    lastSeenAt: Timestamp;
}

// Session activity tracking
export interface SessionActivity {
    id: XID;
    sessionId: XID;
    activityType: 'login' | 'page_view' | 'api_call' | 'logout' | 'timeout';
    timestamp: Timestamp;
    ipAddress?: string;
    userAgent?: string;
    url?: string;
    method?: string;
    statusCode?: number;
    duration?: number;
    metadata?: JSONObject;
}

// Session security events
export interface SessionSecurityEvent {
    id: XID;
    sessionId: XID;
    eventType: 'suspicious_activity' | 'location_change' | 'device_change' | 'concurrent_limit';
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    timestamp: Timestamp;
    ipAddress?: string;
    location?: string;
    automated: boolean;
    resolved: boolean;
    resolvedAt?: Timestamp;
    resolvedBy?: XID;
    metadata?: JSONObject;
}

// Session limits and policies
export interface SessionPolicy {
    maxConcurrentSessions: number;
    sessionDuration: number;
    inactivityTimeout: number;
    requireMfaForSensitive: boolean;
    allowMultipleDevices: boolean;
    trustDeviceDuration?: number;
    ipRestrictions?: string[];
    locationRestrictions?: string[];
    timeRestrictions?: {
        allowedHours: [number, number];
        allowedDays: number[];
        timezone: string;
    };
}

// Session termination
export interface TerminateSessionRequest {
    sessionId?: XID;
    userId?: XID;
    reason?: 'user_logout' | 'admin_revoke' | 'security_policy' | 'account_disabled';
    terminateAll?: boolean;
    notifyUser?: boolean;
}

export interface TerminateSessionResponse {
    success: boolean;
    terminatedSessions: number;
    failedSessions?: Array<{
        sessionId: XID;
        error: string;
    }>;
}

// Session analytics
export interface SessionAnalytics {
    organizationId?: XID;
    dateRange: {
        start: Timestamp;
        end: Timestamp;
    };

    // Overall statistics
    totalSessions: number;
    activeSessions: number;
    uniqueUsers: number;
    averageSessionDuration: number;

    // Device breakdown
    deviceTypes: Record<string, number>;
    browsers: Record<string, number>;
    operatingSystems: Record<string, number>;

    // Geographic breakdown
    countries: Record<string, number>;
    cities: Record<string, number>;

    // Time series data
    sessionsOverTime: Array<{
        date: string;
        sessions: number;
        uniqueUsers: number;
        averageDuration: number;
    }>;

    // Authentication methods
    authMethods: Record<string, number>;
    mfaUsage: {
        enabled: number;
        disabled: number;
        methods: Record<string, number>;
    };
}

// Session storage interface
export interface SessionStorage {
    getSession(sessionId: XID): Promise<Session | null>;
    setSession(session: Session): Promise<void>;
    removeSession(sessionId: XID): Promise<void>;
    getAllSessions(userId: XID): Promise<Session[]>;
    cleanupExpiredSessions(): Promise<number>;
}

// Session middleware types
export interface SessionMiddlewareOptions {
    required?: boolean;
    allowExpired?: boolean;
    requireMfa?: boolean;
    requireOrganization?: boolean;
    permissions?: string[];
    roles?: string[];
}

export interface SessionContext {
    session: Session | null;
    user: User | null;
    organization: Organization | null;
    isAuthenticated: boolean;
    hasPermission: (permission: string, resource?: string) => boolean;
    hasRole: (role: string, context?: string) => boolean;
}

// JWT token payload
export interface JWTPayload {
    // Standard claims
    sub: XID; // subject (user ID)
    aud: string; // audience
    iss: string; // issuer
    exp: number; // expiration time
    iat: number; // issued at
    nbf: number; // not before
    jti: XID; // JWT ID (session ID)

    // Custom claims
    user_type: string;
    organization_id?: XID;
    permissions?: string[];
    roles?: string[];
    mfa_verified: boolean;
    device_id?: string;
    client_id?: string;
}

// Session token types
export interface SessionTokens {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    tokenType: 'bearer' | 'jwt';
    expiresIn: number;
    expiresAt: Timestamp;
    scope?: string;
}

// Session impersonation (for admin users)
export interface ImpersonationContext {
    impersonatorId: XID;
    impersonatorSession: XID;
    targetUserId: XID;
    organizationId?: XID;
    reason: string;
    startedAt: Timestamp;
    expiresAt: Timestamp;
    permissions: string[];
}

// Session backup and recovery
export interface SessionBackup {
    userId: XID;
    sessionData: Record<string, any>;
    createdAt: Timestamp;
    expiresAt: Timestamp;
    encrypted: boolean;
}

// Session sync (for multi-device sync)
export interface SessionSync {
    userId: XID;
    lastSyncAt: Timestamp;
    syncData: {
        preferences: JSONObject;
        state: JSONObject;
        notifications: JSONObject;
    };
    deviceSessions: XID[];
}