import type {JSONObject, Status, Timestamp, XID} from './index';
import type {MFAMethod, PasskeyCredential} from './auth';
import type {Session} from './session';
import type {OrganizationSummary} from './organization';

// Three-tier user system
export type UserType = 'internal' | 'external' | 'end_user';

// User interface - comprehensive user object
export interface User {
    // Core identification
    id: XID;
    externalId?: string;
    customerId?: string;

    // User type and status
    userType: UserType;
    status: Status;
    active: boolean;
    blocked: boolean;

    // Personal information
    firstName?: string;
    lastName?: string;
    fullName?: string;
    username?: string;
    nickname?: string;

    // Contact information
    emailAddress?: string;
    emailVerified: boolean;
    phoneNumber?: string;
    phoneVerified: boolean;

    // Profile information
    profileImageUrl?: string;
    bio?: string;
    website?: string;
    locale?: string;
    timezone?: string;

    // Authentication
    hasPassword: boolean;
    passwordLastChanged?: Timestamp;
    mfaEnabled: boolean;
    mfaMethods?: MFAMethod[];
    passkeyCount: number;
    passkeys?: PasskeyCredential[];

    // Organization relationships
    primaryOrganizationId?: XID;
    organizationId?: XID; // Current organization context
    organizations?: OrganizationSummary[];

    // Permissions and roles
    roles?: UserRoleAssignment[];
    permissions?: UserPermissionAssignment[];

    // Activity tracking
    loginCount: number;
    lastLoginAt?: Timestamp;
    lastActiveAt?: Timestamp;
    createdAt: Timestamp;
    updatedAt: Timestamp;

    // Metadata and custom attributes
    metadata?: JSONObject;
    customAttributes?: JSONObject;

    // Administrative
    createdBy?: XID;
    authProvider: string;

    // Sessions (when included)
    sessions?: Session[];
}

// User summary for lists and references
export interface UserSummary {
    id: XID;
    userType: UserType;
    firstName?: string;
    lastName?: string;
    fullName?: string;
    username?: string;
    emailAddress?: string;
    profileImageUrl?: string;
    status: Status;
    lastActiveAt?: Timestamp;
}

// User profile update request
export interface UserProfileUpdateRequest {
    firstName?: string;
    lastName?: string;
    username?: string;
    nickname?: string;
    bio?: string;
    website?: string;
    locale?: string;
    timezone?: string;
    metadata?: JSONObject;
    customAttributes?: JSONObject;
}

// User creation request
export interface CreateUserRequest {
    userType: UserType;
    emailAddress?: string;
    phoneNumber?: string;
    username?: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    organizationId?: XID;
    skipVerification?: boolean;
    metadata?: JSONObject;
    customAttributes?: JSONObject;
}

// User update request (admin only)
export interface UpdateUserRequest {
    firstName?: string;
    lastName?: string;
    username?: string;
    emailAddress?: string;
    phoneNumber?: string;
    status?: Status;
    active?: boolean;
    blocked?: boolean;
    metadata?: JSONObject;
    customAttributes?: JSONObject;
}

// Role assignment types
export interface UserRoleAssignment {
    id: XID;
    userId: XID;
    roleId: XID;
    roleName: string;
    roleType: 'system' | 'organization' | 'application';
    contextType: 'system' | 'organization' | 'application';
    contextId?: XID;
    assignedAt: Timestamp;
    assignedBy: XID;
    expiresAt?: Timestamp;
}

// Permission assignment types
export interface UserPermissionAssignment {
    id: XID;
    userId: XID;
    permissionId: XID;
    permissionName: string;
    resourceType: string;
    resourceId?: XID;
    contextType: 'system' | 'organization' | 'application';
    contextId?: XID;
    assignedAt: Timestamp;
    assignedBy: XID;
    expiresAt?: Timestamp;
}

// User activity tracking
export interface UserActivity {
    id: XID;
    userId: XID;
    activityType: string;
    description: string;
    timestamp: Timestamp;
    ipAddress?: string;
    userAgent?: string;
    sessionId?: XID;
    organizationId?: XID;
    metadata?: JSONObject;
}

// User preferences
export interface UserPreferences {
    theme: 'light' | 'dark' | 'system';
    language: string;
    timezone: string;
    emailNotifications: boolean;
    smsNotifications: boolean;
    securityEmails: boolean;
    marketingEmails: boolean;
    twoFactorBackupShown: boolean;
    onboardingCompleted: boolean;
    customPreferences?: JSONObject;
}

// User statistics
export interface UserStats {
    totalUsers: number;
    activeUsers: number;
    newUsers: number;
    internalUsers: number;
    externalUsers: number;
    endUsers: number;
    verifiedUsers: number;
    mfaEnabledUsers: number;
    passkeyUsers: number;
    blockedUsers: number;
    organizationBreakdown?: Record<XID, number>;
    timeSeriesData?: Array<{
        date: string;
        total: number;
        active: number;
        new: number;
    }>;
}

// User search and filtering
export interface UserSearchParams {
    query?: string;
    userType?: UserType;
    status?: Status;
    organizationId?: XID;
    hasPassword?: boolean;
    mfaEnabled?: boolean;
    emailVerified?: boolean;
    phoneVerified?: boolean;
    createdBefore?: Timestamp;
    createdAfter?: Timestamp;
    lastActiveBefore?: Timestamp;
    lastActiveAfter?: Timestamp;
    sortBy?: 'createdAt' | 'lastActiveAt' | 'loginCount' | 'firstName' | 'lastName';
    sortOrder?: 'asc' | 'desc';
}

// Bulk user operations
export interface BulkUserOperation {
    operation: 'update' | 'delete' | 'activate' | 'deactivate' | 'block' | 'unblock';
    userIds: XID[];
    data?: Partial<UpdateUserRequest>;
    reason?: string;
}

export interface BulkUserOperationResult {
    success: boolean;
    processedCount: number;
    failedCount: number;
    errors?: Array<{
        userId: XID;
        error: string;
    }>;
}

// Password management
export interface PasswordChangeRequest {
    currentPassword: string;
    newPassword: string;
}

export interface SetPasswordRequest {
    password: string;
    signOutAllOtherSessions?: boolean;
}

// Account deletion
export interface DeleteUserRequest {
    transferDataTo?: XID;
    reason?: string;
    hardDelete?: boolean;
}

// User invitation (for external users)
export interface UserInvitation {
    id: XID;
    organizationId: XID;
    inviterUserId: XID;
    emailAddress: string;
    roleId?: XID;
    status: 'pending' | 'accepted' | 'expired' | 'revoked';
    token: string;
    expiresAt: Timestamp;
    createdAt: Timestamp;
    acceptedAt?: Timestamp;
    metadata?: JSONObject;
}

// User impersonation (internal users only)
export interface ImpersonationSession {
    id: XID;
    impersonatorId: XID;
    targetUserId: XID;
    organizationId?: XID;
    reason: string;
    startedAt: Timestamp;
    expiresAt: Timestamp;
    endedAt?: Timestamp;
    ipAddress: string;
    userAgent: string;
}