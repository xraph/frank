import type {JSONObject, Status, Timestamp, XID} from './index';
import type {UserSummary} from './user';

// Organization types
export type OrganizationType = 'platform' | 'customer';

// Main organization interface
export interface Organization {
    // Core identification
    id: XID;
    name: string;
    slug: string;
    displayName?: string;

    // Organization type and status
    orgType: OrganizationType;
    isPlatformOrganization: boolean;
    status: Status;

    // Branding and appearance
    logoUrl?: string;
    brandColor?: string;
    faviconUrl?: string;
    customCSS?: string;

    // Contact and location
    domain?: string;
    domains?: string[];
    website?: string;
    description?: string;
    address?: OrganizationAddress;

    // Ownership and management
    owner?: UserSummary;
    ownerId?: XID;

    // Members and roles
    members?: MemberSummary[];
    memberCount?: number;

    // Billing and subscription
    plan: string;
    subscriptionId?: string;
    subscriptionStatus: string;
    billingEmail?: string;
    trialEndsAt?: Timestamp;

    // Limits and quotas
    externalUserLimit: number;
    endUserLimit: number;
    currentExternalUsers?: number;
    currentEndUsers?: number;

    // Features and capabilities
    features?: FeatureSummary[];
    enabledFeatures?: string[];

    // SSO configuration
    ssoEnabled: boolean;
    ssoDomain?: string;
    ssoProvider?: string;
    ssoConfiguration?: JSONObject;

    // Security settings
    mfaRequired: boolean;
    allowPublicSignup: boolean;
    emailDomainRestrictions?: string[];
    ipWhitelist?: string[];

    // Timestamps
    createdAt: Timestamp;
    updatedAt: Timestamp;

    // Metadata
    metadata?: JSONObject;
    customAttributes?: JSONObject;

    // Statistics (when included)
    stats?: OrganizationStats;
}

// Organization summary for lists and references
export interface OrganizationSummary {
    id: XID;
    name: string;
    slug: string;
    logoUrl?: string;
    orgType: OrganizationType;
    status: Status;
    memberCount?: number;
    userRole?: string;
    userPermissions?: string[];
}

// Organization creation request
export interface CreateOrganizationRequest {
    name: string;
    slug?: string;
    displayName?: string;
    domain?: string;
    logoUrl?: string;
    description?: string;
    plan?: string;
    metadata?: JSONObject;
    customAttributes?: JSONObject;
}

// Organization update request
export interface UpdateOrganizationRequest {
    name?: string;
    displayName?: string;
    domain?: string;
    logoUrl?: string;
    brandColor?: string;
    faviconUrl?: string;
    customCSS?: string;
    website?: string;
    description?: string;
    address?: OrganizationAddress;
    billingEmail?: string;
    metadata?: JSONObject;
    customAttributes?: JSONObject;
}

// Organization address
export interface OrganizationAddress {
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
}

// Member management
export interface MemberSummary {
    id: XID;
    userId: XID;
    user?: UserSummary;
    role: string;
    roleId: XID;
    status: 'active' | 'inactive' | 'pending' | 'suspended';
    joinedAt: Timestamp;
    invitedBy?: XID;
    lastActiveAt?: Timestamp;
    permissions?: string[];
}

// Full membership details
export interface Membership {
    id: XID;
    organizationId: XID;
    organization?: OrganizationSummary;
    userId: XID;
    user?: UserSummary;

    // Role and permissions
    roleId: XID;
    roleName: string;
    permissions: string[];

    // Status and lifecycle
    status: 'active' | 'inactive' | 'pending' | 'suspended';
    joinedAt: Timestamp;
    invitedAt?: Timestamp;
    invitedBy?: XID;
    acceptedAt?: Timestamp;
    suspendedAt?: Timestamp;
    suspendedBy?: XID;
    suspensionReason?: string;

    // Activity tracking
    lastActiveAt?: Timestamp;
    loginCount?: number;

    // Billing
    isBillableSeat: boolean;
    seatType?: 'full' | 'guest' | 'service';

    // Metadata
    metadata?: JSONObject;
}

// Member invitation
export interface MemberInvitation {
    id: XID;
    organizationId: XID;
    inviterUserId: XID;
    inviterName?: string;
    emailAddress: string;
    roleId: XID;
    roleName: string;

    // Status and lifecycle
    status: 'pending' | 'accepted' | 'expired' | 'revoked';
    token: string;
    expiresAt: Timestamp;
    createdAt: Timestamp;
    acceptedAt?: Timestamp;
    revokedAt?: Timestamp;
    revokedBy?: XID;

    // Customization
    customMessage?: string;
    redirectUrl?: string;
    metadata?: JSONObject;
}

// Invitation request
export interface CreateInvitationRequest {
    emailAddress: string;
    roleId: XID;
    customMessage?: string;
    redirectUrl?: string;
    expiresAt?: Timestamp;
    metadata?: JSONObject;
}

// Organization roles
export interface OrganizationRole {
    id: XID;
    name: string;
    description?: string;
    organizationId: XID;
    isDefault: boolean;
    isSystemRole: boolean;
    permissions: string[];
    memberCount?: number;
    createdAt: Timestamp;
    updatedAt: Timestamp;
}

// Feature management
export interface FeatureSummary {
    id: XID;
    name: string;
    displayName: string;
    description?: string;
    enabled: boolean;
    required: boolean;
    planRestricted: boolean;
    configuration?: JSONObject;
}

// Organization settings
export interface OrganizationSettings {
    // Authentication settings
    allowPublicSignup: boolean;
    requireEmailVerification: boolean;
    allowUsernameSignup: boolean;
    allowPhoneSignup: boolean;

    // Password policy
    passwordMinLength: number;
    passwordRequireUppercase: boolean;
    passwordRequireLowercase: boolean;
    passwordRequireNumbers: boolean;
    passwordRequireSymbols: boolean;

    // Session settings
    sessionDuration: number;
    inactivityTimeout: number;
    maxConcurrentSessions: number;

    // MFA settings
    mfaRequired: boolean;
    allowedMfaMethods: string[];
    mfaGracePeriod?: number;

    // Domain restrictions
    emailDomainRestrictions?: string[];
    emailDomainRestrictionsEnabled: boolean;

    // Security settings
    ipWhitelist?: string[];
    ipWhitelistEnabled: boolean;
    allowedCountries?: string[];
    blockedCountries?: string[];

    // Notification settings
    securityNotifications: boolean;
    billingNotifications: boolean;
    featureAnnouncements: boolean;

    // Branding settings
    customBranding: boolean;
    hideFromDirectory: boolean;

    // Advanced settings
    auditLogRetentionDays: number;
    dataResidency?: string;
    encryptionAtRest: boolean;

    // API settings
    apiRateLimit?: number;
    webhookSecret?: string;
    allowedCallbackUrls?: string[];
}

// Organization statistics
export interface OrganizationStats {
    // Member statistics
    totalMembers: number;
    activeMembers: number;
    pendingInvitations: number;
    suspendedMembers: number;

    // User type breakdown
    internalUsers: number;
    externalUsers: number;
    endUsers: number;

    // Activity statistics
    dailyActiveUsers: number;
    weeklyActiveUsers: number;
    monthlyActiveUsers: number;

    // Authentication statistics
    totalLogins: number;
    successfulLogins: number;
    failedLogins: number;
    mfaLogins: number;
    ssoLogins: number;

    // Security statistics
    blockedAttempts: number;
    passwordResets: number;
    accountLockouts: number;

    // Billing statistics
    billableSeats: number;
    seatUtilization: number;

    // Time series data (optional)
    timeSeriesData?: Array<{
        date: string;
        activeUsers: number;
        newMembers: number;
        logins: number;
    }>;
}

// Organization search and filtering
export interface OrganizationSearchParams {
    query?: string;
    orgType?: OrganizationType;
    status?: Status;
    plan?: string;
    subscriptionStatus?: string;
    hasSSO?: boolean;
    createdBefore?: Timestamp;
    createdAfter?: Timestamp;
    sortBy?: 'name' | 'createdAt' | 'memberCount' | 'lastActiveAt';
    sortOrder?: 'asc' | 'desc';
}

// Domain management
export interface OrganizationDomain {
    id: XID;
    organizationId: XID;
    domain: string;
    isPrimary: boolean;
    verified: boolean;
    verificationToken?: string;
    verificationMethod: 'dns' | 'http';
    verifiedAt?: Timestamp;
    createdAt: Timestamp;
}

// Domain verification
export interface DomainVerificationRequest {
    domain: string;
    method: 'dns' | 'http';
}

export interface DomainVerificationResponse {
    domain: string;
    token: string;
    method: 'dns' | 'http';
    instructions: string;
    dnsRecord?: {
        type: string;
        name: string;
        value: string;
    };
    httpFile?: {
        path: string;
        content: string;
    };
}

// Organization transfer
export interface TransferOrganizationRequest {
    newOwnerId: XID;
    reason?: string;
    notifyMembers: boolean;
}

// Organization usage and billing
export interface OrganizationUsage {
    organizationId: XID;
    billingPeriodStart: Timestamp;
    billingPeriodEnd: Timestamp;

    // Seat usage
    billableSeats: number;
    maxSeats: number;
    seatOverage: number;

    // Feature usage
    apiCallsUsed: number;
    apiCallsLimit: number;
    storageUsed: number;
    storageLimit: number;

    // Monthly statistics
    activeUsers: number;
    newUsers: number;
    totalLogins: number;
    dataTransfer: number;
}

// Organization billing
export interface OrganizationBilling {
    organizationId: XID;
    subscriptionId?: string;
    customerId?: string;

    // Plan information
    plan: string;
    planName: string;
    planPrice: number;
    billingCycle: 'monthly' | 'yearly';

    // Subscription status
    status: 'active' | 'trialing' | 'past_due' | 'canceled' | 'unpaid';
    trialStart?: Timestamp;
    trialEnd?: Timestamp;
    currentPeriodStart: Timestamp;
    currentPeriodEnd: Timestamp;

    // Payment information
    paymentMethod?: string;
    lastPaymentAmount?: number;
    lastPaymentDate?: Timestamp;
    nextPaymentDate?: Timestamp;

    // Usage and overages
    baseSeats: number;
    additionalSeats: number;
    overage: number;

    // Billing contact
    billingEmail: string;
    billingAddress?: OrganizationAddress;
    taxId?: string;
}