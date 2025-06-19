import type {
    CreateInvitationRequest,
    JSONObject,
    PaginatedResponse,
    PasskeyAuthenticationOptions,
    PasskeyRegistrationOptions,
    PasswordResetRequest,
    Timestamp,
    XID
} from './index';
import type {UpdateUserRequest, User, UserSummary} from './user';
import type {
    CreateOrganizationRequest,
    Membership,
    Organization,
    OrganizationSummary,
    UpdateOrganizationRequest
} from './organization';
import type {Session, SessionSummary} from './session';

// API response wrapper
export interface APIResponse<T = any> {
    success: boolean;
    data: T;
    message?: string;
    errors?: APIError[];
    meta?: APIResponseMeta;
}

// API error
export interface APIError {
    code: string;
    message: string;
    field?: string;
    details?: JSONObject;
}

// API response metadata
export interface APIResponseMeta {
    requestId: string;
    timestamp: Timestamp;
    version: string;
    rateLimit?: {
        limit: number;
        remaining: number;
        reset: Timestamp;
    };
}

// Authentication API
export interface AuthAPI {
    // Sign in
    signIn(request: SignInAPIRequest): Promise<APIResponse<SignInAPIResponse>>;

    // Sign up
    signUp(request: SignUpAPIRequest): Promise<APIResponse<SignUpAPIResponse>>;

    // Sign out
    signOut(sessionId?: XID): Promise<APIResponse<void>>;

    // Refresh session
    refreshSession(refreshToken: string): Promise<APIResponse<RefreshSessionAPIResponse>>;

    // Verify session
    verifySession(sessionId: XID): Promise<APIResponse<SessionVerificationResponse>>;

    // OAuth
    getOAuthUrl(request: OAuthURLRequest): Promise<APIResponse<OAuthURLResponse>>;
    handleOAuthCallback(request: OAuthCallbackRequest): Promise<APIResponse<SignInAPIResponse>>;

    // MFA
    initiateMFA(request: InitiateMFARequest): Promise<APIResponse<MFAChallengeResponse>>;
    verifyMFA(request: VerifyMFARequest): Promise<APIResponse<MFAVerificationResponse>>;

    // Passkeys
    initiatePasskeyRegistration(request: PasskeyRegistrationRequest): Promise<APIResponse<PasskeyRegistrationOptions>>;
    completePasskeyRegistration(request: CompletePasskeyRegistrationRequest): Promise<APIResponse<PasskeyCredentialResponse>>;
    initiatePasskeyAuthentication(request: PasskeyAuthenticationRequest): Promise<APIResponse<PasskeyAuthenticationOptions>>;
    completePasskeyAuthentication(request: CompletePasskeyAuthenticationRequest): Promise<APIResponse<SignInAPIResponse>>;

    // Password management
    resetPassword(request: PasswordResetRequest): Promise<APIResponse<void>>;
    updatePassword(request: PasswordUpdateRequest): Promise<APIResponse<void>>;

    // Email verification
    sendVerificationEmail(request: SendVerificationEmailRequest): Promise<APIResponse<void>>;
    verifyEmail(request: VerifyEmailRequest): Promise<APIResponse<void>>;

    // Phone verification
    sendVerificationSMS(request: SendVerificationSMSRequest): Promise<APIResponse<void>>;
    verifyPhone(request: VerifyPhoneRequest): Promise<APIResponse<void>>;

    // Magic links
    sendMagicLink(request: SendMagicLinkRequest): Promise<APIResponse<void>>;
    verifyMagicLink(request: VerifyMagicLinkRequest): Promise<APIResponse<SignInAPIResponse>>;
}

// User API
export interface UserAPI {
    // Get current user
    getCurrentUser(): Promise<APIResponse<User>>;

    // Get user by ID
    getUser(userId: XID): Promise<APIResponse<User>>;

    // Update user
    updateUser(userId: XID, request: UpdateUserRequest): Promise<APIResponse<User>>;

    // Update current user profile
    updateProfile(request: UpdateUserProfileRequest): Promise<APIResponse<User>>;

    // Delete user
    deleteUser(userId: XID): Promise<APIResponse<void>>;

    // List users
    listUsers(params: ListUsersParams): Promise<APIResponse<PaginatedResponse<UserSummary>>>;

    // Search users
    searchUsers(params: SearchUsersParams): Promise<APIResponse<PaginatedResponse<UserSummary>>>;

    // User sessions
    getUserSessions(userId: XID): Promise<APIResponse<SessionSummary[]>>;

    // User organizations
    getUserOrganizations(userId: XID): Promise<APIResponse<OrganizationSummary[]>>;

    // User permissions
    getUserPermissions(userId: XID, organizationId?: XID): Promise<APIResponse<UserPermissionResponse>>;

    // User roles
    getUserRoles(userId: XID, organizationId?: XID): Promise<APIResponse<UserRoleResponse>>;

    // User activity
    getUserActivity(userId: XID, params: UserActivityParams): Promise<APIResponse<PaginatedResponse<UserActivityRecord>>>;

    // User statistics
    getUserStats(organizationId?: XID): Promise<APIResponse<UserStatsResponse>>;
}

// Organization API
export interface OrganizationAPI {
    // Get current organization
    getCurrentOrganization(): Promise<APIResponse<Organization>>;

    // Get organization by ID
    getOrganization(organizationId: XID): Promise<APIResponse<Organization>>;

    // Create organization
    createOrganization(request: CreateOrganizationRequest): Promise<APIResponse<Organization>>;

    // Update organization
    updateOrganization(organizationId: XID, request: UpdateOrganizationRequest): Promise<APIResponse<Organization>>;

    // Delete organization
    deleteOrganization(organizationId: XID): Promise<APIResponse<void>>;

    // List organizations
    listOrganizations(params: ListOrganizationsParams): Promise<APIResponse<PaginatedResponse<OrganizationSummary>>>;

    // Organization members
    getOrganizationMembers(organizationId: XID, params: ListMembersParams): Promise<APIResponse<PaginatedResponse<Membership>>>;

    // Add member
    addMember(organizationId: XID, request: AddMemberRequest): Promise<APIResponse<Membership>>;

    // Update member
    updateMember(organizationId: XID, userId: XID, request: UpdateMemberRequest): Promise<APIResponse<Membership>>;

    // Remove member
    removeMember(organizationId: XID, userId: XID): Promise<APIResponse<void>>;

    // Organization invitations
    createInvitation(organizationId: XID, request: CreateInvitationRequest): Promise<APIResponse<InvitationResponse>>;

    // List invitations
    listInvitations(organizationId: XID, params: ListInvitationsParams): Promise<APIResponse<PaginatedResponse<InvitationResponse>>>;

    // Cancel invitation
    cancelInvitation(organizationId: XID, invitationId: XID): Promise<APIResponse<void>>;

    // Accept invitation
    acceptInvitation(invitationToken: string): Promise<APIResponse<AcceptInvitationResponse>>;

    // Organization settings
    getOrganizationSettings(organizationId: XID): Promise<APIResponse<OrganizationSettingsResponse>>;
    updateOrganizationSettings(organizationId: XID, request: UpdateOrganizationSettingsRequest): Promise<APIResponse<OrganizationSettingsResponse>>;

    // Organization statistics
    getOrganizationStats(organizationId: XID): Promise<APIResponse<OrganizationStatsResponse>>;
}

// Session API
export interface SessionAPI {
    // Get current session
    getCurrentSession(): Promise<APIResponse<Session>>;

    // Get session by ID
    getSession(sessionId: XID): Promise<APIResponse<Session>>;

    // List user sessions
    listSessions(userId?: XID): Promise<APIResponse<SessionSummary[]>>;

    // Terminate session
    terminateSession(sessionId: XID): Promise<APIResponse<void>>;

    // Terminate all sessions
    terminateAllSessions(userId?: XID): Promise<APIResponse<TerminateSessionsResponse>>;

    // Update session
    updateSession(sessionId: XID, request: UpdateSessionRequest): Promise<APIResponse<Session>>;

    // Session activity
    getSessionActivity(sessionId: XID, params: SessionActivityParams): Promise<APIResponse<PaginatedResponse<SessionActivityRecord>>>;
}

// API request types
export interface SignInAPIRequest {
    identifier: string;
    password?: string;
    strategy: 'password' | 'oauth' | 'passkey' | 'magic_link';
    mfaCode?: string;
    rememberMe?: boolean;
    organizationId?: XID;
    redirectUrl?: string;
}

export interface SignUpAPIRequest {
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

export interface OAuthURLRequest {
    provider: string;
    redirectUrl?: string;
    state?: string;
    organizationId?: XID;
}

export interface OAuthCallbackRequest {
    provider: string;
    code: string;
    state?: string;
    organizationId?: XID;
}

export interface InitiateMFARequest {
    method: 'totp' | 'sms' | 'email';
    sessionId?: XID;
}

export interface VerifyMFARequest {
    challengeId: XID;
    code: string;
    rememberDevice?: boolean;
}

export interface PasskeyRegistrationRequest {
    userId?: XID;
    displayName?: string;
}

export interface CompletePasskeyRegistrationRequest {
    registrationId: XID;
    credential: any; // WebAuthn credential
}

export interface PasskeyAuthenticationRequest {
    identifier?: string;
    organizationId?: XID;
}

export interface CompletePasskeyAuthenticationRequest {
    authenticationId: XID;
    credential: any; // WebAuthn credential
}

// export interface PasswordResetRequest {
//     emailAddress: string;
//     organizationId?: XID;
// }

export interface PasswordUpdateRequest {
    token?: string;
    currentPassword?: string;
    newPassword: string;
}

export interface SendVerificationEmailRequest {
    emailAddress?: string;
    userId?: XID;
}

export interface VerifyEmailRequest {
    token: string;
}

export interface SendVerificationSMSRequest {
    phoneNumber?: string;
    userId?: XID;
}

export interface VerifyPhoneRequest {
    token: string;
    code: string;
}

export interface SendMagicLinkRequest {
    emailAddress: string;
    organizationId?: XID;
    redirectUrl?: string;
}

export interface VerifyMagicLinkRequest {
    token: string;
}

export interface UpdateUserProfileRequest {
    firstName?: string;
    lastName?: string;
    username?: string;
    bio?: string;
    website?: string;
    locale?: string;
    timezone?: string;
    metadata?: JSONObject;
}

export interface AddMemberRequest {
    userId?: XID;
    emailAddress?: string;
    roleId: XID;
    sendInvitation?: boolean;
}

export interface UpdateMemberRequest {
    roleId?: XID;
    status?: 'active' | 'inactive' | 'suspended';
}

// export interface CreateInvitationRequest {
//     emailAddress: string;
//     roleId: XID;
//     customMessage?: string;
//     expiresAt?: Timestamp;
// }

export interface UpdateOrganizationSettingsRequest {
    allowPublicSignup?: boolean;
    requireEmailVerification?: boolean;
    mfaRequired?: boolean;
    emailDomainRestrictions?: string[];
    ipWhitelist?: string[];
    customSettings?: JSONObject;
}

export interface UpdateSessionRequest {
    metadata?: JSONObject;
    extendExpiry?: boolean;
}

// API response types
export interface SignInAPIResponse {
    user: User;
    session: Session;
    organization?: Organization;
    requiresMfa?: boolean;
    mfaChallenge?: MFAChallengeResponse;
}

export interface SignUpAPIResponse {
    user: User;
    session?: Session;
    organization?: Organization;
    requiresVerification?: boolean;
    verificationMethods?: string[];
}

export interface RefreshSessionAPIResponse {
    session: Session;
    accessToken: string;
    refreshToken?: string;
}

export interface SessionVerificationResponse {
    valid: boolean;
    session?: Session;
    reason?: string;
}

export interface OAuthURLResponse {
    url: string;
    state: string;
}

export interface MFAChallengeResponse {
    challengeId: XID;
    method: string;
    message?: string;
    expiresAt: Timestamp;
}

export interface MFAVerificationResponse {
    success: boolean;
    session?: Session;
    backupCodes?: string[];
}

// export interface PasskeyRegistrationOptions {
//     registrationId: XID;
//     options: any; // WebAuthn registration options
// }

export interface PasskeyCredentialResponse {
    credentialId: XID;
    name: string;
    publicKey: string;
}

// export interface PasskeyAuthenticationOptions {
//     authenticationId: XID;
//     options: any; // WebAuthn authentication options
// }

export interface UserPermissionResponse {
    userId: XID;
    organizationId?: XID;
    permissions: string[];
    roles: string[];
}

export interface UserRoleResponse {
    userId: XID;
    organizationId?: XID;
    systemRoles: RoleInfo[];
    organizationRoles: RoleInfo[];
    applicationRoles: RoleInfo[];
}

export interface RoleInfo {
    id: XID;
    name: string;
    description?: string;
    permissions: string[];
}

export interface UserActivityRecord {
    id: XID;
    activityType: string;
    description: string;
    timestamp: Timestamp;
    ipAddress?: string;
    userAgent?: string;
    metadata?: JSONObject;
}

export interface UserStatsResponse {
    totalUsers: number;
    activeUsers: number;
    newUsers: number;
    userTypeBreakdown: Record<string, number>;
    activityStats: {
        dailyActiveUsers: number;
        weeklyActiveUsers: number;
        monthlyActiveUsers: number;
    };
}

export interface InvitationResponse {
    id: XID;
    organizationId: XID;
    emailAddress: string;
    roleId: XID;
    roleName: string;
    status: 'pending' | 'accepted' | 'expired' | 'revoked';
    token: string;
    expiresAt: Timestamp;
    createdAt: Timestamp;
    inviterName?: string;
}

export interface AcceptInvitationResponse {
    user: User;
    organization: Organization;
    membership: Membership;
    session?: Session;
}

export interface OrganizationSettingsResponse {
    organizationId: XID;
    allowPublicSignup: boolean;
    requireEmailVerification: boolean;
    mfaRequired: boolean;
    emailDomainRestrictions: string[];
    ipWhitelist: string[];
    customSettings: JSONObject;
}

export interface OrganizationStatsResponse {
    organizationId: XID;
    memberStats: {
        totalMembers: number;
        activeMembers: number;
        pendingInvitations: number;
    };
    activityStats: {
        dailyActiveUsers: number;
        weeklyActiveUsers: number;
        monthlyActiveUsers: number;
    };
    authStats: {
        totalLogins: number;
        mfaLogins: number;
        ssoLogins: number;
    };
}

export interface TerminateSessionsResponse {
    terminatedCount: number;
    failedCount: number;
    errors?: Array<{
        sessionId: XID;
        error: string;
    }>;
}

export interface SessionActivityRecord {
    id: XID;
    sessionId: XID;
    activityType: string;
    timestamp: Timestamp;
    ipAddress?: string;
    userAgent?: string;
    url?: string;
    metadata?: JSONObject;
}

// API query parameters
export interface ListUsersParams {
    organizationId?: XID;
    userType?: string;
    status?: string;
    search?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface SearchUsersParams {
    query: string;
    organizationId?: XID;
    userType?: string;
    fields?: string[];
    page?: number;
    limit?: number;
}

export interface ListOrganizationsParams {
    search?: string;
    orgType?: string;
    status?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface ListMembersParams {
    status?: string;
    roleId?: XID;
    search?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface ListInvitationsParams {
    status?: string;
    search?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface UserActivityParams {
    activityType?: string;
    startDate?: Timestamp;
    endDate?: Timestamp;
    page?: number;
    limit?: number;
}

export interface SessionActivityParams {
    activityType?: string;
    startDate?: Timestamp;
    endDate?: Timestamp;
    page?: number;
    limit?: number;
}