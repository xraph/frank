/**
 * @frank-auth/react - Provider Types
 *
 * Type definitions for all authentication providers including auth state,
 * configuration, theme, and organization context.
 */

import type {ReactNode} from 'react';

import type {
    AuthProvider,
    AuthStatus,
    MFAMethod,
    Organization,
    OrganizationSettings,
    PasskeySummary,
    Session,
    User,
    UserType,
} from '@frank-auth/client';

import type {
    AppearanceConfig,
    ComponentOverrides,
    FrankAuthUIConfig,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
} from '../config';
import {FrankAuth, FrankOrganization, FrankSession, FrankUser} from "@frank-auth/sdk";

// ============================================================================
// Auth State Types
// ============================================================================

/**
 * Authentication state
 */
export interface AuthState {
    // Loading states
    isLoaded: boolean;
    isLoading: boolean;

    // Authentication status
    isSignedIn: boolean;
    user: User | null;
    session: Session | null;

    // Organization context
    organization: Organization | null;
    organizationMemberships: OrganizationMembership[];
    activeOrganization: Organization | null;

    // Error state
    error: AuthError | null;

    // Feature availability
    features: AuthFeatures;
}

/**
 * Organization membership information
 */
export interface OrganizationMembership {
    organization: Organization;
    role: string;
    permissions: string[];
    joinedAt: Date;
    status: 'active' | 'invited' | 'suspended';
}

/**
 * Available authentication features
 */
export interface AuthFeatures {
    signUp: boolean;
    signIn: boolean;
    passwordReset: boolean;
    mfa: boolean;
    passkeys: boolean;
    oauth: boolean;
    magicLink: boolean;
    sso: boolean;
    organizationManagement: boolean;
    userProfile: boolean;
    sessionManagement: boolean;
}

/**
 * Authentication error
 */
export interface AuthError {
    code: string;
    message: string;
    details?: Record<string, any>;
    field?: string;
}

// ============================================================================
// Auth Context Types
// ============================================================================

/**
 * Authentication context methods
 */
export interface AuthContextMethods {
    // Authentication methods
    signIn: (params: SignInParams) => Promise<SignInResult>;
    signUp: (params: SignUpParams) => Promise<SignUpResult>;
    signOut: () => Promise<void>;

    // Session management
    createSession: (token: string) => Promise<Session>;
    setActive: (params: SetActiveParams) => Promise<void>;

    // Organization management
    setActiveOrganization: (organizationId: string) => Promise<void>;
    switchOrganization: (organizationId: string) => Promise<void>;

    // User management
    updateUser: (params: UpdateUserParams) => Promise<User>;
    deleteUser: () => Promise<void>;

    // Reload data
    reload: () => Promise<void>;

    frankAuth?: FrankAuth
    frankSess?: FrankSession
    frankOrg?: FrankOrganization
    frankUser?: FrankUser
}

/**
 * Authentication context value
 */
export interface AuthContextValue extends AuthState, AuthContextMethods {}

// ============================================================================
// Authentication Method Parameters
// ============================================================================

/**
 * Sign in parameters
 */
export interface SignInParams {
    strategy: 'password' | 'oauth' | 'magic_link' | 'passkey' | 'sso';
    identifier?: string;
    password?: string;
    code?: string;
    token?: string;
    provider?: string;
    redirectUrl?: string;
    organizationId?: string;
}

/**
 * Sign in result
 */
export interface SignInResult {
    status: 'complete' | 'needs_verification' | 'needs_mfa' | 'needs_passkey';
    user?: User;
    session?: Session;
    verificationId?: string;
    mfaToken?: string;
    error?: AuthError;
}

/**
 * Sign up parameters
 */
export interface SignUpParams {
    emailAddress?: string;
    phoneNumber?: string;
    locale?: string;
    username?: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    marketingConsent: boolean;
    acceptTerms: boolean;
    unsafeMetadata?: Record<string, any>;
    organizationId?: string;
    invitationToken?: string;
}

/**
 * Sign up result
 */
export interface SignUpResult {
    status: 'complete' | 'needs_verification' | 'missing_requirements';
    user?: User;
    session?: Session;
    verificationId?: string;
    error?: AuthError;
}

/**
 * Set active parameters
 */
export interface SetActiveParams {
    session?: Session | string | null;
    organization?: Organization | string | null;
}

/**
 * Update user parameters
 */
export interface UpdateUserParams {
    firstName?: string;
    lastName?: string;
    primaryEmailAddressId?: string;
    primaryPhoneNumberId?: string;
    profileImageUrl?: string;
    username?: string;
    unsafeMetadata?: Record<string, any>;
}

// ============================================================================
// Configuration Context Types
// ============================================================================

export interface LinksPathConfig {
    signIn?: string;
    signUp?: string;
    signOut?: string;
    verify?: string;
    resetPassword?: string;
    verifyPasskey?: string;
    magicLink?: string;
    forgotPassword?: string;
}

/**
 * Configuration state
 */
export interface ConfigState {
    isLoaded: boolean;
    config: FrankAuthUIConfig;
    publishableKey: string;
    userType: UserType;
    apiUrl: string;
    frontendUrl: string;

    // Organization-specific configuration
    organizationConfig?: OrganizationConfig;
    organizationSettings?: OrganizationSettings;

    // UI configuration
    theme: Theme;
    appearance: AppearanceConfig;
    localization: LocalizationConfig;
    components: ComponentOverrides;

    // Feature flags
    features: AuthFeatures;

    linksPath?: LinksPathConfig

    // Debug mode
    debug: boolean;
}

/**
 * Configuration context methods
 */
export interface ConfigContextMethods {
    updateConfig: (updates: Partial<FrankAuthUIConfig>) => void;
    setOrganization: (organization: Organization) => void;
    setTheme: (theme: Partial<Theme>) => void;
    setAppearance: (appearance: Partial<AppearanceConfig>) => void;
    setLocale: (locale: string) => void;
    applyOrganizationBranding: (organization: Organization) => void;
    resetToDefaults: () => void;
}

/**
 * Configuration context value
 */
export interface ConfigContextValue extends ConfigState, ConfigContextMethods {}

// ============================================================================
// Theme Context Types
// ============================================================================

/**
 * Theme state
 */
export interface ThemeState {
    theme: Theme;
    mode: 'light' | 'dark' | 'system';
    effectiveMode: 'light' | 'dark';
    isSystemMode: boolean;

    // CSS variables
    cssVariables: Record<string, string>;

    // Customization status
    isCustomized: boolean;
    organizationBranding?: {
        primaryColor?: string;
        secondaryColor?: string;
        logo?: string;
        customCSS?: string;
    };
}

/**
 * Theme context methods
 */
export interface ThemeContextMethods {
    setTheme: (theme: Partial<Theme>) => void;
    setMode: (mode: 'light' | 'dark' | 'system') => void;
    applyBranding: (branding: OrganizationBranding) => void;
    resetTheme: () => void;
    generateCSS: () => string;
}

/**
 * Theme context value
 */
export interface ThemeContextValue extends ThemeState, ThemeContextMethods {}

/**
 * Organization branding configuration
 */
export interface OrganizationBranding {
    primaryColor?: string;
    secondaryColor?: string;
    logo?: string;
    favicon?: string;
    customCSS?: string;
    fonts?: {
        primary?: string;
        secondary?: string;
    };
}

// ============================================================================
// Provider Props Types
// ============================================================================

/**
 * Auth provider props
 */
export interface AuthProviderProps {
    children: ReactNode;
    publishableKey: string;
    userType?: UserType;
    apiUrl?: string;
    organizationId?: string;
    initialState?: Partial<AuthState>;
    onError?: (error: AuthError) => void;
    onSignIn?: (user: User) => void;
    onSignOut?: () => void;
    debug?: boolean;
}

/**
 * Config provider props
 */
export interface ConfigProviderProps {
    children: ReactNode;
    config: Partial<FrankAuthUIConfig>;
    onConfigChange?: (config: FrankAuthUIConfig) => void;
}

/**
 * Theme provider props
 */
export interface ThemeProviderProps {
    children: ReactNode;
    theme?: Partial<Theme>;
    mode?: 'light' | 'dark' | 'system';
    organizationBranding?: OrganizationBranding;
    onThemeChange?: (theme: Theme) => void;
}

// ============================================================================
// Session Types
// ============================================================================

/**
 * Session context state
 */
export interface SessionState {
    isLoaded: boolean;
    sessions: Session[];
    activeSession: Session | null;
    error: AuthError | null;
}

/**
 * Session context methods
 */
export interface SessionContextMethods {
    createSession: (token: string) => Promise<Session>;
    setActiveSession: (sessionId: string) => Promise<void>;
    removeSession: (sessionId: string) => Promise<void>;
    removeAllSessions: () => Promise<void>;
    refreshSession: () => Promise<Session | null>;
    endSession: () => Promise<void>;
}

/**
 * Session context value
 */
export interface SessionContextValue extends SessionState, SessionContextMethods {}

// ============================================================================
// Organization Types
// ============================================================================

/**
 * Organization context state
 */
export interface OrganizationState {
    isLoaded: boolean;
    organizations: Organization[];
    activeOrganization: Organization | null;
    memberships: OrganizationMembership[];
    invitations: OrganizationInvitation[];
    error: AuthError | null;
}

/**
 * Organization invitation
 */
export interface OrganizationInvitation {
    id: string;
    organizationId: string;
    organizationName: string;
    inviterName?: string;
    inviterEmail?: string;
    role: string;
    status: 'pending' | 'accepted' | 'declined' | 'expired';
    expiresAt: Date;
    createdAt: Date;
}

/**
 * Organization context methods
 */
export interface OrganizationContextMethods {
    switchOrganization: (organizationId: string) => Promise<void>;
    createOrganization: (params: CreateOrganizationParams) => Promise<Organization>;
    updateOrganization: (organizationId: string, params: UpdateOrganizationParams) => Promise<Organization>;
    deleteOrganization: (organizationId: string) => Promise<void>;

    // Member management
    inviteMember: (params: InviteMemberParams) => Promise<void>;
    removeMember: (memberId: string) => Promise<void>;
    updateMemberRole: (memberId: string, role: string) => Promise<void>;

    // Invitation management
    acceptInvitation: (invitationId: string) => Promise<void>;
    declineInvitation: (invitationId: string) => Promise<void>;
}

/**
 * Organization context value
 */
export interface OrganizationContextValue extends OrganizationState, OrganizationContextMethods {}

/**
 * Create organization parameters
 */
export interface CreateOrganizationParams {
    name: string;
    slug?: string;
    description?: string;
    logoUrl?: string;
    websiteUrl?: string;
    settings?: Partial<OrganizationSettings>;
}

/**
 * Update organization parameters
 */
export interface UpdateOrganizationParams {
    name?: string;
    slug?: string;
    description?: string;
    logoUrl?: string;
    websiteUrl?: string;
    settings?: Partial<OrganizationSettings>;
}

/**
 * Invite member parameters
 */
export interface InviteMemberParams {
    emailAddress: string;
    role: string;
    redirectUrl?: string;
    publicMetadata?: Record<string, any>;
    privateMetadata?: Record<string, any>;
}

// ============================================================================
// Permission Types
// ============================================================================

/**
 * Permission context state
 */
export interface PermissionState {
    isLoaded: boolean;
    permissions: string[];
    roles: string[];
    context: PermissionContext;
    error: AuthError | null;
}

/**
 * Permission context
 */
export interface PermissionContext {
    type: 'system' | 'organization' | 'application';
    resourceId?: string;
    organizationId?: string;
    applicationId?: string;
}

/**
 * Permission context methods
 */
export interface PermissionContextMethods {
    hasPermission: (permission: string, context?: PermissionContext) => boolean;
    hasRole: (role: string, context?: PermissionContext) => boolean;
    hasAnyPermission: (permissions: string[], context?: PermissionContext) => boolean;
    hasAllPermissions: (permissions: string[], context?: PermissionContext) => boolean;
    can: (action: string, resource: string, context?: PermissionContext) => boolean;
    refreshPermissions: () => Promise<void>;
}

/**
 * Permission context value
 */
export interface PermissionContextValue extends PermissionState, PermissionContextMethods {}

// ============================================================================
// Export all types
// ============================================================================

export type {
    // Re-export client types for convenience
    User,
    Session,
    Organization,
    OrganizationSettings,
    AuthStatus,
    UserType,
    AuthProvider,
    MFAMethod,
    PasskeySummary,
};