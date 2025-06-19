import type {AuthMethod, Organization, Session, User, XID} from '../types';

// Token utilities
export interface DecodedJWT {
    header: {
        alg: string;
        typ: string;
        kid?: string;
    };
    payload: {
        sub: XID;
        aud: string;
        iss: string;
        exp: number;
        iat: number;
        nbf?: number;
        jti?: XID;
        user_type?: string;
        organization_id?: XID;
        permissions?: string[];
        roles?: string[];
        mfa_verified?: boolean;
        device_id?: string;
        client_id?: string;
    };
    signature: string;
}

export const decodeJWT = (token: string): DecodedJWT | null => {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        const signature = parts[2];

        return { header, payload, signature };
    } catch {
        return null;
    }
};

export const isTokenExpired = (token: string): boolean => {
    const decoded = decodeJWT(token);
    if (!decoded) return true;

    const now = Math.floor(Date.now() / 1000);
    return decoded.payload.exp < now;
};

export const getTokenExpiration = (token: string): Date | null => {
    const decoded = decodeJWT(token);
    if (!decoded) return null;

    return new Date(decoded.payload.exp * 1000);
};

export const getTokenTimeToExpiry = (token: string): number => {
    const decoded = decodeJWT(token);
    if (!decoded) return 0;

    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, decoded.payload.exp - now);
};

// Session utilities
export const isSessionActive = (session: Session): boolean => {
    const now = new Date();
    const expiresAt = new Date(session.expiresAt);
    return session.isActive && expiresAt > now;
};

export const getSessionTimeRemaining = (session: Session): number => {
    const now = new Date();
    const expiresAt = new Date(session.expiresAt);
    return Math.max(0, expiresAt.getTime() - now.getTime());
};

export const formatSessionDuration = (session: Session): string => {
    const remaining = getSessionTimeRemaining(session);
    if (remaining === 0) return 'Expired';

    const hours = Math.floor(remaining / (1000 * 60 * 60));
    const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));

    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
};

// User utilities
export const getUserDisplayName = (user: User): string => {
    if (user.fullName) return user.fullName;
    if (user.firstName && user.lastName) return `${user.firstName} ${user.lastName}`;
    if (user.firstName) return user.firstName;
    if (user.username) return user.username;
    if (user.emailAddress) return user.emailAddress;
    return 'Unknown User';
};

export const getUserInitials = (user: User): string => {
    const displayName = getUserDisplayName(user);
    return displayName
        .split(' ')
        .map(name => name.charAt(0).toUpperCase())
        .slice(0, 2)
        .join('');
};

export const isUserVerified = (user: User): boolean => {
    return user.emailVerified && (user.phoneNumber ? user.phoneVerified : true);
};

export const getUserVerificationStatus = (user: User): {
    isVerified: boolean;
    emailVerified: boolean;
    phoneVerified: boolean;
    missingVerifications: string[];
} => {
    const missingVerifications: string[] = [];

    if (!user.emailVerified) missingVerifications.push('email');
    if (user.phoneNumber && !user.phoneVerified) missingVerifications.push('phone');

    return {
        isVerified: missingVerifications.length === 0,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified,
        missingVerifications,
    };
};

export const canUserAccessOrganization = (
    user: User,
    organizationId: XID
): boolean => {
    if (!user.organizations) return false;
    return user.organizations.some(org => org.id === organizationId);
};

export const getUserRoleInOrganization = (
    user: User,
    organizationId: XID
): string | null => {
    if (!user.organizations) return null;

    const org = user.organizations.find(org => org.id === organizationId);
    return org?.userRole || null;
};

export const getUserPermissionsInOrganization = (
    user: User,
    organizationId: XID
): string[] => {
    if (!user.organizations) return [];

    const org = user.organizations.find(org => org.id === organizationId);
    return org?.userPermissions || [];
};

export const hasPermission = (
    user: User,
    permission: string,
    organizationId?: XID
): boolean => {
    if (!user.permissions) return false;

    return user.permissions.some(perm => {
        if (perm.permissionName !== permission) return false;

        if (organizationId) {
            return perm.contextType === 'organization' && perm.contextId === organizationId;
        }

        return perm.contextType === 'system';
    });
};

export const hasRole = (
    user: User,
    role: string,
    organizationId?: XID
): boolean => {
    if (!user.roles) return false;

    return user.roles.some(userRole => {
        if (userRole.roleName !== role) return false;

        if (organizationId) {
            return userRole.contextType === 'organization' && userRole.contextId === organizationId;
        }

        return userRole.contextType === 'system';
    });
};

// Organization utilities
export const isUserOrganizationOwner = (
    user: User,
    organization: Organization
): boolean => {
    return organization.ownerId === user.id;
};

export const canUserManageOrganization = (
    user: User,
    organization: Organization
): boolean => {
    return (
        isUserOrganizationOwner(user, organization) ||
        hasRole(user, 'admin', organization.id) ||
        hasPermission(user, 'organization:manage', organization.id)
    );
};

export const canUserInviteMembers = (
    user: User,
    organization: Organization
): boolean => {
    return (
        isUserOrganizationOwner(user, organization) ||
        hasRole(user, 'admin', organization.id) ||
        hasPermission(user, 'members:invite', organization.id)
    );
};

// Authentication flow utilities
export const getRequiredAuthMethods = (methods: AuthMethod[]): AuthMethod[] => {
    const priority: Record<AuthMethod, number> = {
        'passkey': 1,
        'oauth': 2,
        'email': 3,
        'phone': 4,
        'username': 5,
        'mfa': 6,
        'magic_link': 7,
    };

    return methods.sort((a, b) => priority[a] - priority[b]);
};

export const isAuthMethodAvailable = (
    method: AuthMethod,
    enabledMethods: AuthMethod[]
): boolean => {
    return enabledMethods.includes(method);
};

export const getAuthMethodDisplayName = (method: AuthMethod): string => {
    const displayNames: Record<AuthMethod, string> = {
        'email': 'Email',
        'phone': 'Phone',
        'username': 'Username',
        'oauth': 'Social Login',
        'passkey': 'Passkey',
        'magic_link': 'Magic Link',
        'mfa': 'Multi-Factor Authentication',
    };

    return displayNames[method] || method;
};

// Password utilities
export const validatePasswordStrength = (password: string): {
    score: number;
    feedback: string[];
    isValid: boolean;
} => {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= 8) {
        score += 1;
    } else {
        feedback.push('Password must be at least 8 characters long');
    }

    // Character variety checks
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Include lowercase letters');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Include uppercase letters');

    if (/\d/.test(password)) score += 1;
    else feedback.push('Include numbers');

    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Include special characters');

    // Additional complexity checks
    if (password.length >= 12) score += 1;
    if (/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) score += 1;

    return {
        score: Math.min(score, 5),
        feedback,
        isValid: score >= 4,
    };
};

export const getPasswordStrengthLabel = (score: number): string => {
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    return labels[Math.min(score, 4)] || 'Very Weak';
};

export const isCommonPassword = (password: string): boolean => {
    const commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'dragon', 'master', 'login', 'welcome123'
    ];

    return commonPasswords.includes(password.toLowerCase());
};


export const formatBackupCode = (code: string): string => {
    return code.replace(/(.{4})/g, '$1-').replace(/-$/, '');
};

export const validateTOTPCode = (code: string): boolean => {
    return /^\d{6}$/.test(code);
};

export const validateSMSCode = (code: string): boolean => {
    return /^\d{4,8}$/.test(code);
};

export const validateBackupCode = (code: string): boolean => {
    return /^[A-Z0-9]{8}$/.test(code.replace(/-/g, ''));
};

// Device and location utilities
export const getDeviceInfo = (): {
    deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
    browser?: string;
    operatingSystem?: string;
    userAgent: string;
} => {
    const userAgent = navigator.userAgent;

    // Device type detection
    let deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown' = 'unknown';
    if (/Mobile|Android|iPhone|iPad/.test(userAgent)) {
        deviceType = /iPad/.test(userAgent) ? 'tablet' : 'mobile';
    } else if (/Windows|Mac|Linux/.test(userAgent)) {
        deviceType = 'desktop';
    }

    // Browser detection
    let browser: string | undefined;
    if (userAgent.includes('Chrome')) browser = 'Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Firefox';
    else if (userAgent.includes('Safari')) browser = 'Safari';
    else if (userAgent.includes('Edge')) browser = 'Edge';

    // OS detection
    let operatingSystem: string | undefined;
    if (userAgent.includes('Windows')) operatingSystem = 'Windows';
    else if (userAgent.includes('Mac')) operatingSystem = 'macOS';
    else if (userAgent.includes('Linux')) operatingSystem = 'Linux';
    else if (userAgent.includes('Android')) operatingSystem = 'Android';
    else if (userAgent.includes('iOS')) operatingSystem = 'iOS';

    return {
        deviceType,
        browser,
        operatingSystem,
        userAgent,
    };
};

// Passkey utilities
export const isPasskeySupported = (): boolean => {
    return !!(
        window.PublicKeyCredential &&
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        window.PublicKeyCredential.isConditionalMediationAvailable
    );
};

export const getPasskeySupport = async (): Promise<{
    supported: boolean;
    conditionalUI: boolean;
    platformAuthenticator: boolean;
}> => {
    if (!window.PublicKeyCredential) {
        return {
            supported: false,
            conditionalUI: false,
            platformAuthenticator: false,
        };
    }

    const [conditionalUI, platformAuthenticator] = await Promise.all([
        window.PublicKeyCredential.isConditionalMediationAvailable?.() || Promise.resolve(false),
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.() || Promise.resolve(false),
    ]);

    return {
        supported: true,
        conditionalUI,
        platformAuthenticator,
    };
};

// URL and redirect utilities
export const buildRedirectUrl = (
    baseUrl: string,
    params: Record<string, string | undefined>
): string => {
    const url = new URL(baseUrl);

    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) {
            url.searchParams.set(key, value);
        }
    }

    return url.toString();
};

export const parseAuthCallback = (url: string): {
    code?: string;
    state?: string;
    error?: string;
    error_description?: string;
} => {
    const urlObj = new URL(url);

    return {
        code: urlObj.searchParams.get('code') || undefined,
        state: urlObj.searchParams.get('state') || undefined,
        error: urlObj.searchParams.get('error') || undefined,
        error_description: urlObj.searchParams.get('error_description') || undefined,
    };
};

export const generateRandomState = (): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Security utilities
export const isSecureContext = (): boolean => {
    return window.isSecureContext;
};

export const requireSecureContext = (): void => {
    if (!isSecureContext()) {
        throw new Error('This operation requires a secure context (HTTPS)');
    }
};

export const sanitizeRedirectUrl = (url: string, allowedDomains: string[]): string | null => {
    try {
        const urlObj = new URL(url);

        if (allowedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith(`.${domain}`))) {
            return url;
        }

        return null;
    } catch {
        return null;
    }
};

// Event utilities
export const createAuthEvent = (
    type: string,
    data: Record<string, any> = {}
): CustomEvent => {
    return new CustomEvent(`frank-auth:${type}`, {
        detail: {
            timestamp: new Date().toISOString(),
            ...data,
        },
    });
};

export const dispatchAuthEvent = (
    type: string,
    data: Record<string, any> = {}
): void => {
    const event = createAuthEvent(type, data);
    window.dispatchEvent(event);
};