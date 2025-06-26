/**
 * @frank-auth/react - Organization Configuration
 *
 * Organization-specific configuration management with support for
 * multi-tenant settings, branding, and feature customization.
 */

import type {
    AppearanceConfig,
    FrankAuthUIConfig,
    LocalizationConfig,
    OrganizationConfig,
    Theme,
    UserType,
} from './types';

import {DEFAULT_ORGANIZATION_CONFIG} from './defaults';
import {ThemeManager} from './theme';
import {AppearanceManager} from './appearance';

// ============================================================================
// Organization-Specific Types
// ============================================================================

/**
 * Organization feature flags with granular control
 */
export interface OrganizationFeatureFlags {
    // Authentication features
    authentication: {
        signUp: boolean;
        signIn: boolean;
        passwordReset: boolean;
        emailVerification: boolean;
        phoneVerification: boolean;
        socialAuth: boolean;
        magicLink: boolean;
        passkeys: boolean;
    };

    // Security features
    security: {
        mfa: boolean;
        mfaRequired: boolean;
        sso: boolean;
        sessionManagement: boolean;
        auditLogs: boolean;
        ipWhitelist: boolean;
        deviceTrust: boolean;
        riskAssessment: boolean;
    };

    // User management
    userManagement: {
        userProfiles: boolean;
        userRoles: boolean;
        userPermissions: boolean;
        userInvitations: boolean;
        userSuspension: boolean;
        userDeletion: boolean;
        bulkUserOperations: boolean;
    };

    // Organization features
    organization: {
        memberManagement: boolean;
        roleManagement: boolean;
        invitations: boolean;
        customBranding: boolean;
        customDomain: boolean;
        webhooks: boolean;
        apiAccess: boolean;
        analytics: boolean;
    };

    // UI features
    ui: {
        darkMode: boolean;
        customThemes: boolean;
        localization: boolean;
        customCSS: boolean;
        logoUpload: boolean;
        colorCustomization: boolean;
        layoutCustomization: boolean;
    };

    // Integration features
    integrations: {
        saml: boolean;
        oidc: boolean;
        ldap: boolean;
        scim: boolean;
        slack: boolean;
        microsoft: boolean;
        google: boolean;
        github: boolean;
    };
}

/**
 * Organization limits and quotas
 */
export interface OrganizationLimits {
    users: {
        maxUsers: number;
        maxEndUsers: number;
        maxExternalUsers: number;
        maxInternalUsers: number;
    };

    sessions: {
        maxSessionsPerUser: number;
        maxConcurrentSessions: number;
        sessionTimeout: number;
        maxSessionDuration: number;
    };

    api: {
        monthlyRequestLimit: number;
        rateLimit: number;
        burstLimit: number;
        maxWebhooks: number;
    };

    storage: {
        maxLogoSize: number;
        maxCustomCSSSize: number;
        auditLogRetention: number;
        maxCustomFields: number;
    };

    features: {
        maxRoles: number;
        maxPermissions: number;
        maxIntegrations: number;
        maxDomains: number;
    };
}

/**
 * Organization compliance settings
 */
export interface OrganizationCompliance {
    dataRetention: {
        userDataRetention: number; // days
        auditLogRetention: number; // days
        sessionLogRetention: number; // days
        automaticDeletion: boolean;
    };

    privacy: {
        gdprCompliant: boolean;
        ccpaCompliant: boolean;
        hipaaCompliant: boolean;
        soc2Compliant: boolean;
        dataProcessingAgreement: boolean;
    };

    security: {
        encryptionAtRest: boolean;
        encryptionInTransit: boolean;
        keyRotation: boolean;
        backupEncryption: boolean;
        accessLogging: boolean;
    };

    reporting: {
        complianceReports: boolean;
        auditReports: boolean;
        securityReports: boolean;
        dataExport: boolean;
        rightToBeForgotten: boolean;
    };
}

/**
 * Extended organization configuration
 */
export interface ExtendedOrganizationConfig extends OrganizationConfig {
    features: OrganizationFeatureFlags;
    limits: OrganizationLimits;
    compliance: OrganizationCompliance;

    // Computed properties
    tier: 'free' | 'starter' | 'professional' | 'enterprise';
    isActive: boolean;
    trialEndsAt?: Date;
    subscriptionStatus: 'active' | 'trialing' | 'past_due' | 'canceled' | 'unpaid';

    // Usage statistics
    usage: {
        currentUsers: number;
        currentEndUsers: number;
        monthlyApiRequests: number;
        storageUsed: number;
        lastActivityAt: Date;
    };
}

// ============================================================================
// Organization Configuration Manager
// ============================================================================

export class OrganizationConfigManager {
    private config: ExtendedOrganizationConfig;
    private themeManager: ThemeManager;
    private appearanceManager: AppearanceManager;
    private listeners: Set<(config: ExtendedOrganizationConfig) => void> = new Set();

    constructor(
        organizationConfig: Partial<ExtendedOrganizationConfig>,
        themeManager?: ThemeManager,
        appearanceManager?: AppearanceManager
    ) {
        this.config = this.mergeWithDefaults(organizationConfig);
        this.themeManager = themeManager || new ThemeManager();
        this.appearanceManager = appearanceManager || new AppearanceManager();

        // Apply organization branding
        this.applyOrganizationBranding();
    }

    /**
     * Get current organization configuration
     */
    getConfig(): ExtendedOrganizationConfig {
        return { ...this.config };
    }

    /**
     * Update organization configuration
     */
    updateConfig(updates: Partial<ExtendedOrganizationConfig>): void {
        this.config = {
            ...this.config,
            ...updates,
            settings: { ...this.config.settings, ...updates.settings },
            features: { ...this.config.features, ...updates.features },
            limits: { ...this.config.limits, ...updates.limits },
            compliance: { ...this.config.compliance, ...updates.compliance },
            usage: { ...this.config.usage, ...updates.usage },
        };

        // Re-apply branding if branding settings changed
        if (updates.settings?.branding) {
            this.applyOrganizationBranding();
        }

        this.notifyListeners();
    }

    /**
     * Check if a feature is enabled
     */
    isFeatureEnabled(featurePath: string): boolean {
        const keys = featurePath.split('.');
        let current: any = this.config.features;

        for (const key of keys) {
            if (current?.[key] === undefined) {
                return false;
            }
            current = current[key];
        }

        return Boolean(current);
    }

    /**
     * Check if a user type is allowed
     */
    isUserTypeAllowed(userType: UserType): boolean {
        switch (userType) {
            case 'internal':
                return this.config.tier === 'enterprise';
            case 'external':
                return this.isFeatureEnabled('userManagement.userProfiles');
            case 'end_user':
                return true; // Always allowed
            default:
                return false;
        }
    }

    /**
     * Get user limits for a specific user type
     */
    getUserLimits(userType: UserType): number {
        switch (userType) {
            case 'internal':
                return this.config.limits.users.maxInternalUsers;
            case 'external':
                return this.config.limits.users.maxExternalUsers;
            case 'end_user':
                return this.config.limits.users.maxEndUsers;
            default:
                return 0;
        }
    }

    /**
     * Check if organization is within limits
     */
    checkLimits(): {
        withinLimits: boolean;
        violations: Array<{ type: string; current: number; limit: number }>;
    } {
        const violations: Array<{ type: string; current: number; limit: number }> = [];

        // Check user limits
        if (this.config.usage.currentUsers > this.config.limits.users.maxUsers) {
            violations.push({
                type: 'users',
                current: this.config.usage.currentUsers,
                limit: this.config.limits.users.maxUsers,
            });
        }

        if (this.config.usage.currentEndUsers > this.config.limits.users.maxEndUsers) {
            violations.push({
                type: 'endUsers',
                current: this.config.usage.currentEndUsers,
                limit: this.config.limits.users.maxEndUsers,
            });
        }

        // Check API limits
        if (this.config.usage.monthlyApiRequests > this.config.limits.api.monthlyRequestLimit) {
            violations.push({
                type: 'apiRequests',
                current: this.config.usage.monthlyApiRequests,
                limit: this.config.limits.api.monthlyRequestLimit,
            });
        }

        return {
            withinLimits: violations.length === 0,
            violations,
        };
    }

    /**
     * Get organization tier configuration
     */
    getTierConfig(): {
        name: string;
        features: string[];
        limits: Record<string, number>;
        price?: string;
    } {
        const tierConfigs = {
            free: {
                name: 'Free',
                features: [
                    'Basic authentication',
                    'Up to 100 users',
                    'Email support',
                ],
                limits: {
                    users: 100,
                    apiRequests: 1000,
                    sessions: 5,
                },
            },
            starter: {
                name: 'Starter',
                price: '$29/month',
                features: [
                    'Everything in Free',
                    'Up to 1,000 users',
                    'MFA support',
                    'Basic branding',
                    'Priority support',
                ],
                limits: {
                    users: 1000,
                    apiRequests: 10000,
                    sessions: 10,
                },
            },
            professional: {
                name: 'Professional',
                price: '$99/month',
                features: [
                    'Everything in Starter',
                    'Up to 10,000 users',
                    'SSO integration',
                    'Advanced branding',
                    'API access',
                    'Webhooks',
                    'Audit logs',
                ],
                limits: {
                    users: 10000,
                    apiRequests: 100000,
                    sessions: 25,
                },
            },
            enterprise: {
                name: 'Enterprise',
                price: 'Custom',
                features: [
                    'Everything in Professional',
                    'Unlimited users',
                    'SAML/LDAP integration',
                    'Custom domain',
                    'Advanced security',
                    'Compliance features',
                    'Dedicated support',
                ],
                limits: {
                    users: -1, // Unlimited
                    apiRequests: -1, // Unlimited
                    sessions: -1, // Unlimited
                },
            },
        };

        return tierConfigs[this.config.tier];
    }

    /**
     * Generate UI configuration based on organization settings
     */
    generateUIConfig(): Partial<FrankAuthUIConfig> {
        const baseConfig: Partial<FrankAuthUIConfig> = {
            projectId: this.config.id,
            organization: this.config,
            features: {
                signUp: this.isFeatureEnabled('authentication.signUp'),
                signIn: this.isFeatureEnabled('authentication.signIn'),
                passwordReset: this.isFeatureEnabled('authentication.passwordReset'),
                mfa: this.isFeatureEnabled('security.mfa'),
                sso: this.isFeatureEnabled('security.sso'),
                organizationManagement: this.isFeatureEnabled('organization.memberManagement'),
                userProfile: this.isFeatureEnabled('userManagement.userProfiles'),
                sessionManagement: this.isFeatureEnabled('security.sessionManagement'),
            },
        };

        // Apply theme customization if enabled
        if (this.isFeatureEnabled('ui.customThemes')) {
            baseConfig.theme = this.generateCustomTheme();
        }

        // Apply appearance customization if enabled
        if (this.isFeatureEnabled('ui.customThemes')) {
            baseConfig.appearance = this.generateCustomAppearance();
        }

        // Apply localization if enabled
        if (this.isFeatureEnabled('ui.localization')) {
            baseConfig.localization = this.generateLocalizationConfig();
        }

        return baseConfig;
    }

    /**
     * Subscribe to configuration changes
     */
    subscribe(callback: (config: ExtendedOrganizationConfig) => void): () => void {
        this.listeners.add(callback);
        return () => {
            this.listeners.delete(callback);
        };
    }

    /**
     * Validate organization configuration
     */
    validateConfig(): {
        isValid: boolean;
        errors: string[];
        warnings: string[];
    } {
        const errors: string[] = [];
        const warnings: string[] = [];

        // Validate required fields
        if (!this.config.id) {
            errors.push('Organization ID is required');
        }

        if (!this.config.name) {
            errors.push('Organization name is required');
        }

        // Validate limits
        const { withinLimits, violations } = this.checkLimits();
        if (!withinLimits) {
            violations.forEach(violation => {
                warnings.push(`${violation.type} limit exceeded: ${violation.current}/${violation.limit}`);
            });
        }

        // Validate branding
        if (this.config.settings.branding?.logo && !this.isValidUrl(this.config.settings.branding.logo)) {
            errors.push('Invalid logo URL');
        }

        // Validate feature consistency
        if (this.isFeatureEnabled('security.mfaRequired') && !this.isFeatureEnabled('security.mfa')) {
            errors.push('MFA must be enabled if MFA is required');
        }

        if (this.isFeatureEnabled('organization.customDomain') && this.config.tier === 'free') {
            warnings.push('Custom domain requires paid plan');
        }

        return {
            isValid: errors.length === 0,
            errors,
            warnings,
        };
    }

    // Private methods

    private mergeWithDefaults(config: Partial<ExtendedOrganizationConfig>): ExtendedOrganizationConfig {
        const defaultFeatures: OrganizationFeatureFlags = {
            authentication: {
                signUp: true,
                signIn: true,
                passwordReset: true,
                emailVerification: true,
                phoneVerification: false,
                socialAuth: false,
                magicLink: false,
                passkeys: false,
            },
            security: {
                mfa: false,
                mfaRequired: false,
                sso: false,
                sessionManagement: true,
                auditLogs: false,
                ipWhitelist: false,
                deviceTrust: false,
                riskAssessment: false,
            },
            userManagement: {
                userProfiles: true,
                userRoles: false,
                userPermissions: false,
                userInvitations: true,
                userSuspension: false,
                userDeletion: false,
                bulkUserOperations: false,
            },
            organization: {
                memberManagement: true,
                roleManagement: false,
                invitations: true,
                customBranding: false,
                customDomain: false,
                webhooks: false,
                apiAccess: false,
                analytics: false,
            },
            ui: {
                darkMode: true,
                customThemes: false,
                localization: true,
                customCSS: false,
                logoUpload: false,
                colorCustomization: false,
                layoutCustomization: false,
            },
            integrations: {
                saml: false,
                oidc: false,
                ldap: false,
                scim: false,
                slack: false,
                microsoft: false,
                google: false,
                github: false,
            },
        };

        const defaultLimits: OrganizationLimits = {
            users: {
                maxUsers: 100,
                maxEndUsers: 1000,
                maxExternalUsers: 50,
                maxInternalUsers: 5,
            },
            sessions: {
                maxSessionsPerUser: 5,
                maxConcurrentSessions: 100,
                sessionTimeout: 1800, // 30 minutes
                maxSessionDuration: 86400, // 24 hours
            },
            api: {
                monthlyRequestLimit: 1000,
                rateLimit: 100, // per minute
                burstLimit: 200,
                maxWebhooks: 3,
            },
            storage: {
                maxLogoSize: 1024 * 1024, // 1MB
                maxCustomCSSSize: 50 * 1024, // 50KB
                auditLogRetention: 90, // days
                maxCustomFields: 10,
            },
            features: {
                maxRoles: 10,
                maxPermissions: 50,
                maxIntegrations: 5,
                maxDomains: 1,
            },
        };

        const defaultCompliance: OrganizationCompliance = {
            dataRetention: {
                userDataRetention: 365,
                auditLogRetention: 90,
                sessionLogRetention: 30,
                automaticDeletion: false,
            },
            privacy: {
                gdprCompliant: false,
                ccpaCompliant: false,
                hipaaCompliant: false,
                soc2Compliant: false,
                dataProcessingAgreement: false,
            },
            security: {
                encryptionAtRest: true,
                encryptionInTransit: true,
                keyRotation: false,
                backupEncryption: false,
                accessLogging: true,
            },
            reporting: {
                complianceReports: false,
                auditReports: false,
                securityReports: false,
                dataExport: false,
                rightToBeForgotten: false,
            },
        };

        return {
            ...DEFAULT_ORGANIZATION_CONFIG,
            ...config,
            features: { ...defaultFeatures, ...config.features },
            limits: { ...defaultLimits, ...config.limits },
            compliance: { ...defaultCompliance, ...config.compliance },
            tier: config.tier || 'free',
            isActive: config.isActive ?? true,
            subscriptionStatus: config.subscriptionStatus || 'active',
            usage: {
                currentUsers: 0,
                currentEndUsers: 0,
                monthlyApiRequests: 0,
                storageUsed: 0,
                lastActivityAt: new Date(),
                ...config.usage,
            },
        } as ExtendedOrganizationConfig;
    }

    private applyOrganizationBranding(): void {
        if (this.config.settings.branding) {
            // Apply to theme manager
            this.themeManager.applyBranding({
                logo: {
                    url: this.config.settings.branding.logo,
                    alt: this.config.name,
                },
                colors: {
                    primary: this.config.settings.branding.primaryColor || '#3b82f6',
                    secondary: this.config.settings.branding.secondaryColor || '#64748b',
                },
                fonts: {
                    primary: 'Inter, ui-sans-serif, system-ui, sans-serif',
                },
                customCSS: this.config.settings.branding.customCSS,
            });

            // Apply to appearance manager
            this.appearanceManager.applyOrganizationBranding(this.config);
        }
    }

    private generateCustomTheme(): Partial<Theme> {
        if (!this.isFeatureEnabled('ui.customThemes')) return {};

        return this.themeManager.getTheme();
    }

    private generateCustomAppearance(): Partial<AppearanceConfig> {
        if (!this.isFeatureEnabled('ui.customThemes')) return {};

        return this.appearanceManager.getConfig();
    }

    private generateLocalizationConfig(): Partial<LocalizationConfig> {
        if (!this.isFeatureEnabled('ui.localization')) return {};

        // Return basic localization config
        // In a real implementation, this might be customizable per organization
        return {
            defaultLocale: 'en',
            supportedLocales: ['en', 'es', 'fr'],
        };
    }

    private isValidUrl(url: string): boolean {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    private notifyListeners(): void {
        this.listeners.forEach(callback => callback(this.config));
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create organization configuration manager
 */
export function createOrganizationConfigManager(
    config: Partial<ExtendedOrganizationConfig>,
    themeManager?: ThemeManager,
    appearanceManager?: AppearanceManager
): OrganizationConfigManager {
    return new OrganizationConfigManager(config, themeManager, appearanceManager);
}

/**
 * Transform organization settings from API to UI config
 */
export function transformOrganizationSettings(
    apiSettings: any
): Partial<ExtendedOrganizationConfig> {
    return {
        id: apiSettings.id,
        name: apiSettings.name,
        slug: apiSettings.slug,
        settings: {
            allowPublicSignup: apiSettings.allowPublicSignup,
            requireEmailVerification: apiSettings.requireEmailVerification,
            requirePhoneVerification: apiSettings.requirePhoneVerification,
            allowedDomains: apiSettings.allowedDomains,
            mfaRequired: apiSettings.mfaSettings?.required,
            allowedMfaMethods: apiSettings.mfaSettings?.allowedMethods || [],
            passwordPolicy: apiSettings.passwordPolicy,
            sessionSettings: apiSettings.sessionSettings,
            branding: apiSettings.branding,
            customFields: apiSettings.customFields,
        },
        features: {
            // Map API features to UI feature flags
            authentication: {
                signUp: apiSettings.allowPublicSignup,
                signIn: true,
                passwordReset: true,
                emailVerification: apiSettings.requireEmailVerification,
                phoneVerification: apiSettings.requirePhoneVerification,
                socialAuth: apiSettings.ssoEnabled,
                magicLink: apiSettings.features?.magicLink || false,
                passkeys: apiSettings.features?.passkeys || false,
            },
            security: {
                mfa: apiSettings.mfaSettings?.enabled || false,
                mfaRequired: apiSettings.mfaSettings?.required || false,
                sso: apiSettings.ssoEnabled || false,
                sessionManagement: true,
                auditLogs: apiSettings.features?.auditLogs || false,
                ipWhitelist: apiSettings.features?.ipWhitelist || false,
                deviceTrust: apiSettings.features?.deviceTrust || false,
                riskAssessment: apiSettings.features?.riskAssessment || false,
            },
            // ... other feature mappings
        } as OrganizationFeatureFlags,
        tier: apiSettings.plan?.tier || 'free',
        isActive: apiSettings.active,
        subscriptionStatus: apiSettings.subscription?.status || 'active',
        usage: {
            currentUsers: apiSettings.stats?.currentUsers || 0,
            currentEndUsers: apiSettings.stats?.currentEndUsers || 0,
            monthlyApiRequests: apiSettings.stats?.monthlyApiRequests || 0,
            storageUsed: apiSettings.stats?.storageUsed || 0,
            lastActivityAt: new Date(apiSettings.stats?.lastActivityAt || Date.now()),
        },
    };
}

/**
 * Get feature availability by tier
 */
export function getFeaturesByTier(tier: 'free' | 'starter' | 'professional' | 'enterprise'): Partial<OrganizationFeatureFlags> {
    const tierFeatures = {
        free: {
            authentication: { signUp: true, signIn: true, passwordReset: true },
            security: { sessionManagement: true },
            userManagement: { userProfiles: true, userInvitations: true },
            organization: { memberManagement: true, invitations: true },
            ui: { darkMode: true, localization: true },
        },
        starter: {
            // All free features plus:
            security: { mfa: true },
            ui: { customThemes: true, logoUpload: true },
            organization: { customBranding: true },
        },
        professional: {
            // All starter features plus:
            security: { sso: true, auditLogs: true },
            organization: { webhooks: true, apiAccess: true, analytics: true },
            integrations: { saml: true, oidc: true },
            ui: { customCSS: true, colorCustomization: true },
        },
        enterprise: {
            // All professional features plus:
            security: { ipWhitelist: true, deviceTrust: true, riskAssessment: true },
            organization: { customDomain: true },
            integrations: { ldap: true, scim: true },
            userManagement: { bulkUserOperations: true },
            ui: { layoutCustomization: true },
        },
    };

    // Merge features for the tier and all lower tiers
    const tierOrder = ['free', 'starter', 'professional', 'enterprise'];
    const tierIndex = tierOrder.indexOf(tier);

    let features = {};
    for (let i = 0; i <= tierIndex; i++) {
        features = { ...features, ...tierFeatures[tierOrder[i] as keyof typeof tierFeatures] };
    }

    return features as Partial<OrganizationFeatureFlags>;
}

// ============================================================================
// Export organization utilities
// ============================================================================

export {
    DEFAULT_ORGANIZATION_CONFIG,
};