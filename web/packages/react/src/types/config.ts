import type {JSONObject, XID} from './index';
import type {AuthMethod, OAuthProvider} from './auth';
import type {ComponentType, ReactNode} from 'react';

export type SizeT = 'xs' | 'sm' | 'md' | 'lg' | 'xl';
export type RadiusT = 'none' | 'sm' | 'md' | 'lg' | 'xl';
export type ShadowT = 'none' | 'sm' | 'md' | 'lg' | 'xl';

// Main configuration interface
export interface FrankAuthConfig {
    // Core settings
    publishableKey: string;
    apiUrl?: string;
    environment?: 'development' | 'staging' | 'production';

    // Organization context
    organizationId?: XID;
    allowOrganizationSwitching?: boolean;

    // Authentication configuration
    authentication: AuthenticationConfig;

    // UI appearance configuration
    appearance: AppearanceConfig;

    // Localization configuration
    localization: LocalizationConfig;

    // Component configuration
    components: ComponentConfig;

    // Feature flags
    features: FeatureConfig;

    // Routing configuration
    routing: RoutingConfig;

    // Session configuration
    session: SessionConfig;

    // Custom configuration
    custom?: JSONObject;
}

// Authentication configuration
export interface AuthenticationConfig {
    // Enabled authentication methods
    methods: AuthMethod[];

    // Primary authentication method
    primaryMethod: AuthMethod;

    // Sign-in configuration
    signIn: SignInConfig;

    // Sign-up configuration
    signUp: SignUpConfig;

    // OAuth configuration
    oauth: OAuthConfig;

    // MFA configuration
    mfa: MFAConfig;

    // Passkey configuration
    passkeys: PasskeyConfig;

    // Password configuration
    password: PasswordConfig;

    // Verification configuration
    verification: VerificationConfig;
}

// Sign-in configuration
export interface SignInConfig {
    enabled: boolean;
    allowedMethods: AuthMethod[];
    defaultMethod: AuthMethod;
    showAlternativeMethods: boolean;
    allowRememberMe: boolean;
    requireEmailVerification: boolean;
    allowPasswordReset: boolean;
    redirectUrl?: string;
    afterSignInUrl?: string;
    maxAttempts?: number;
    lockoutDuration?: number;
}

// Sign-up configuration
export interface SignUpConfig {
    enabled: boolean;
    allowedMethods: AuthMethod[];
    defaultMethod: AuthMethod;
    requireEmailVerification: boolean;
    requirePhoneVerification: boolean;
    allowedFields: string[];
    requiredFields: string[];
    captchaEnabled: boolean;
    termsOfServiceUrl?: string;
    privacyPolicyUrl?: string;
    redirectUrl?: string;
    afterSignUpUrl?: string;
}

// OAuth configuration
export interface OAuthConfig {
    enabled: boolean;
    providers: OAuthProviderConfig[];
    allowAccountLinking: boolean;
    popupMode: boolean;
    redirectMode: 'popup' | 'redirect';
}

export interface OAuthProviderConfig {
    provider: OAuthProvider;
    enabled: boolean;
    clientId?: string;
    scopes?: string[];
    buttonText?: string;
    buttonIcon?: string;
    buttonStyle?: 'full' | 'icon' | 'minimal';
    customParameters?: Record<string, string>;
    redirectUrl?: string;
}

// MFA configuration
export interface MFAConfig {
    enabled: boolean;
    required: boolean;
    allowedMethods: ('totp' | 'sms' | 'email' | 'backup_codes')[];
    defaultMethod: 'totp' | 'sms' | 'email';
    backupCodesEnabled: boolean;
    gracePeriod?: number;
    rememberDevice: boolean;
    rememberDeviceDuration?: number;
}

// Passkey configuration
export interface PasskeyConfig {
    enabled: boolean;
    allowRegistration: boolean;
    allowAuthentication: boolean;
    requireUserVerification: boolean;
    rpName: string;
    rpId?: string;
    timeout?: number;
    attestation?: 'none' | 'indirect' | 'direct';
}

// Password configuration
export interface PasswordConfig {
    enabled: boolean;
    minLength: number;
    maxLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSymbols: boolean;
    allowCommonPasswords: boolean;
    maxAge?: number;
    historyCount?: number;
    showStrengthIndicator: boolean;
    allowPasswordManager: boolean;
}

// Verification configuration
export interface VerificationConfig {
    email: {
        enabled: boolean;
        required: boolean;
        allowResend: boolean;
        resendCooldown: number;
        expirationTime: number;
        template?: string;
    };
    phone: {
        enabled: boolean;
        required: boolean;
        allowResend: boolean;
        resendCooldown: number;
        expirationTime: number;
        allowedCountries?: string[];
        blockedCountries?: string[];
    };
}

// Appearance configuration
export interface AppearanceConfig {
    // Theme configuration
    theme: ThemeConfig;

    // Layout configuration
    layout: LayoutConfig;

    // Branding configuration
    branding: BrandingConfig;

    // Component styling
    elements: ElementConfig;

    // Color scheme
    colorScheme: 'light' | 'dark' | 'system';

    // Custom CSS
    customCSS?: string;
}

// Theme configuration
export interface ThemeConfig {
    primary: string;
    secondary: string;
    accent: string;
    background: string;
    foreground: string;
    muted: string;
    border: string;
    input: string;
    ring: string;
    destructive: string;
    warning: string;
    success: string;
    info: string;
}

// Layout configuration
export interface LayoutConfig {
    containerMaxWidth: string
    sidebarWidth: string
    headerHeight: string
    footerHeight: string
    contentPadding: string

    // Card layout
    card: {
        width: 'sm' | 'md' | 'lg' | 'xl' | 'full';
        padding: 'sm' | 'md' | 'lg';
        rounded: 'none' | 'sm' | 'md' | 'lg' | 'xl';
        shadow: 'none' | 'sm' | 'md' | 'lg' | 'xl';
        border: boolean;
    };

    // Modal layout
    modal: {
        size: 'sm' | 'md' | 'lg' | 'xl' | 'full';
        overlay: boolean;
        closeOnOverlayClick: boolean;
        showCloseButton: boolean;
    };

    // Form layout
    form: {
        spacing: 'sm' | 'md' | 'lg';
        labelPosition: 'top' | 'left' | 'floating';
        buttonSize: 'sm' | 'md' | 'lg';
        buttonWidth: 'auto' | 'full';
    };
}

// Branding configuration
export interface BrandingConfig {
    logo?: string;
    logoUrl?: string;
    favicon?: string;
    applicationName?: string;
    tagline?: string;
    supportEmail?: string;
    supportUrl?: string;
    termsOfServiceUrl?: string;
    privacyPolicyUrl?: string;
    showPoweredBy: boolean;
}

// Element styling configuration
export interface ElementConfig {
    // Global styles
    fontFamily?: string;
    fontSize?: 'xs' | 'sm' | 'base' | 'lg' | 'xl';

    // Button styles
    button?: {
        primary?: string;
        secondary?: string;
        outline?: string;
        ghost?: string;
        destructive?: string;
    };

    // Input styles
    input?: {
        base?: string;
        focus?: string;
        error?: string;
        disabled?: string;
    };

    // Card styles
    card?: {
        base?: string;
        header?: string;
        body?: string;
        footer?: string;
    };

    // Form styles
    form?: {
        label?: string;
        error?: string;
        helper?: string;
    };

    // Link styles
    link?: {
        base?: string;
        hover?: string;
        visited?: string;
    };
}

// Localization configuration
export interface LocalizationConfig {
    // Default locale
    defaultLocale: string;

    // Available locales
    availableLocales: string[];

    // Allow locale switching
    allowLocaleSwitching: boolean;

    // Custom translations
    customTranslations?: Record<string, Record<string, string>>;

    // Date/time formatting
    dateFormat: string;
    timeFormat: string;
    timezone?: string;

    // Number formatting
    numberFormat: {
        locale: string;
        currency?: string;
    };
}

// Component configuration
export interface ComponentConfig {
    // Global component props
    globalProps?: Record<string, any>;

    // Component overrides
    overrides?: ComponentOverrides;

    // Component slots
    slots?: ComponentSlots;

    // Custom components
    customComponents?: CustomComponents;
}

// Component overrides
export interface ComponentOverrides {
    // Authentication components
    SignIn?: ComponentOverride;
    SignUp?: ComponentOverride;
    UserButton?: ComponentOverride;
    UserProfile?: ComponentOverride;

    // Organization components
    OrganizationSwitcher?: ComponentOverride;
    OrganizationProfile?: ComponentOverride;

    // Form components
    PasswordField?: ComponentOverride;
    EmailField?: ComponentOverride;
    PhoneField?: ComponentOverride;

    // Layout components
    AuthLayout?: ComponentOverride;
    ModalLayout?: ComponentOverride;
    CardLayout?: ComponentOverride;
}

export interface ComponentOverride {
    props?: Record<string, any>;
    className?: string;
    style?: Record<string, any>;
    replace?: ComponentType<any>;
    wrapper?: ComponentType<any>;
}

// Component slots
export interface ComponentSlots {
    beforeSignIn?: ReactNode;
    afterSignIn?: ReactNode;
    beforeSignUp?: ReactNode;
    afterSignUp?: ReactNode;
    header?: ReactNode;
    footer?: ReactNode;
    sidebar?: ReactNode;
    loading?: ReactNode;
    error?: ReactNode;
}

// Custom components
export interface CustomComponents {
    LoadingSpinner?: ComponentType<any>;
    ErrorBoundary?: ComponentType<any>;
    SuccessMessage?: ComponentType<any>;
    ErrorMessage?: ComponentType<any>;
    Avatar?: ComponentType<any>;
    Button?: ComponentType<any>;
    Input?: ComponentType<any>;
    Card?: ComponentType<any>;
    Modal?: ComponentType<any>;
}

// Feature configuration
export interface FeatureConfig {
    // Authentication features
    signIn: boolean;
    signUp: boolean;
    userProfile: boolean;
    passwordReset: boolean;
    emailVerification: boolean;
    phoneVerification: boolean;

    // Organization features
    organizations: boolean;
    organizationSwitcher: boolean;
    organizationProfile: boolean;
    memberManagement: boolean;
    roleManagement: boolean;

    // Security features
    mfa: boolean;
    passkeys: boolean;
    sessionManagement: boolean;
    deviceManagement: boolean;
    auditLog: boolean;

    // Advanced features
    impersonation: boolean;
    bulkOperations: boolean;
    apiKeys: boolean;
    webhooks: boolean;

    // UI features
    darkMode: boolean;
    customBranding: boolean;
    localization: boolean;
    accessibility: boolean;
}

// Routing configuration
export interface RoutingConfig {
    // Base paths
    basePath: string;
    signInPath: string;
    signUpPath: string;
    userProfilePath: string;
    organizationProfilePath: string;

    // Redirect URLs
    afterSignInUrl: string;
    afterSignUpUrl: string;
    afterSignOutUrl: string;

    // Protected routes
    protectedRoutes: string[];
    publicRoutes: string[];

    // Custom redirects
    customRedirects?: Record<string, string>;
}

// Session configuration
export interface SessionConfig {
    // Session duration
    duration: number;

    // Inactivity timeout
    inactivityTimeout: number;

    // Refresh token rotation
    refreshTokenRotation: boolean;

    // Session storage
    storage: 'cookie' | 'localStorage' | 'sessionStorage';

    // Cookie configuration
    cookie: {
        name: string;
        domain?: string;
        secure: boolean;
        sameSite: 'strict' | 'lax' | 'none';
        httpOnly: true;
    };

    // Session monitoring
    monitoring: {
        enabled: boolean;
        trackActivity: boolean;
        trackLocation: boolean;
        trackDevice: boolean;
    };
}

// Server-side configuration
export interface ServerConfig {
    // Organization-specific configuration
    organizationConfig?: OrganizationSpecificConfig;

    // Feature flags
    featureFlags?: Record<string, boolean>;

    // Branding overrides
    brandingOverrides?: BrandingConfig;

    // Authentication policies
    authenticationPolicies?: AuthenticationPolicies;

    // UI customization
    uiCustomization?: UICustomization;
}

// Organization-specific configuration
export interface OrganizationSpecificConfig {
    organizationId: XID;
    customDomain?: string;
    customBranding?: BrandingConfig;
    authenticationMethods?: AuthMethod[];
    mfaRequired?: boolean;
    allowedEmailDomains?: string[];
    customCSS?: string;
    customComponents?: CustomComponents;
    featureOverrides?: Partial<FeatureConfig>;
}

// Authentication policies
export interface AuthenticationPolicies {
    passwordPolicy: {
        minLength: number;
        maxLength: number;
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
        allowedMethods: string[];
        gracePeriod?: number;
    };

    lockoutPolicy: {
        enabled: boolean;
        maxAttempts: number;
        lockoutDuration: number;
    };
}

// UI customization
export interface UICustomization {
    // Custom CSS
    customCSS?: string;

    // Custom components
    customComponents?: Record<string, ComponentType<any>>;

    // Custom themes
    customThemes?: Record<string, ThemeConfig>;

    // Custom layouts
    customLayouts?: Record<string, ComponentType<any>>;

    // Custom translations
    customTranslations?: Record<string, Record<string, string>>;
}

// Configuration validation
export interface ConfigValidation {
    valid: boolean;
    errors: string[];
    warnings: string[];
}

// Configuration defaults
export const DEFAULT_CONFIG: Partial<FrankAuthConfig> = {
    authentication: {
        methods: ['email', 'oauth'],
        primaryMethod: 'email',
        signIn: {
            enabled: true,
            allowedMethods: ['email', 'oauth'],
            defaultMethod: 'email',
            showAlternativeMethods: true,
            allowRememberMe: true,
            requireEmailVerification: false,
            allowPasswordReset: true,
        },
        signUp: {
            enabled: true,
            allowedMethods: ['email'],
            defaultMethod: 'email',
            requireEmailVerification: true,
            requirePhoneVerification: false,
            allowedFields: ['firstName', 'lastName', 'email', 'password'],
            requiredFields: ['email', 'password'],
            captchaEnabled: false,
        },
        oauth: {
            enabled: true,
            providers: [],
            allowAccountLinking: true,
            popupMode: true,
            redirectMode: 'popup',
        },
        mfa: {
            enabled: true,
            required: false,
            allowedMethods: ['totp', 'sms'],
            defaultMethod: 'totp',
            backupCodesEnabled: true,
            rememberDevice: true,
            rememberDeviceDuration: 30 * 24 * 60 * 60 * 1000, // 30 days
        },
        passkeys: {
            enabled: true,
            allowRegistration: true,
            allowAuthentication: true,
            requireUserVerification: true,
            rpName: 'Frank Auth',
            timeout: 60000,
            attestation: 'none',
        },
        password: {
            enabled: true,
            minLength: 8,
            maxLength: 128,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSymbols: false,
            allowCommonPasswords: false,
            showStrengthIndicator: true,
            allowPasswordManager: true,
        },
        verification: {
            email: {
                enabled: true,
                required: false,
                allowResend: true,
                resendCooldown: 60,
                expirationTime: 24 * 60 * 60 * 1000, // 24 hours
            },
            phone: {
                enabled: true,
                required: false,
                allowResend: true,
                resendCooldown: 60,
                expirationTime: 10 * 60 * 1000, // 10 minutes
            },
        },
    },
    appearance: {
        elements: {},
        colorScheme: 'system',
        theme: {
            primary: 'hsl(262.1 83.3% 57.8%)',
            secondary: 'hsl(220 14.3% 95.9%)',
            accent: 'hsl(220 14.3% 95.9%)',
            background: 'hsl(0 0% 100%)',
            foreground: 'hsl(224 71.4% 4.1%)',
            muted: 'hsl(220 14.3% 95.9%)',
            border: 'hsl(220 13% 91%)',
            input: 'hsl(220 13% 91%)',
            ring: 'hsl(262.1 83.3% 57.8%)',
            destructive: 'hsl(0 84.2% 60.2%)',
            warning: 'hsl(38 92% 50%)',
            success: 'hsl(142 76% 36%)',
            info: 'hsl(204 94% 94%)',
        },
        layout: {
            card: {
                width: 'md',
                padding: 'md',
                rounded: 'md',
                shadow: 'md',
                border: true,
            },
            modal: {
                size: 'md',
                overlay: true,
                closeOnOverlayClick: true,
                showCloseButton: true,
            },
            form: {
                spacing: 'md',
                labelPosition: 'top',
                buttonSize: 'md',
                buttonWidth: 'full',
            },
        },
        branding: {
            applicationName: 'Frank Auth',
            showPoweredBy: true,
        },
    },
    localization: {
        defaultLocale: 'en',
        availableLocales: ['en'],
        allowLocaleSwitching: false,
        dateFormat: 'MM/dd/yyyy',
        timeFormat: 'HH:mm',
        numberFormat: {
            locale: 'en-US',
        },
    },
    components: {
        globalProps: {},
        overrides: {},
        slots: {},
        customComponents: {},
    },
    features: {
        signIn: true,
        signUp: true,
        userProfile: true,
        passwordReset: true,
        emailVerification: true,
        phoneVerification: false,
        organizations: true,
        organizationSwitcher: true,
        organizationProfile: true,
        memberManagement: true,
        roleManagement: true,
        mfa: true,
        passkeys: true,
        sessionManagement: true,
        deviceManagement: true,
        auditLog: false,
        impersonation: false,
        bulkOperations: false,
        apiKeys: false,
        webhooks: false,
        darkMode: true,
        customBranding: true,
        localization: true,
        accessibility: true,
    },
    routing: {
        basePath: '/auth',
        signInPath: '/sign-in',
        signUpPath: '/sign-up',
        userProfilePath: '/user',
        organizationProfilePath: '/organization',
        afterSignInUrl: '/dashboard',
        afterSignUpUrl: '/welcome',
        afterSignOutUrl: '/',
        protectedRoutes: ['/dashboard', '/settings', '/profile'],
        publicRoutes: ['/sign-in', '/sign-up', '/forgot-password'],
    },
    session: {
        duration: 24 * 60 * 60 * 1000, // 24 hours
        inactivityTimeout: 30 * 60 * 1000, // 30 minutes
        refreshTokenRotation: true,
        storage: 'cookie',
        cookie: {
            name: 'frank_session',
            secure: true,
            sameSite: 'lax',
            httpOnly: true,
        },
        monitoring: {
            enabled: true,
            trackActivity: true,
            trackLocation: false,
            trackDevice: true,
        },
    },
};