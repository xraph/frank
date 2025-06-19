import type {ButtonHTMLAttributes, ComponentType, FormHTMLAttributes, InputHTMLAttributes, ReactNode} from 'react';
import type {XID} from './index';
import type {User} from './user';
import type {Organization, OrganizationSummary} from './organization';
import type {Session} from './session';
import type {AuthMethod, OAuthProvider} from './auth';
import type {FrankAuthConfig} from './config';

// Base component props
export interface BaseComponentProps {
    className?: string;
    style?: React.CSSProperties;
    children?: ReactNode;
    'data-testid'?: string;
}

// Layout component props
export interface LayoutProps extends BaseComponentProps {
    variant?: 'card' | 'modal' | 'fullscreen' | 'embedded';
    size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
    padding?: 'none' | 'sm' | 'md' | 'lg';
    centered?: boolean;
    showHeader?: boolean;
    showFooter?: boolean;
    headerSlot?: ReactNode;
    footerSlot?: ReactNode;
}

// Authentication component props
export interface AuthComponentProps extends BaseComponentProps {
    organizationId?: XID;
    redirectUrl?: string;
    afterSignInUrl?: string;
    afterSignUpUrl?: string;
    routing?: 'path' | 'hash' | 'virtual';
    appearance?: {
        theme?: string;
        variables?: Record<string, string>;
        elements?: Record<string, string>;
    };
    localization?: {
        locale?: string;
        customMessages?: Record<string, string>;
    };
}

// Sign In component props
export interface SignInProps extends AuthComponentProps {
    // Authentication methods
    methods?: AuthMethod[];
    primaryMethod?: AuthMethod;

    // OAuth configuration
    oauthProviders?: OAuthProvider[];
    oauthRedirectMode?: 'popup' | 'redirect';

    // Form configuration
    fields?: SignInFieldConfig[];
    showAlternativeMethods?: boolean;
    allowRememberMe?: boolean;

    // Features
    allowPasswordReset?: boolean;
    allowSignUp?: boolean;
    signUpUrl?: string;

    // Callbacks
    onSignInSuccess?: (user: User, session: Session) => void;
    onSignInError?: (error: Error) => void;
    onMfaRequired?: (challenge: any) => void;

    // Customization
    customFields?: ReactNode;
    customButtons?: ReactNode;
    customHeader?: ReactNode;
    customFooter?: ReactNode;

    // Layout
    layout?: LayoutProps;
}

// Sign Up component props
export interface SignUpProps extends AuthComponentProps {
    // Authentication methods
    methods?: AuthMethod[];
    primaryMethod?: AuthMethod;

    // OAuth configuration
    oauthProviders?: OAuthProvider[];
    oauthRedirectMode?: 'popup' | 'redirect';

    // Form configuration
    fields?: SignUpFieldConfig[];
    requiredFields?: string[];

    // Features
    allowSignIn?: boolean;
    signInUrl?: string;
    requireTermsAcceptance?: boolean;
    termsOfServiceUrl?: string;
    privacyPolicyUrl?: string;

    // Verification
    requireEmailVerification?: boolean;
    requirePhoneVerification?: boolean;

    // Invitations
    invitationToken?: string;
    invitationMode?: boolean;

    // Callbacks
    onSignUpSuccess?: (user: User, session?: Session) => void;
    onSignUpError?: (error: Error) => void;
    onVerificationRequired?: (method: string) => void;

    // Customization
    customFields?: ReactNode;
    customButtons?: ReactNode;
    customHeader?: ReactNode;
    customFooter?: ReactNode;

    // Layout
    layout?: LayoutProps;
}

// User Button component props
export interface UserButtonProps extends BaseComponentProps {
    // User information
    user?: User;
    showUserInfo?: boolean;
    showEmailAddress?: boolean;
    showUsername?: boolean;

    // Organization context
    organization?: Organization;
    showOrganization?: boolean;
    allowOrganizationSwitching?: boolean;

    // Menu configuration
    showProfileMenuItem?: boolean;
    showOrganizationMenuItem?: boolean;
    showSettingsMenuItem?: boolean;
    showHelpMenuItem?: boolean;
    showSignOutMenuItem?: boolean;
    customMenuItems?: UserButtonMenuItem[];

    // Appearance
    appearance?: 'default' | 'minimal' | 'avatar-only';
    avatarSize?: 'sm' | 'md' | 'lg';
    showCaret?: boolean;

    // Callbacks
    onProfileClick?: () => void;
    onOrganizationClick?: () => void;
    onSettingsClick?: () => void;
    onHelpClick?: () => void;
    onSignOutClick?: () => void;
    onSignOut?: () => void;

    // Customization
    customAvatar?: ReactNode;
    customTrigger?: ReactNode;
    customContent?: ReactNode;
}

// User Profile component props
export interface UserProfileProps extends AuthComponentProps {
    // User context
    user?: User;

    // Navigation
    mode?: 'modal' | 'navigation' | 'embedded';
    initialPage?: 'profile' | 'security' | 'connected-accounts' | 'organization';

    // Features
    allowProfileEdit?: boolean;
    allowPasswordChange?: boolean;
    allowEmailChange?: boolean;
    allowPhoneChange?: boolean;
    allowUsernameChange?: boolean;
    allowAccountDeletion?: boolean;

    // Security features
    allowMfaManagement?: boolean;
    allowPasskeyManagement?: boolean;
    allowSessionManagement?: boolean;
    allowConnectedAccounts?: boolean;

    // Organization features
    allowOrganizationManagement?: boolean;
    allowMembershipManagement?: boolean;

    // Customization
    customPages?: UserProfilePage[];
    customFields?: UserProfileField[];

    // Callbacks
    onProfileUpdate?: (user: User) => void;
    onPasswordChange?: () => void;
    onMfaChange?: (enabled: boolean) => void;
    onAccountDelete?: () => void;

    // Layout
    layout?: LayoutProps;
}

// Organization Switcher component props
export interface OrganizationSwitcherProps extends BaseComponentProps {
    // Current context
    currentOrganization?: Organization;
    organizations?: OrganizationSummary[];

    // Features
    allowOrganizationCreation?: boolean;
    allowPersonalWorkspace?: boolean;
    showOrganizationProfile?: boolean;

    // Appearance
    appearance?: 'default' | 'minimal' | 'compact';
    showCreateOrganization?: boolean;
    showOrganizationSuggestions?: boolean;

    // Callbacks
    onOrganizationSwitch?: (organization: Organization) => void;
    onOrganizationCreate?: () => void;
    onOrganizationProfile?: (organization: Organization) => void;

    // Customization
    customTrigger?: ReactNode;
    customContent?: ReactNode;
    customCreateButton?: ReactNode;

    // Layout
    hidePersonalWorkspace?: boolean;
    organizationProfileMode?: 'modal' | 'navigation' | 'redirect';
    organizationProfileUrl?: string;
}

// Organization Profile component props
export interface OrganizationProfileProps extends AuthComponentProps {
    // Organization context
    organization?: Organization;

    // Navigation
    mode?: 'modal' | 'navigation' | 'embedded';
    initialPage?: 'general' | 'members' | 'settings' | 'billing' | 'security';

    // Features
    allowProfileEdit?: boolean;
    allowMemberManagement?: boolean;
    allowRoleManagement?: boolean;
    allowInvitations?: boolean;
    allowBillingManagement?: boolean;
    allowDomainManagement?: boolean;
    allowSSOConfiguration?: boolean;
    allowOrganizationDeletion?: boolean;

    // Member management
    allowMemberInvite?: boolean;
    allowMemberRemove?: boolean;
    allowMemberRoleChange?: boolean;
    allowMemberSuspension?: boolean;

    // Customization
    customPages?: OrganizationProfilePage[];
    customFields?: OrganizationProfileField[];

    // Callbacks
    onOrganizationUpdate?: (organization: Organization) => void;
    onMemberInvite?: (invitation: any) => void;
    onMemberUpdate?: (member: any) => void;
    onMemberRemove?: (memberId: XID) => void;
    onBillingUpdate?: (billing: any) => void;

    // Layout
    layout?: LayoutProps;
}

// Form field configuration
export interface SignInFieldConfig {
    name: 'email' | 'username' | 'phone' | 'password';
    required?: boolean;
    placeholder?: string;
    label?: string;
    helperText?: string;
    validation?: {
        required?: boolean;
        pattern?: RegExp;
        minLength?: number;
        maxLength?: number;
        custom?: (value: string) => string | undefined;
    };
}

export interface SignUpFieldConfig {
    name: 'email' | 'username' | 'phone' | 'password' | 'firstName' | 'lastName' | 'confirmPassword';
    required?: boolean;
    placeholder?: string;
    label?: string;
    helperText?: string;
    validation?: {
        required?: boolean;
        pattern?: RegExp;
        minLength?: number;
        maxLength?: number;
        custom?: (value: string) => string | undefined;
    };
}

// User button menu item
export interface UserButtonMenuItem {
    label: string;
    icon?: ReactNode;
    onClick: () => void;
    disabled?: boolean;
    destructive?: boolean;
    separator?: boolean;
}

// User profile page
export interface UserProfilePage {
    id: string;
    label: string;
    icon?: ReactNode;
    component: ComponentType<any>;
    path?: string;
    enabled?: boolean;
}

// User profile field
export interface UserProfileField {
    name: string;
    label: string;
    type: 'text' | 'email' | 'phone' | 'password' | 'textarea' | 'select' | 'checkbox' | 'custom';
    component?: ComponentType<any>;
    required?: boolean;
    disabled?: boolean;
    placeholder?: string;
    helperText?: string;
    validation?: {
        required?: boolean;
        pattern?: RegExp;
        minLength?: number;
        maxLength?: number;
        options?: Array<{ label: string; value: string }>;
        custom?: (value: any) => string | undefined;
    };
}

// Organization profile page
export interface OrganizationProfilePage {
    id: string;
    label: string;
    icon?: ReactNode;
    component: ComponentType<any>;
    path?: string;
    enabled?: boolean;
    requiredPermissions?: string[];
}

// Organization profile field
export interface OrganizationProfileField {
    name: string;
    label: string;
    type: 'text' | 'email' | 'url' | 'textarea' | 'select' | 'checkbox' | 'file' | 'custom';
    component?: ComponentType<any>;
    required?: boolean;
    disabled?: boolean;
    placeholder?: string;
    helperText?: string;
    validation?: {
        required?: boolean;
        pattern?: RegExp;
        minLength?: number;
        maxLength?: number;
        fileTypes?: string[];
        maxFileSize?: number;
        options?: Array<{ label: string; value: string }>;
        custom?: (value: any) => string | undefined;
    };
}

// Form component props
export interface FormProps extends BaseComponentProps, Omit<FormHTMLAttributes<HTMLFormElement>, 'className' | 'style' | 'onError'> {
    // Form configuration
    onSubmit?: (data: any) => void | Promise<void>;
    onError?: (errors: Record<string, string>) => void;
    onValidate?: (data: any) => Record<string, string> | Promise<Record<string, string>>;

    // Loading and disabled states
    loading?: boolean;
    disabled?: boolean;

    // Form layout
    layout?: 'vertical' | 'horizontal' | 'inline';
    spacing?: 'sm' | 'md' | 'lg';

    // Validation
    validateOnChange?: boolean;
    validateOnBlur?: boolean;
    validateOnSubmit?: boolean;

    // Initial values
    initialValues?: Record<string, any>;

    // Form actions
    showSubmitButton?: boolean;
    showResetButton?: boolean;
    submitButtonText?: string;
    resetButtonText?: string;

    // Customization
    customActions?: ReactNode;
    customValidation?: ReactNode;
}

// Input component props
export interface InputProps extends BaseComponentProps, Omit<InputHTMLAttributes<HTMLInputElement>, 'className' | 'style' | 'size'> {
    // Input configuration
    label?: string;
    helperText?: string;
    errorText?: string;

    // Input variants
    variant?: 'flat' | 'bordered' | 'underlined' | 'faded';
    size?: 'sm' | 'md' | 'lg';
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    // Input features
    clearable?: boolean;
    password?: boolean;
    showPasswordToggle?: boolean;

    // Icons
    startIcon?: ReactNode;
    endIcon?: ReactNode;

    // Validation
    error?: boolean;
    success?: boolean;

    // Callbacks
    onClear?: () => void;
    onIconClick?: () => void;
}

// Button component props
export interface ButtonProps extends BaseComponentProps, Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className' | 'style'> {
    // Button variants
    variant?: 'solid' | 'bordered' | 'light' | 'flat' | 'faded' | 'shadow' | 'ghost';
    size?: 'sm' | 'md' | 'lg';
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    // Button features
    loading?: boolean;
    disabled?: boolean;
    fullWidth?: boolean;

    // Icons
    startIcon?: ReactNode;
    endIcon?: ReactNode;

    // Special buttons
    iconOnly?: boolean;
    href?: string;
    external?: boolean;

    // Callbacks
    onClick?: () => void | Promise<void>;
}

// Card component props
export interface CardProps extends BaseComponentProps {
    // Card variants
    variant?: 'shadow' | 'bordered' | 'flat';

    // Card features
    hoverable?: boolean;
    clickable?: boolean;

    // Card content
    header?: ReactNode;
    body?: ReactNode;
    footer?: ReactNode;

    // Card layout
    padding?: 'none' | 'sm' | 'md' | 'lg';
    radius?: 'none' | 'sm' | 'md' | 'lg' | 'xl';

    // Callbacks
    onClick?: () => void;
}

// Modal component props
export interface ModalProps extends BaseComponentProps {
    // Modal state
    open?: boolean;
    onOpenChange?: (open: boolean) => void;

    // Modal configuration
    size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl' | '4xl' | '5xl' | 'full';
    placement?: 'center' | 'top' | 'bottom';

    // Modal features
    backdrop?: 'transparent' | 'opaque' | 'blur';
    closeOnBackdropClick?: boolean;
    closeOnEscape?: boolean;
    hideCloseButton?: boolean;
    isDismissable?: boolean;

    // Modal content
    header?: ReactNode;
    body?: ReactNode;
    footer?: ReactNode;

    // Callbacks
    onClose?: () => void;
    onOpen?: () => void;
}

// Avatar component props
export interface AvatarProps extends BaseComponentProps {
    // Avatar content
    src?: string;
    alt?: string;
    name?: string;
    fallback?: ReactNode;

    // Avatar configuration
    size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    // Avatar features
    bordered?: boolean;
    showFallback?: boolean;

    // Callbacks
    onClick?: () => void;
    onError?: () => void;
}

// Dropdown component props
export interface DropdownProps extends BaseComponentProps {
    // Dropdown state
    open?: boolean;
    onOpenChange?: (open: boolean) => void;

    // Dropdown configuration
    placement?: 'top' | 'bottom' | 'left' | 'right' | 'top-start' | 'top-end' | 'bottom-start' | 'bottom-end';

    // Dropdown features
    closeOnSelect?: boolean;
    closeOnBlur?: boolean;
    disabled?: boolean;

    // Dropdown content
    trigger?: ReactNode;
    content?: ReactNode;

    // Callbacks
    onClose?: () => void;
    onOpen?: () => void;
}

// Toast component props
export interface ToastProps extends BaseComponentProps {
    // Toast content
    title?: string;
    description?: string;

    // Toast configuration
    type?: 'default' | 'success' | 'warning' | 'error' | 'info';
    duration?: number;

    // Toast features
    closable?: boolean;
    showIcon?: boolean;

    // Toast actions
    action?: {
        label: string;
        onClick: () => void;
    };

    // Callbacks
    onClose?: () => void;
    onOpen?: () => void;
}

// Loading component props
export interface LoadingProps extends BaseComponentProps {
    // Loading configuration
    size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    // Loading content
    text?: string;

    // Loading variants
    variant?: 'spinner' | 'dots' | 'bars' | 'pulse';
}

// Error boundary props
export interface ErrorBoundaryProps extends BaseComponentProps {
    // Error handling
    fallback?: ComponentType<{ error: Error; retry: () => void }>;
    onError?: (error: Error, errorInfo: any) => void;

    // Error boundary features
    isolated?: boolean;
    resetOnPropsChange?: boolean;
    resetKeys?: any[];
}

// Provider component props
export interface FrankAuthProviderProps extends BaseComponentProps {
    // Core configuration
    config: FrankAuthConfig;

    // Optional overrides
    publishableKey?: string;
    organizationId?: XID;

    // Custom configuration
    customConfig?: Partial<FrankAuthConfig>;

    // Development features
    debug?: boolean;

    // Callbacks
    onUserUpdate?: (user: User | null) => void;
    onSessionUpdate?: (session: Session | null) => void;
    onOrganizationUpdate?: (organization: Organization | null) => void;
    onError?: (error: Error) => void;
}