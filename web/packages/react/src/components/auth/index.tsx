/**
 * @frank-auth/react - Auth Components Index
 *
 * Main entry point for all auth related components.
 * Exports all auth variants and utilities.
 */

import UserButton, {UserAvatar, UserProfile as UserProfileDropdown} from './user-button';
import UserProfile, {MFASetup, PasskeySetup, ProfileForm, SecurityPanel, UserProfileModal} from './user-profile';

// ============================================================================
// Main Components
// ============================================================================

export * from './sign-in';
export * from './sign-up';
export * from './common';
export * from './sign-in';
export * from './account-linking';
export * from './password';
export * from './magic-link';
export * from './invitations';
export * from './verification';


/**
 * @frank-auth/react - Auth Components Index
 *
 * Main entry point for all authentication components including user management,
 * sign-in/sign-up flows, organization management, and security features.
 */

// ============================================================================
// User Button Components
// ============================================================================

export {
    UserButton,
    UserProfile as UserProfileDropdown,
    UserAvatar,
    type UserButtonProps,
    type UserProfileMenuItem,
    type UserAvatarProps,
} from './user-button';

// ============================================================================
// User Profile Components
// ============================================================================

export {
    UserProfile,
    UserProfileModal,
    useUserProfileModal,
    ProfileForm,
    SecurityPanel,
    MFASetup,
    PasskeySetup,
    type UserProfileProps,
    type UserProfileModalProps,
    type UserProfileTab,
    type ProfileFormProps,
    type ProfileFormData,
    type ProfileFormField,
    type SecurityPanelProps,
    type SecurityPanelSection,
    type MFASetupProps,
    type MFAMethodConfig,
    type PasskeySetupProps,
    type PasskeyTypeConfig,
} from './user-profile';

// ============================================================================
// Component Collections
// ============================================================================

/**
 * Collection of all user-related authentication components
 */
export const UserComponents = {
    UserButton,
    UserProfile,
    UserProfileModal,
    UserAvatar,
    ProfileForm,
    SecurityPanel,
    MFASetup,
    PasskeySetup,
} as const;

/**
 * Collection of user interface components
 */
export const UserInterfaceComponents = {
    UserButton,
    UserAvatar,
    UserProfile: UserProfileDropdown,
} as const;

/**
 * Collection of user management components
 */
export const UserManagementComponents = {
    ProfileForm,
    SecurityPanel,
    MFASetup,
    PasskeySetup,
} as const;

// ============================================================================
// Hooks Re-exports
// ============================================================================

// Re-export commonly used hooks for convenience
export { useAuthState, useAuthActions, useAuthOrganization, useAuthStatus } from '../../hooks/use-auth';
export { useUser, useUserProfile, useUserVerification, useUserActions } from '../../hooks/use-user';
export { useSession, useSessionStatus, useMultiSession, useSessionSecurity } from '../../hooks/use-session';
export { useOrganization, useOrganizationMembership, useOrganizationInvitations } from '../../hooks/use-organization';
export { useMFA, useTOTP, useSMSMFA, useBackupCodes } from '../../hooks/use-mfa';
export { usePasskeys, usePasskeyRegistration, usePasskeyAuthentication } from '../../hooks/use-passkeys';
export { usePermissions, useOrganizationPermissions, useSystemPermissions } from '../../hooks/use-permissions';
export { useThemeColors, useThemeTypography, useThemeLayout } from '../../hooks/use-theme';
export { useFeatureFlags, useThemeConfig, useLocalizationConfig } from '../../hooks/use-config';

// ============================================================================
// Default Export (Most commonly used component)
// ============================================================================

export { UserButton as default } from './user-button';