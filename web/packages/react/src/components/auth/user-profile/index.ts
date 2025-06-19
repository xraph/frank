/**
 * @frank-auth/react - User Profile Components Index
 *
 * Exports all user profile related components including the main profile,
 * modal variant, form components, and security settings.
 */

// ============================================================================
// User Profile Components
// ============================================================================

export { UserProfile, type UserProfileProps, type UserProfileTab } from './user-profile';
export { UserProfileModal, useUserProfileModal, type UserProfileModalProps } from './user-profile-modal';
export { ProfileForm, type ProfileFormProps, type ProfileFormData, type ProfileFormField } from './profile-form';
export { SecurityPanel, type SecurityPanelProps, type SecurityPanelSection } from './security-panel';
export { MFASetup, type MFASetupProps, type MFAMethodConfig } from './mfa-setup';
export { PasskeySetup, type PasskeySetupProps, type PasskeyTypeConfig } from './passkey-setup';

// ============================================================================
// Default Export
// ============================================================================

export { UserProfile as default } from './user-profile';