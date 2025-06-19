/**
 * @frank-auth/react - User Button Components Index
 *
 * Exports all user button related components including avatar,
 * profile dropdown, and main user button.
 */

// ============================================================================
// User Button Components
// ============================================================================

export { UserButton, type UserButtonProps } from './user-button';
export { UserProfile, type UserProfileProps, type UserProfileMenuItem } from './user-profile';
export { UserAvatar, type UserAvatarProps } from './user-avatar';

// ============================================================================
// Default Export
// ============================================================================

export { UserButton as default } from './user-button';