/**
 * @frank-auth/react - User Button Component
 *
 * Main user button component that combines avatar with dropdown menu,
 * providing comprehensive user and organization management interface.
 */

'use client';

import type React from 'react';
import {Button} from '@heroui/react';
import {useAuth} from '../../../hooks/use-auth';
import {useConfig} from '../../../hooks/use-config';
import {UserAvatar, type UserAvatarProps} from './user-avatar';
import {UserProfile, type UserProfileMenuItem, type UserProfileProps} from './user-profile';

// ============================================================================
// User Button Interface
// ============================================================================

export interface UserButtonProps {
    /**
     * Button appearance style
     */
    appearance?: 'default' | 'minimal' | 'compact';

    /**
     * Avatar props (extends UserAvatarProps)
     */
    avatarProps?: Partial<UserAvatarProps>;

    /**
     * Dropdown props (extends UserProfileProps)
     */
    dropdownProps?: Partial<Omit<UserProfileProps, 'children'>>;

    /**
     * Custom className for button
     */
    className?: string;

    /**
     * Show user name next to avatar
     */
    showName?: boolean;

    /**
     * Show organization name
     */
    showOrganization?: boolean;

    /**
     * Show online status indicator
     */
    showStatus?: boolean;

    /**
     * Show notification badge
     */
    showNotifications?: boolean;

    /**
     * Notification count
     */
    notificationCount?: number;

    /**
     * Button size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Button radius
     */
    radius?: 'none' | 'sm' | 'md' | 'lg' | 'full';

    /**
     * Whether button is disabled
     */
    isDisabled?: boolean;

    /**
     * Whether button should be full width
     */
    isFullWidth?: boolean;

    /**
     * Custom menu items for dropdown
     */
    customMenuItems?: UserProfileMenuItem[];

    /**
     * Hide default menu items
     */
    hideMenuItems?: string[];

    /**
     * Sign out handler
     */
    onSignOut?: () => void;

    /**
     * Profile click handler
     */
    onProfileClick?: () => void;

    /**
     * Settings click handler
     */
    onSettingsClick?: () => void;

    /**
     * Organization switch handler
     */
    onOrganizationClick?: (organizationId: string) => void;

    /**
     * Notification click handler
     */
    onNotificationClick?: () => void;

    /**
     * Custom button content (overrides all default content)
     */
    children?: React.ReactNode;

    /**
     * Loading state
     */
    isLoading?: boolean;

    /**
     * Show dropdown arrow indicator
     */
    showDropdownIndicator?: boolean;

    /**
     * Button variant
     */
    variant?: 'solid' | 'bordered' | 'light' | 'flat' | 'faded' | 'shadow' | 'ghost';

    /**
     * Button color
     */
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    /**
     * Custom start content
     */
    startContent?: React.ReactNode;

    /**
     * Custom end content
     */
    endContent?: React.ReactNode;

    /**
     * Whether to show organization badge on avatar
     */
    showOrganizationBadge?: boolean;

    /**
     * User role to display in badge
     */
    role?: string;
}

// ============================================================================
// User Button Component
// ============================================================================

export function UserButton({
                               appearance = 'default',
                               avatarProps = {},
                               dropdownProps = {},
                               className = '',
                               showName = false,
                               showOrganization = false,
                               showStatus = false,
                               showNotifications = false,
                               notificationCount = 0,
                               size = 'md',
                               radius = 'lg',
                               isDisabled = false,
                               isFullWidth = false,
                               customMenuItems = [],
                               hideMenuItems = [],
                               onSignOut,
                               onProfileClick,
                               onSettingsClick,
                               onOrganizationClick,
                               onNotificationClick,
                               children,
                               isLoading = false,
                               showDropdownIndicator = false,
                               variant = 'light',
                               color = 'default',
                               startContent,
                               endContent,
                               showOrganizationBadge = false,
                               role,
                           }: UserButtonProps) {
    const {
        user,
        isSignedIn,
        isLoading: authLoading,
        userName,
        activeOrganization,
        isOrganizationMember,
    } = useAuth();

    const { components } = useConfig();

    // Custom component override
    const CustomUserButton = components.UserButton;
    if (CustomUserButton) {
        return <CustomUserButton {...{
            appearance, avatarProps, dropdownProps, className, showName, showOrganization,
            showStatus, showNotifications, notificationCount, size, radius, isDisabled,
            isFullWidth, customMenuItems, hideMenuItems, onSignOut, onProfileClick,
            onSettingsClick, onOrganizationClick, onNotificationClick, children,
            isLoading, showDropdownIndicator, variant, color, startContent, endContent,
            showOrganizationBadge, role
        }} />;
    }

    // Don't render if user is not signed in
    if (!isSignedIn || !user) {
        return null;
    }

    // Effective loading state
    const effectiveIsLoading = isLoading || authLoading;

    // Avatar size mapping
    const avatarSizeMap = {
        sm: 'sm' as const,
        md: 'md' as const,
        lg: 'lg' as const,
    };

    // Get effective role for badge
    const effectiveRole = role || (isOrganizationMember ? 'member' : undefined);

    // Dropdown indicator
    const dropdownIndicator = showDropdownIndicator && (
        <svg className="w-4 h-4 text-default-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
    );

    // Notification badge
    const notificationBadge = showNotifications && notificationCount > 0 && (
        <div className="absolute -top-1 -right-1 bg-danger text-white text-xs rounded-full min-w-[1.25rem] h-5 flex items-center justify-center">
            {notificationCount > 99 ? '99+' : notificationCount}
        </div>
    );

    // Render different appearances
    const renderButtonContent = () => {
        // Custom children override
        if (children) {
            return children;
        }

        // Avatar component
        const avatar = (
            <div className="relative">
                <UserAvatar
                    size={avatarSizeMap[size]}
                    showStatus={showStatus}
                    showOrganizationBadge={showOrganizationBadge}
                    role={effectiveRole}
                    isClickable={false}
                    {...avatarProps}
                />
                {notificationBadge}
            </div>
        );

        switch (appearance) {
            case 'minimal':
                return (
                    <div className="flex items-center gap-0">
                        {startContent}
                        {avatar}
                        {endContent || dropdownIndicator}
                    </div>
                );

            case 'compact':
                return (
                    <div className="flex items-center gap-2">
                        {startContent}
                        {avatar}
                        {(showName || showOrganization) && (
                            <div className="flex flex-col items-start min-w-0">
                                {showName && userName && (
                                    <span className="text-sm font-medium text-default-700 truncate max-w-[120px]">
                                        {userName}
                                    </span>
                                )}
                                {showOrganization && activeOrganization && (
                                    <span className="text-xs text-default-500 truncate max-w-[120px]">
                                        {activeOrganization.name}
                                    </span>
                                )}
                            </div>
                        )}
                        {endContent || dropdownIndicator}
                    </div>
                );

            default:
                return (
                    <div className="flex items-center gap-3">
                        {startContent}
                        {avatar}
                        {(showName || showOrganization) && (
                            <div className="flex flex-col items-start min-w-0 flex-1">
                                {showName && userName && (
                                    <span className="text-sm font-medium text-default-700 truncate">
                                        {userName}
                                    </span>
                                )}
                                {showOrganization && activeOrganization && (
                                    <span className="text-xs text-default-500 truncate">
                                        {activeOrganization.name}
                                    </span>
                                )}
                            </div>
                        )}
                        {endContent || dropdownIndicator}
                    </div>
                );
        }
    };

    // Base button
    const button = (
        <Button
            size={size}
            radius={radius}
            variant={variant}
            color={color}
            isDisabled={isDisabled || effectiveIsLoading}
            isLoading={effectiveIsLoading}
            fullWidth={isFullWidth}
            className={[
                'justify-start h-auto',
                appearance === 'minimal' ? 'min-w-unit-10 p-1' :
                    appearance === 'compact' ? 'px-2 py-1.5' : 'px-3 py-2',
                className
            ].filter(Boolean).join(' ')}
        >
            {renderButtonContent()}
        </Button>
    );

    // Wrap with dropdown
    return (
        <UserProfile
            customItems={customMenuItems}
            hideDefaultItems={hideMenuItems}
            onSignOut={onSignOut}
            onProfileClick={onProfileClick}
            onSettingsClick={onSettingsClick}
            onOrganizationSwitch={onOrganizationClick}
            isDisabled={isDisabled || effectiveIsLoading}
            {...dropdownProps}
        >
            {button}
        </UserProfile>
    );
}

// ============================================================================
// Export
// ============================================================================

export default UserButton;