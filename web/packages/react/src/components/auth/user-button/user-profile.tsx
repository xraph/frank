/**
 * @frank-auth/react - User Profile Dropdown
 *
 * User profile dropdown menu that appears from the user button,
 * includes user info, organization switching, and quick actions.
 */

'use client';

import React from 'react';
import {
    Avatar,
    Button,
    Chip,
    Dropdown,
    DropdownItem,
    DropdownMenu,
    DropdownSection,
    DropdownTrigger,
    User,
} from '@heroui/react';
import {useAuth} from '../../../hooks/use-auth';
import {useOrganization} from '../../../hooks/use-organization';
import {useSession} from '../../../hooks/use-session';
import {useConfig} from '../../../hooks/use-config';
import {useTheme} from '../../../hooks/use-theme';

// ============================================================================
// User Profile Dropdown Interface
// ============================================================================

export interface UserProfileProps {
    /**
     * Trigger element (usually UserButton)
     */
    children: React.ReactNode;

    /**
     * Dropdown placement
     */
    placement?: 'bottom' | 'bottom-start' | 'bottom-end' | 'top' | 'top-start' | 'top-end';

    /**
     * Custom className for dropdown
     */
    className?: string;

    /**
     * Custom className for dropdown content
     */
    contentClassName?: string;

    /**
     * Show organization section
     */
    showOrganization?: boolean;

    /**
     * Show session management
     */
    showSessionManagement?: boolean;

    /**
     * Show theme toggle
     */
    showThemeToggle?: boolean;

    /**
     * Custom menu items
     */
    customItems?: UserProfileMenuItem[];

    /**
     * Hide default items
     */
    hideDefaultItems?: string[];

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
    onOrganizationSwitch?: (organizationId: string) => void;

    /**
     * Custom footer content
     */
    footerContent?: React.ReactNode;

    /**
     * Whether dropdown is disabled
     */
    isDisabled?: boolean;

    /**
     * Close on select
     */
    closeOnSelect?: boolean;
}

export interface UserProfileMenuItem {
    key: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';
    variant?: 'solid' | 'light';
    href?: string;
    onClick?: () => void;
    isDisabled?: boolean;
    startContent?: React.ReactNode;
    endContent?: React.ReactNode;
    showDivider?: boolean;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get role badge color
 */
function getRoleBadgeColor(role: string): 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger' {
    switch (role?.toLowerCase()) {
        case 'owner':
            return 'danger';
        case 'admin':
            return 'warning';
        case 'member':
            return 'primary';
        case 'guest':
            return 'secondary';
        default:
            return 'default';
    }
}

/**
 * Get session device icon
 */
function getDeviceIcon(deviceInfo: any) {
    const device = deviceInfo?.device?.toLowerCase() || '';
    const os = deviceInfo?.os?.toLowerCase() || '';

    if (device.includes('mobile') || os.includes('ios') || os.includes('android')) {
        return (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a1 1 0 001-1V4a1 1 0 00-1-1H8a1 1 0 00-1 1v16a1 1 0 001 1z" />
            </svg>
        );
    }

    return (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
    );
}

// ============================================================================
// Default Icons
// ============================================================================

const Icons = {
    user: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
    ),
    settings: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
    ),
    signOut: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
        </svg>
    ),
    organization: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
    ),
    theme: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
    ),
    security: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
    ),
};

// ============================================================================
// User Profile Dropdown Component
// ============================================================================

export function UserProfile({
                                children,
                                placement = 'bottom-end',
                                className = '',
                                contentClassName = '',
                                showOrganization = true,
                                showSessionManagement = false,
                                showThemeToggle = true,
                                customItems = [],
                                hideDefaultItems = [],
                                onSignOut,
                                onProfileClick,
                                onSettingsClick,
                                onOrganizationSwitch,
                                footerContent,
                                isDisabled = false,
                                closeOnSelect = true,
                            }: UserProfileProps) {
    const {
        user,
        signOut,
        isOrganizationMember,
        userName,
        userEmail,
    } = useAuth();

    const {
        organizations,
        activeOrganization,
        switchOrganization,
        isOwner,
        isAdmin
    } = useOrganization();

    const {
        sessions,
        hasMultipleSessions,
        revokeSession,
        deviceInfo,
    } = useSession();

    const { components } = useConfig();
    const { mode, toggleMode } = useTheme();

    // Custom component override
    const CustomUserProfile = components.UserProfile;
    if (CustomUserProfile) {
        return <CustomUserProfile {...{
            children, placement, className, contentClassName, showOrganization,
            showSessionManagement, showThemeToggle, customItems, hideDefaultItems,
            onSignOut, onProfileClick, onSettingsClick, onOrganizationSwitch,
            footerContent, isDisabled, closeOnSelect
        }} />;
    }

    // Handle sign out
    const handleSignOut = React.useCallback(async () => {
        try {
            if (onSignOut) {
                onSignOut();
            } else {
                await signOut();
            }
        } catch (error) {
            console.error('Sign out failed:', error);
        }
    }, [signOut, onSignOut]);

    // Handle organization switch
    const handleOrganizationSwitch = React.useCallback(async (orgId: string) => {
        try {
            if (onOrganizationSwitch) {
                onOrganizationSwitch(orgId);
            } else {
                await switchOrganization(orgId);
            }
        } catch (error) {
            console.error('Organization switch failed:', error);
        }
    }, [switchOrganization, onOrganizationSwitch]);

    // Handle menu item action
    const handleMenuAction = React.useCallback((key: string) => {
        switch (key) {
            case 'profile':
                onProfileClick?.();
                break;
            case 'settings':
                onSettingsClick?.();
                break;
            case 'sign-out':
                handleSignOut();
                break;
            case 'toggle-theme':
                toggleMode();
                break;
            default:
                // Handle custom items
                const customItem = customItems.find(item => item.key === key);
                if (customItem?.onClick) {
                    customItem.onClick();
                } else if (customItem?.href) {
                    window.location.href = customItem.href;
                }
                break;
        }
    }, [onProfileClick, onSettingsClick, handleSignOut, toggleMode, customItems]);

    // Don't render if user is not available
    if (!user) return null;

    // Current organization membership role
    const currentMembershipRole = React.useMemo(() => {
        if (!activeOrganization) return null;
        return isOwner ? 'owner' : isAdmin ? 'admin' : 'member';
    }, [activeOrganization, isOwner, isAdmin]);

    return (
        <Dropdown
            placement={placement}
            className={className}
            isDisabled={isDisabled}
            closeOnSelect={closeOnSelect}
        >
            <DropdownTrigger>
                {children}
            </DropdownTrigger>

            <DropdownMenu
                aria-label="User menu"
                onAction={handleMenuAction}
                className={contentClassName}
            >
                {/* User Info Section */}
                <DropdownSection showDivider>
                    <DropdownItem
                        key="user-info"
                        isReadOnly
                        className="h-14 gap-2 opacity-100"
                    >
                        <User
                            name={userName}
                            description={userEmail}
                            avatarProps={{
                                size: "sm",
                                src: user.profileImageUrl,
                            }}
                            classNames={{
                                name: "text-default-600",
                                description: "text-default-500",
                            }}
                        />
                    </DropdownItem>
                </DropdownSection>

                {/* Organization Section */}
                {showOrganization && activeOrganization && (
                    <DropdownSection title="Organization" showDivider>
                        <DropdownItem
                            key="current-org"
                            isReadOnly
                            className="opacity-100"
                            startContent={Icons.organization}
                            endContent={
                                currentMembershipRole && (
                                    <Chip
                                        size="sm"
                                        color={getRoleBadgeColor(currentMembershipRole)}
                                        variant="flat"
                                    >
                                        {currentMembershipRole}
                                    </Chip>
                                )
                            }
                        >
                            <div className="flex flex-col">
                                <span className="text-small">{activeOrganization.name}</span>
                                <span className="text-tiny text-default-400">
                                    {activeOrganization.slug}
                                </span>
                            </div>
                        </DropdownItem>

                        {/* Organization Switcher */}
                        {organizations.length > 1 && (
                            <>
                                {organizations
                                    .filter(org => org.id !== activeOrganization.id)
                                    .map(org => (
                                        <DropdownItem
                                            key={`switch-${org.id}`}
                                            onPress={() => handleOrganizationSwitch(org.id)}
                                            startContent={
                                                <Avatar
                                                    size="sm"
                                                    src={org.logoUrl}
                                                    name={org.name}
                                                />
                                            }
                                        >
                                            Switch to {org.name}
                                        </DropdownItem>
                                    ))}
                            </>
                        )}
                    </DropdownSection>
                )}

                {/* Session Management */}
                {showSessionManagement && hasMultipleSessions && (
                    <DropdownSection title="Sessions" showDivider>
                        {sessions.slice(0, 3).map(session => (
                            <DropdownItem
                                key={`session-${session.id}`}
                                startContent={getDeviceIcon(session.deviceInfo)}
                                endContent={
                                    session.id !== sessions[0]?.id && (
                                        <Button
                                            size="sm"
                                            variant="light"
                                            color="danger"
                                            onPress={() => revokeSession(session.id)}
                                        >
                                            End
                                        </Button>
                                    )
                                }
                                className="text-small"
                            >
                                <div className="flex flex-col">
                                    <span>{session.deviceInfo?.browser || 'Unknown Browser'}</span>
                                    <span className="text-tiny text-default-400">
                                        {session.deviceInfo?.os || 'Unknown OS'}
                                    </span>
                                </div>
                            </DropdownItem>
                        ))}
                    </DropdownSection>
                )}

                {/* Action Section */}
                <DropdownSection showDivider>
                    {!hideDefaultItems.includes('profile') && (
                        <DropdownItem
                            key="profile"
                            startContent={Icons.user}
                        >
                            Profile
                        </DropdownItem>
                    )}

                    {!hideDefaultItems.includes('settings') && (
                        <DropdownItem
                            key="settings"
                            startContent={Icons.settings}
                        >
                            Settings
                        </DropdownItem>
                    )}

                    {!hideDefaultItems.includes('security') && (
                        <DropdownItem
                            key="security"
                            startContent={Icons.security}
                        >
                            Security
                        </DropdownItem>
                    )}

                    {showThemeToggle && !hideDefaultItems.includes('theme') && (
                        <DropdownItem
                            key="toggle-theme"
                            startContent={Icons.theme}
                        >
                            {mode === 'dark' ? 'Light Mode' : 'Dark Mode'}
                        </DropdownItem>
                    )}

                    {/* Custom Items */}
                    {customItems.map(item => (
                        <DropdownItem
                            key={item.key}
                            startContent={item.startContent || item.icon}
                            endContent={item.endContent}
                            color={item.color}
                            variant={item.variant}
                            isDisabled={item.isDisabled}
                            showDivider={item.showDivider}
                        >
                            <div className="flex flex-col">
                                <span>{item.label}</span>
                                {item.description && (
                                    <span className="text-tiny text-default-400">
                                        {item.description}
                                    </span>
                                )}
                            </div>
                        </DropdownItem>
                    ))}
                </DropdownSection>

                {/* Sign Out */}
                <DropdownSection>
                    {!hideDefaultItems.includes('signOut') && (
                        <DropdownItem
                            key="sign-out"
                            color="danger"
                            startContent={Icons.signOut}
                        >
                            Sign Out
                        </DropdownItem>
                    )}
                </DropdownSection>

                {/* Custom Footer */}
                {footerContent && (
                    <DropdownSection>
                        <DropdownItem key="footer" isReadOnly className="opacity-100">
                            {footerContent}
                        </DropdownItem>
                    </DropdownSection>
                )}
            </DropdownMenu>
        </Dropdown>
    );
}

// ============================================================================
// Export
// ============================================================================

export default UserProfile;