/**
 * @frank-auth/react - User Avatar Component
 *
 * Customizable user avatar component with fallback initials,
 * online status, and organization-specific styling.
 */

'use client';

import React from 'react';
import {Avatar, Badge} from '@heroui/react';
import {useAuth} from '../../../hooks/use-auth';
import {useConfig} from '../../../hooks/use-config';
import {useTheme} from '../../../hooks/use-theme';

// ============================================================================
// User Avatar Interface
// ============================================================================

export interface UserAvatarProps {
    /**
     * User ID (if different from current user)
     */
    userId?: string;

    /**
     * User profile image URL
     */
    src?: string;

    /**
     * User name for fallback initials
     */
    name?: string;

    /**
     * User email for fallback initials
     */
    email?: string;

    /**
     * Avatar size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Avatar radius
     */
    radius?: 'none' | 'sm' | 'md' | 'lg' | 'full';

    /**
     * Show online status
     */
    showStatus?: boolean;

    /**
     * Online status
     */
    isOnline?: boolean;

    /**
     * Custom fallback content
     */
    fallback?: React.ReactNode;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Click handler
     */
    onClick?: () => void;

    /**
     * Whether avatar is clickable
     */
    isClickable?: boolean;

    /**
     * Show organization badge
     */
    showOrganizationBadge?: boolean;

    /**
     * Organization role to display
     */
    role?: string;

    /**
     * Color scheme
     */
    color?: 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger';

    /**
     * Whether to show border
     */
    isBordered?: boolean;

    /**
     * Whether avatar is disabled
     */
    isDisabled?: boolean;

    /**
     * Custom initials
     */
    initials?: string;

    /**
     * Fallback icon when no image or initials
     */
    icon?: React.ReactNode;

    /**
     * Avatar quality for image
     */
    quality?: number;

    /**
     * Whether to use organization colors
     */
    useOrganizationColors?: boolean;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate initials from name or email
 */
function generateInitials(name?: string, email?: string): string {
    if (name) {
        const parts = name.trim().split(' ');
        if (parts.length >= 2) {
            return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
        }
        return parts[0][0]?.toUpperCase() || '';
    }

    if (email) {
        return email[0]?.toUpperCase() || '';
    }

    return '';
}

/**
 * Get role color based on role type
 */
function getRoleColor(role?: string): 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'danger' {
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
 * Get role label for display
 */
function getRoleLabel(role?: string): string {
    switch (role?.toLowerCase()) {
        case 'owner':
            return 'Owner';
        case 'admin':
            return 'Admin';
        case 'member':
            return 'Member';
        case 'guest':
            return 'Guest';
        default:
            return role || '';
    }
}

// ============================================================================
// User Avatar Component
// ============================================================================

export function UserAvatar({
                               userId,
                               src,
                               name,
                               email,
                               size = 'md',
                               radius = 'full',
                               showStatus = false,
                               isOnline = false,
                               fallback,
                               className = '',
                               onClick,
                               isClickable = false,
                               showOrganizationBadge = false,
                               role,
                               color = 'default',
                               isBordered = false,
                               isDisabled = false,
                               initials: customInitials,
                               icon,
                               quality = 80,
                               useOrganizationColors = false,
                           }: UserAvatarProps) {
    const { user, isOrganizationMember } = useAuth();
    const { components, organizationSettings } = useConfig();
    const { primaryColor } = useTheme();

    // Custom component override
    const CustomUserAvatar = components.UserAvatar;
    if (CustomUserAvatar) {
        return <CustomUserAvatar {...{
            userId, src, name, email, size, radius, showStatus, isOnline, fallback,
            className, onClick, isClickable, showOrganizationBadge, role, color,
            isBordered, isDisabled, initials: customInitials, icon, quality, useOrganizationColors
        }} />;
    }

    // Use current user data if no specific user provided
    const effectiveUser = userId ? null : user;
    const effectiveSrc = src || effectiveUser?.profileImageUrl;
    const effectiveName = name || effectiveUser?.firstName && effectiveUser?.lastName
        ? `${effectiveUser.firstName} ${effectiveUser.lastName}`
        : effectiveUser?.username;
    const effectiveEmail = email || effectiveUser?.primaryEmailAddress;

    // Generate initials
    const displayInitials = customInitials || generateInitials(effectiveName, effectiveEmail);

    // Apply organization colors if enabled
    const effectiveColor = useOrganizationColors && organizationSettings?.branding?.primaryColor
        ? 'primary'
        : color;

    // Default user icon
    const defaultIcon = icon || (
        <svg
            className="w-full h-full text-default-400"
            fill="currentColor"
            viewBox="0 0 24 24"
        >
            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
        </svg>
    );

    // Fallback content
    const fallbackContent = fallback || (
        displayInitials ? (
            <span className="font-medium text-inherit">
                {displayInitials}
            </span>
        ) : (
            defaultIcon
        )
    );

    // Handle click
    const handleClick = React.useCallback(() => {
        if (isClickable && onClick && !isDisabled) {
            onClick();
        }
    }, [isClickable, onClick, isDisabled]);

    // Status indicator
    const statusIndicator = showStatus && (
        <Badge
            content=""
            color={isOnline ? 'success' : 'default'}
            shape="circle"
            placement="bottom-right"
            size="sm"
            classNames={{
                badge: isOnline ? 'border-2 border-white' : 'border-2 border-white bg-default-300',
            }}
        />
    );

    // Role badge
    const roleBadge = showOrganizationBadge && role && isOrganizationMember && (
        <Badge
            content={getRoleLabel(role)}
            color={getRoleColor(role)}
            variant="flat"
            placement="bottom-right"
            size="sm"
            classNames={{
                badge: 'text-xs px-1 py-0.5 min-w-fit',
            }}
        />
    );

    // Base avatar
    const avatar = (
        <Avatar
            src={effectiveSrc}
            name={effectiveName}
            size={size}
            radius={radius}
            color={effectiveColor}
            isBordered={isBordered}
            isDisabled={isDisabled}
            fallback={fallbackContent}
            classNames={{
                base: [
                    className,
                    isClickable && !isDisabled && 'cursor-pointer hover:opacity-80 transition-opacity',
                    isDisabled && 'opacity-50 cursor-not-allowed',
                ].filter(Boolean).join(' '),
            }}
            onClick={handleClick}
        />
    );

    // Apply badges
    if (statusIndicator && roleBadge) {
        return (
            <div className="relative inline-block">
                {avatar}
                {statusIndicator}
                <div className="absolute -bottom-1 -right-1 transform translate-x-1/2">
                    {roleBadge}
                </div>
            </div>
        );
    }

    if (statusIndicator) {
        return (
            <Badge
                content=""
                color={isOnline ? 'success' : 'default'}
                shape="circle"
                placement="bottom-right"
                size="sm"
                classNames={{
                    badge: isOnline ? 'border-2 border-white' : 'border-2 border-white bg-default-300',
                }}
            >
                {avatar}
            </Badge>
        );
    }

    if (roleBadge) {
        return (
            <Badge
                content={getRoleLabel(role)}
                color={getRoleColor(role)}
                variant="flat"
                placement="bottom-right"
                size="sm"
                classNames={{
                    badge: 'text-xs px-1 py-0.5 min-w-fit',
                }}
            >
                {avatar}
            </Badge>
        );
    }

    return avatar;
}

// ============================================================================
// Export
// ============================================================================

export default UserAvatar;