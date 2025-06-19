/**
 * @frank-auth/react - User Profile Component
 *
 * Comprehensive user profile management interface with sections for
 * personal information, security settings, organization management,
 * and account preferences.
 */

'use client';

import React from 'react';
import {Button, Card, CardBody, CardHeader, Divider, Spinner, Tab, Tabs,} from '@heroui/react';
import {useAuth} from '../../../hooks/use-auth';
import {useUser} from '../../../hooks/use-user';
import {useConfig} from '../../../hooks/use-config';
import {ProfileForm} from './profile-form';
import {SecurityPanel} from './security-panel';
import {MFASetup} from './mfa-setup';
import {PasskeySetup} from './passkey-setup';

// ============================================================================
// User Profile Interface
// ============================================================================

export interface UserProfileProps {
    /**
     * Default active tab
     */
    defaultTab?: string;

    /**
     * Available tabs
     */
    tabs?: UserProfileTab[];

    /**
     * Hide specific tabs
     */
    hideTabs?: string[];

    /**
     * Show organization settings
     */
    showOrganizationSettings?: boolean;

    /**
     * Show security settings
     */
    showSecuritySettings?: boolean;

    /**
     * Show MFA settings
     */
    showMFASettings?: boolean;

    /**
     * Show passkey settings
     */
    showPasskeySettings?: boolean;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Card variant
     */
    variant?: 'flat' | 'bordered' | 'shadow';

    /**
     * Layout orientation
     */
    orientation?: 'horizontal' | 'vertical';

    /**
     * Tab placement
     */
    tabPlacement?: 'top' | 'bottom' | 'start' | 'end';

    /**
     * Custom header content
     */
    headerContent?: React.ReactNode;

    /**
     * Custom footer content
     */
    footerContent?: React.ReactNode;

    /**
     * Profile update handler
     */
    onProfileUpdate?: (data: any) => void;

    /**
     * Success callback
     */
    onSuccess?: (message: string) => void;

    /**
     * Error callback
     */
    onError?: (error: string) => void;

    /**
     * Close handler (for modal usage)
     */
    onClose?: () => void;

    /**
     * Loading state override
     */
    isLoading?: boolean;

    /**
     * Disable all interactions
     */
    isDisabled?: boolean;

    /**
     * Size variant
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Custom tab content
     */
    customTabs?: Record<string, React.ReactNode>;
}

export interface UserProfileTab {
    key: string;
    title: string;
    icon?: React.ReactNode;
    content?: React.ReactNode;
    isDisabled?: boolean;
    badge?: string | number;
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
    security: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
    ),
    shield: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
    ),
    key: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
    ),
    organization: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
    ),
    settings: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
    ),
};

// ============================================================================
// User Profile Component
// ============================================================================

export function UserProfile({
                                defaultTab = 'profile',
                                tabs,
                                hideTabs = [],
                                showOrganizationSettings = true,
                                showSecuritySettings = true,
                                showMFASettings = true,
                                showPasskeySettings = true,
                                className = '',
                                variant = 'bordered',
                                orientation = 'horizontal',
                                tabPlacement = 'top',
                                headerContent,
                                footerContent,
                                onProfileUpdate,
                                onSuccess,
                                onError,
                                onClose,
                                isLoading: externalLoading = false,
                                isDisabled = false,
                                size = 'md',
                                customTabs = {},
                            }: UserProfileProps) {
    const { user, isLoading: authLoading } = useAuth();
    const { isLoading: userLoading } = useUser();
    const { components, features } = useConfig();

    // Custom component override
    const CustomUserProfile = components.UserProfile;
    if (CustomUserProfile) {
        return <CustomUserProfile {...{
            defaultTab, tabs, hideTabs, showOrganizationSettings, showSecuritySettings,
            showMFASettings, showPasskeySettings, className, variant, orientation,
            tabPlacement, headerContent, footerContent, onProfileUpdate, onSuccess,
            onError, onClose, isLoading: externalLoading, isDisabled, size, customTabs
        }} />;
    }

    // Loading state
    const isLoading = externalLoading || authLoading || userLoading;

    // Selected tab state
    const [selectedTab, setSelectedTab] = React.useState(defaultTab);

    // Default tabs configuration
    const defaultTabs = React.useMemo((): UserProfileTab[] => {
        const tabsList: UserProfileTab[] = [
            {
                key: 'profile',
                title: 'Profile',
                icon: Icons.user,
                content: (
                    <ProfileForm
                        onUpdate={onProfileUpdate}
                        onSuccess={onSuccess}
                        onError={onError}
                        isDisabled={isDisabled}
                    />
                ),
            },
        ];

        if (showSecuritySettings) {
            tabsList.push({
                key: 'security',
                title: 'Security',
                icon: Icons.security,
                content: (
                    <SecurityPanel
                        onSuccess={onSuccess}
                        onError={onError}
                        isDisabled={isDisabled}
                    />
                ),
            });
        }

        if (showMFASettings && features.mfa) {
            tabsList.push({
                key: 'mfa',
                title: 'Two-Factor Auth',
                icon: Icons.shield,
                content: (
                    <MFASetup
                        onSuccess={onSuccess}
                        onError={onError}
                        isDisabled={isDisabled}
                    />
                ),
            });
        }

        if (showPasskeySettings && features.passkeys) {
            tabsList.push({
                key: 'passkeys',
                title: 'Passkeys',
                icon: Icons.key,
                content: (
                    <PasskeySetup
                        onSuccess={onSuccess}
                        onError={onError}
                        isDisabled={isDisabled}
                    />
                ),
            });
        }

        if (showOrganizationSettings && features.organizationManagement) {
            tabsList.push({
                key: 'organizations',
                title: 'Organizations',
                icon: Icons.organization,
                content: (
                    <div className="space-y-4">
                        <p>Organization management coming soon...</p>
                    </div>
                ),
            });
        }

        // Add custom tabs
        Object.entries(customTabs).forEach(([key, content]) => {
            tabsList.push({
                key,
                title: key.charAt(0).toUpperCase() + key.slice(1),
                content,
            });
        });

        return tabsList.filter(tab => !hideTabs.includes(tab.key));
    }, [
        showSecuritySettings,
        showMFASettings,
        showPasskeySettings,
        showOrganizationSettings,
        features,
        hideTabs,
        customTabs,
        onProfileUpdate,
        onSuccess,
        onError,
        isDisabled,
    ]);

    // Use provided tabs or default tabs
    const effectiveTabs = tabs || defaultTabs;

    // Size mapping
    const sizeMapping = {
        sm: 'sm',
        md: 'md',
        lg: 'lg',
    };

    // Don't render if no user
    if (!user && !isLoading) {
        return null;
    }

    // Loading state
    if (isLoading) {
        return (
            <Card variant={variant} className={className}>
                <CardBody className="flex items-center justify-center py-8">
                    <Spinner size="lg" />
                </CardBody>
            </Card>
        );
    }

    return (
        <Card variant={variant} className={className}>
            {/* Header */}
            {(headerContent || onClose) && (
                <>
                    <CardHeader className="flex items-center justify-between">
                        {headerContent || (
                            <div>
                                <h3 className="text-lg font-semibold">Profile Settings</h3>
                                <p className="text-sm text-default-500">
                                    Manage your account settings and preferences
                                </p>
                            </div>
                        )}
                        {onClose && (
                            <Button
                                isIconOnly
                                variant="light"
                                onPress={onClose}
                                aria-label="Close"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </Button>
                        )}
                    </CardHeader>
                    <Divider />
                </>
            )}

            {/* Content */}
            <CardBody className="p-0">
                <Tabs
                    selectedKey={selectedTab}
                    onSelectionChange={(key) => setSelectedTab(key as string)}
                    orientation={orientation}
                    placement={tabPlacement}
                    size={sizeMapping[size] as any}
                    classNames={{
                        base: 'w-full',
                        tabList: orientation === 'vertical' ? 'w-full' : undefined,
                        panel: 'w-full',
                    }}
                >
                    {effectiveTabs.map((tab) => (
                        <Tab
                            key={tab.key}
                            title={
                                <div className="flex items-center gap-2">
                                    {tab.icon}
                                    <span>{tab.title}</span>
                                    {tab.badge && (
                                        <span className="bg-danger text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] h-5 flex items-center justify-center">
                                            {tab.badge}
                                        </span>
                                    )}
                                </div>
                            }
                            isDisabled={tab.isDisabled || isDisabled}
                        >
                            <div className="p-6">
                                {tab.content}
                            </div>
                        </Tab>
                    ))}
                </Tabs>
            </CardBody>

            {/* Footer */}
            {footerContent && (
                <>
                    <Divider />
                    <CardBody className="pt-4">
                        {footerContent}
                    </CardBody>
                </>
            )}
        </Card>
    );
}

// ============================================================================
// Export
// ============================================================================

export default UserProfile;