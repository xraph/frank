/**
 * @frank-auth/react - Account Linking Components
 *
 * Components for connecting and managing OAuth providers and external accounts,
 * with support for linking, unlinking, and managing connected accounts.
 */

'use client';

import React, {useCallback, useMemo, useState} from 'react';
import {
    Button as HButton,
    Card,
    CardBody,
    Chip,
    Modal,
    ModalBody,
    ModalContent,
    ModalFooter,
    ModalHeader,
    Tooltip
} from '@heroui/react';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    LinkIcon as UnlinkIcon,
    ShieldCheckIcon,
    UserCircleIcon
} from '@heroicons/react/24/outline';

import {useOAuth} from '../../../hooks/use-oauth';
import {useAuth} from '../../../hooks/use-auth';
import {useConfig} from '../../../hooks/use-config';
import FormWrapper from '../../forms/form-wrapper';

// ============================================================================
// Account Linking Types
// ============================================================================

export interface AccountLinkingProps {
    /**
     * Success callback
     */
    onSuccess?: (provider: string, result: any) => void;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Custom title
     */
    title?: string;

    /**
     * Custom subtitle
     */
    subtitle?: string;

    /**
     * Component variant
     */
    variant?: 'default' | 'card' | 'modal';

    /**
     * Size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Custom className
     */
    className?: string;

    /**
     * Show only specific providers
     */
    providers?: string[];

    /**
     * Show connection status
     */
    showStatus?: boolean;

    /**
     * Allow unlinking
     */
    allowUnlink?: boolean;

    /**
     * Require minimum connections
     */
    minimumConnections?: number;
}

export interface ConnectedAccountCardProps {
    provider: string;
    account: any;
    onUnlink?: () => void;
    allowUnlink?: boolean;
    isLoading?: boolean;
    showDetails?: boolean;
}

export interface ProviderConnectionButtonProps {
    provider: string;
    isConnected: boolean;
    onConnect: () => void;
    onDisconnect: () => void;
    isLoading: boolean;
    disabled?: boolean;
    allowUnlink?: boolean;
}

// ============================================================================
// Provider Icons (Static)
// ============================================================================

const ProviderIcon = React.memo(({ provider, className = "w-5 h-5" }: { provider: string; className?: string }) => {
    const icons: Record<string, JSX.Element> = {
        google: (
            <svg className={className} viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
        ),
        github: (
            <svg className={className} fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
        ),
        microsoft: (
            <svg className={className} viewBox="0 0 24 24">
                <path fill="#f25022" d="M1 1h10v10H1z"/>
                <path fill="#00a4ef" d="M13 1h10v10H13z"/>
                <path fill="#7fba00" d="M1 13h10v10H1z"/>
                <path fill="#ffb900" d="M13 13h10v10H13z"/>
            </svg>
        ),
        apple: (
            <svg className={className} fill="currentColor" viewBox="0 0 24 24">
                <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
            </svg>
        ),
        facebook: (
            <svg className={className} fill="#1877f2" viewBox="0 0 24 24">
                <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
            </svg>
        ),
        twitter: (
            <svg className={className} fill="currentColor" viewBox="0 0 24 24">
                <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
            </svg>
        ),
        linkedin: (
            <svg className={className} fill="#0077b5" viewBox="0 0 24 24">
                <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
            </svg>
        ),
        discord: (
            <svg className={className} fill="#5865f2" viewBox="0 0 24 24">
                <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419-.0001 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9554 2.4189-2.1568 2.4189Z"/>
            </svg>
        ),
    };

    return icons[provider] || <UserCircleIcon className={className} />;
});

ProviderIcon.displayName = 'ProviderIcon';

// ============================================================================
// Connected Account Card Component
// ============================================================================

const ConnectedAccountCard = React.memo(({
                                             provider,
                                             account,
                                             onUnlink,
                                             allowUnlink = true,
                                             isLoading = false,
                                             showDetails = true,
                                         }: ConnectedAccountCardProps) => {
    const { components } = useConfig();
    const Button = components.Button ?? HButton;

    const [showUnlinkModal, setShowUnlinkModal] = useState(false);

    const handleUnlinkConfirm = useCallback(() => {
        onUnlink?.();
        setShowUnlinkModal(false);
    }, [onUnlink]);

    const getProviderDisplayName = (provider: string) => {
        const names: Record<string, string> = {
            google: 'Google',
            github: 'GitHub',
            microsoft: 'Microsoft',
            apple: 'Apple',
            facebook: 'Facebook',
            twitter: 'Twitter',
            linkedin: 'LinkedIn',
            discord: 'Discord',
        };
        return names[provider] || provider.charAt(0).toUpperCase() + provider.slice(1);
    };

    const formatConnectionDate = (date: string | Date) => {
        try {
            return new Date(date).toLocaleDateString();
        } catch {
            return 'Unknown';
        }
    };

    return (
        <>
            <Card className="w-full">
                <CardBody className="p-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="flex-shrink-0">
                                <ProviderIcon provider={provider} className="w-8 h-8" />
                            </div>

                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                    <h4 className="font-medium text-foreground">
                                        {getProviderDisplayName(provider)}
                                    </h4>
                                    <Chip
                                        size="sm"
                                        color="success"
                                        variant="flat"
                                        startContent={<CheckCircleIcon className="w-3 h-3" />}
                                    >
                                        Connected
                                    </Chip>
                                </div>

                                {showDetails && account && (
                                    <div className="mt-1 space-y-1">
                                        {account.email && (
                                            <p className="text-sm text-default-500 truncate">
                                                {account.email}
                                            </p>
                                        )}
                                        {account.connectedAt && (
                                            <p className="text-xs text-default-400">
                                                Connected {formatConnectionDate(account.connectedAt)}
                                            </p>
                                        )}
                                    </div>
                                )}
                            </div>

                            <div className="flex items-center gap-2">
                                {allowUnlink && (
                                    <Tooltip content="Disconnect account">
                                        <Button
                                            isIconOnly
                                            size="sm"
                                            variant="light"
                                            color="danger"
                                            onPress={() => setShowUnlinkModal(true)}
                                            isLoading={isLoading}
                                        >
                                            <UnlinkIcon className="w-4 h-4" />
                                        </Button>
                                    </Tooltip>
                                )}
                            </div>
                        </div>
                    </div>
                </CardBody>
            </Card>

            {/* Unlink Confirmation Modal */}
            <Modal
                isOpen={showUnlinkModal}
                onClose={() => setShowUnlinkModal(false)}
                placement="center"
            >
                <ModalContent>
                    <ModalHeader>
                        <div className="flex items-center gap-2">
                            <ExclamationTriangleIcon className="w-5 h-5 text-warning-600" />
                            Disconnect Account
                        </div>
                    </ModalHeader>
                    <ModalBody>
                        <p>
                            Are you sure you want to disconnect your {getProviderDisplayName(provider)} account?
                        </p>
                        <p className="text-sm text-default-500">
                            You won't be able to sign in using {getProviderDisplayName(provider)} until you reconnect it.
                        </p>
                    </ModalBody>
                    <ModalFooter>
                        <Button
                            variant="light"
                            onPress={() => setShowUnlinkModal(false)}
                        >
                            Cancel
                        </Button>
                        <Button
                            color="danger"
                            onPress={handleUnlinkConfirm}
                            isLoading={isLoading}
                        >
                            Disconnect
                        </Button>
                    </ModalFooter>
                </ModalContent>
            </Modal>
        </>
    );
});

ConnectedAccountCard.displayName = 'ConnectedAccountCard';

// ============================================================================
// Provider Connection Button Component
// ============================================================================

const ProviderConnectionButton = React.memo(({
                                                 provider,
                                                 isConnected,
                                                 onConnect,
                                                 onDisconnect,
                                                 isLoading,
                                                 disabled = false,
                                                 allowUnlink = true,
                                             }: ProviderConnectionButtonProps) => {
    const { components } = useConfig();
    const Button = components.Button ?? Button;

    const getProviderDisplayName = (provider: string) => {
        const names: Record<string, string> = {
            google: 'Google',
            github: 'GitHub',
            microsoft: 'Microsoft',
            apple: 'Apple',
            facebook: 'Facebook',
            twitter: 'Twitter',
            linkedin: 'LinkedIn',
            discord: 'Discord',
        };
        return names[provider] || provider.charAt(0).toUpperCase() + provider.slice(1);
    };

    if (isConnected) {
        return (
            <div className="flex items-center justify-between p-4 border border-success-200 bg-success-50 dark:bg-success-900/20 rounded-lg">
                <div className="flex items-center gap-3">
                    <ProviderIcon provider={provider} className="w-6 h-6" />
                    <div>
                        <p className="font-medium text-foreground">
                            {getProviderDisplayName(provider)}
                        </p>
                        <p className="text-sm text-success-600 dark:text-success-400">
                            Connected
                        </p>
                    </div>
                </div>

                {allowUnlink && (
                    <Button
                        size="sm"
                        variant="light"
                        color="danger"
                        onPress={onDisconnect}
                        isLoading={isLoading}
                        isDisabled={disabled}
                        startContent={<UnlinkIcon className="w-4 h-4" />}
                    >
                        Disconnect
                    </Button>
                )}
            </div>
        );
    }

    return (
        <Button
            variant="bordered"
            className="w-full justify-start p-4 h-auto"
            onPress={onConnect}
            isLoading={isLoading}
            isDisabled={disabled}
            startContent={<ProviderIcon provider={provider} className="w-6 h-6" />}
        >
            <div className="flex flex-col items-start">
                <span className="font-medium">
                    Connect {getProviderDisplayName(provider)}
                </span>
                <span className="text-xs text-default-500">
                    Link your {getProviderDisplayName(provider)} account
                </span>
            </div>
        </Button>
    );
});

ProviderConnectionButton.displayName = 'ProviderConnectionButton';

// ============================================================================
// Main Account Linking Component
// ============================================================================

export function AccountLinking({
                                   onSuccess,
                                   onError,
                                   title = 'Connected Accounts',
                                   subtitle = 'Manage your connected social accounts',
                                   variant = 'default',
                                   size = 'md',
                                   className = '',
                                   providers,
                                   showStatus = true,
                                   allowUnlink = true,
                                   minimumConnections = 0,
                               }: AccountLinkingProps) {
    const {
        providers: availableProviders,
        connectProvider,
        disconnectProvider,
        isProviderConnected,
        isLoading,
    } = useOAuth();

    const { user } = useAuth();
    const { components } = useConfig();

    const [loadingProvider, setLoadingProvider] = useState<string | null>(null);

    // Filter providers if specified
    const displayProviders = useMemo(() => {
        if (providers && providers.length > 0) {
            return availableProviders.filter(p => providers.includes(p.name));
        }
        return availableProviders;
    }, [availableProviders, providers]);

    // Get connected accounts
    const connectedAccounts = useMemo(() => {
        if (!user?.connectedAccounts) return [];
        return user.connectedAccounts;
    }, [user]);

    // Handle connect provider
    const handleConnect = useCallback(async (provider: string) => {
        try {
            setLoadingProvider(provider);
            await connectProvider(provider);
            onSuccess?.(provider, { action: 'connect' });
        } catch (error) {
            onError?.(error instanceof Error ? error : new Error(`Failed to connect ${provider}`));
        } finally {
            setLoadingProvider(null);
        }
    }, [connectProvider, onSuccess, onError]);

    // Handle disconnect provider
    const handleDisconnect = useCallback(async (provider: string) => {
        // Check minimum connections
        const connectedCount = connectedAccounts.length;
        if (minimumConnections > 0 && connectedCount <= minimumConnections) {
            onError?.(new Error(`You must have at least ${minimumConnections} connected account(s)`));
            return;
        }

        try {
            setLoadingProvider(provider);
            await disconnectProvider(provider);
            onSuccess?.(provider, { action: 'disconnect' });
        } catch (error) {
            onError?.(error instanceof Error ? error : new Error(`Failed to disconnect ${provider}`));
        } finally {
            setLoadingProvider(null);
        }
    }, [disconnectProvider, connectedAccounts.length, minimumConnections, onSuccess, onError]);

    // Form wrapper props
    const formWrapperProps = useMemo(() => ({
        size,
        variant: 'flat' as const,
        className: `space-y-6 ${className}`,
        title,
        subtitle,
        showCard: variant === 'card',
    }), [size, className, title, subtitle, variant]);

    return (
        <FormWrapper {...formWrapperProps}>
            {/* Connection Status */}
            {showStatus && (
                <div className="flex items-center gap-2 p-4 bg-default-100 dark:bg-default-900/50 rounded-lg">
                    <ShieldCheckIcon className="w-5 h-5 text-success-600" />
                    <div>
                        <p className="text-sm font-medium text-foreground">
                            Account Security
                        </p>
                        <p className="text-xs text-default-500">
                            {connectedAccounts.length} account(s) connected
                            {minimumConnections > 0 && (
                                <span className="ml-1">
                                    (minimum {minimumConnections} required)
                                </span>
                            )}
                        </p>
                    </div>
                </div>
            )}

            {/* Connected Accounts */}
            {connectedAccounts.length > 0 && (
                <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-foreground">
                        Connected Accounts
                    </h3>
                    <div className="space-y-3">
                        {connectedAccounts.map((account: any) => (
                            <ConnectedAccountCard
                                key={account.provider}
                                provider={account.provider}
                                account={account}
                                onUnlink={() => handleDisconnect(account.provider)}
                                allowUnlink={allowUnlink}
                                isLoading={loadingProvider === account.provider}
                            />
                        ))}
                    </div>
                </div>
            )}

            {/* Available Providers */}
            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-foreground">
                    {connectedAccounts.length > 0 ? 'Available Connections' : 'Connect Your Accounts'}
                </h3>

                <div className="space-y-3">
                    {displayProviders
                        .filter(provider => !isProviderConnected(provider.name))
                        .map((provider) => (
                            <ProviderConnectionButton
                                key={provider.name}
                                provider={provider.name}
                                isConnected={false}
                                onConnect={() => handleConnect(provider.name)}
                                onDisconnect={() => handleDisconnect(provider.name)}
                                isLoading={loadingProvider === provider.name}
                                disabled={isLoading}
                            />
                        ))}
                </div>

                {displayProviders.filter(p => !isProviderConnected(p.name)).length === 0 && (
                    <div className="text-center py-8">
                        <UserCircleIcon className="w-12 h-12 text-default-400 mx-auto mb-4" />
                        <p className="text-default-500">
                            All available accounts are connected
                        </p>
                    </div>
                )}
            </div>

            {/* Security Note */}
            <div className="text-center text-xs text-default-400 border-t pt-4">
                <p>
                    Connected accounts can be used to sign in to your account.
                    You can disconnect them at any time.
                </p>
            </div>
        </FormWrapper>
    );
}

// ============================================================================
// Account Linking Variants
// ============================================================================

/**
 * Account Linking Card
 */
export function AccountLinkingCard(props: Omit<AccountLinkingProps, 'variant'>) {
    return <AccountLinking {...props} variant="card" />;
}

/**
 * Simple Provider List (for settings pages)
 */
export function ConnectedAccountsList({
                                          allowUnlink = true,
                                          showDetails = true,
                                          onUnlink,
                                      }: {
    allowUnlink?: boolean;
    showDetails?: boolean;
    onUnlink?: (provider: string) => void;
}) {
    const { user } = useAuth();
    const { disconnectProvider } = useOAuth();
    const [loadingProvider, setLoadingProvider] = useState<string | null>(null);

    const handleUnlink = useCallback(async (provider: string) => {
        try {
            setLoadingProvider(provider);
            await disconnectProvider(provider);
            onUnlink?.(provider);
        } catch (error) {
            console.error('Failed to unlink provider:', error);
        } finally {
            setLoadingProvider(null);
        }
    }, [disconnectProvider, onUnlink]);

    const connectedAccounts = user?.connectedAccounts || [];

    if (connectedAccounts.length === 0) {
        return (
            <div className="text-center py-4">
                <p className="text-default-500 text-sm">No connected accounts</p>
            </div>
        );
    }

    return (
        <div className="space-y-3">
            {connectedAccounts.map((account: any) => (
                <ConnectedAccountCard
                    key={account.provider}
                    provider={account.provider}
                    account={account}
                    onUnlink={() => handleUnlink(account.provider)}
                    allowUnlink={allowUnlink}
                    isLoading={loadingProvider === account.provider}
                    showDetails={showDetails}
                />
            ))}
        </div>
    );
}

// ============================================================================
// Export
// ============================================================================

export default AccountLinking;