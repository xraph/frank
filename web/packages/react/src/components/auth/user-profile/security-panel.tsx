/**
 * @frank-auth/react - Security Panel Component
 *
 * Security settings panel for password management, session control,
 * and account security configuration.
 */

'use client';

import React from 'react';
import {
    Button,
    Card,
    CardBody,
    CardHeader,
    Chip,
    Divider,
    Modal,
    ModalBody,
    ModalContent,
    ModalHeader,
    Switch,
    useDisclosure,
} from '@heroui/react';
import {useAuth} from '../../../hooks/use-auth';
import {useUser} from '../../../hooks/use-user';
import {useSession} from '../../../hooks/use-session';
import {useConfig} from '../../../hooks/use-config';
import {PasswordField} from '../../forms/password-field';

// ============================================================================
// Security Panel Interface
// ============================================================================

export interface SecurityPanelProps {
    /**
     * Success callback
     */
    onSuccess?: (message: string) => void;

    /**
     * Error callback
     */
    onError?: (error: string) => void;

    /**
     * Show password change section
     */
    showPasswordChange?: boolean;

    /**
     * Show session management
     */
    showSessionManagement?: boolean;

    /**
     * Show security preferences
     */
    showSecurityPreferences?: boolean;

    /**
     * Show activity log
     */
    showActivityLog?: boolean;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Whether panel is disabled
     */
    isDisabled?: boolean;

    /**
     * Panel variant
     */
    variant?: 'flat' | 'bordered' | 'shadow';

    /**
     * Panel size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Custom sections
     */
    customSections?: SecurityPanelSection[];

    /**
     * Hide default sections
     */
    hideSections?: string[];
}

export interface SecurityPanelSection {
    key: string;
    title: string;
    description?: string;
    icon?: React.ReactNode;
    content: React.ReactNode;
}

// ============================================================================
// Change Password Form Interface
// ============================================================================

interface ChangePasswordFormProps {
    onSuccess: (message: string) => void;
    onError: (error: string) => void;
    onClose: () => void;
    isOpen: boolean;
}

// ============================================================================
// Device Info Interface
// ============================================================================

interface DeviceInfo {
    browser: string;
    os: string;
    device: string;
    location?: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function getDeviceIcon(deviceInfo: any) {
    const device = deviceInfo?.device?.toLowerCase() || '';
    const os = deviceInfo?.os?.toLowerCase() || '';

    if (device.includes('mobile') || os.includes('ios') || os.includes('android')) {
        return (
            <svg className="w-5 h-5 text-default-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a1 1 0 001-1V4a1 1 0 00-1-1H8a1 1 0 00-1 1v16a1 1 0 001 1z" />
            </svg>
        );
    }

    return (
        <svg className="w-5 h-5 text-default-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
    );
}

function formatLastActive(date: Date | null): string {
    if (!date) return 'Never';

    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
}

// ============================================================================
// Change Password Form Component
// ============================================================================

function ChangePasswordForm({ onSuccess, onError, onClose, isOpen }: ChangePasswordFormProps) {
    const { changePassword } = useUser();

    const [currentPassword, setCurrentPassword] = React.useState('');
    const [newPassword, setNewPassword] = React.useState('');
    const [confirmPassword, setConfirmPassword] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const [errors, setErrors] = React.useState<Record<string, string>>({});

    // Reset form when modal opens/closes
    React.useEffect(() => {
        if (!isOpen) {
            setCurrentPassword('');
            setNewPassword('');
            setConfirmPassword('');
            setErrors({});
        }
    }, [isOpen]);

    // Validate form
    const validateForm = () => {
        const newErrors: Record<string, string> = {};

        if (!currentPassword) {
            newErrors.currentPassword = 'Current password is required';
        }

        if (!newPassword) {
            newErrors.newPassword = 'New password is required';
        } else if (newPassword.length < 8) {
            newErrors.newPassword = 'Password must be at least 8 characters';
        }

        if (!confirmPassword) {
            newErrors.confirmPassword = 'Please confirm your new password';
        } else if (newPassword !== confirmPassword) {
            newErrors.confirmPassword = 'Passwords do not match';
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    // Handle form submission
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            setIsLoading(true);

            await changePassword({
                currentPassword,
                newPassword,
            });

            onSuccess('Password changed successfully');
            onClose();
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to change password';
            onError(message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <PasswordField
                label="Current Password"
                placeholder="Enter your current password"
                value={currentPassword}
                onChange={setCurrentPassword}
                error={errors.currentPassword}
                required
            />

            <PasswordField
                label="New Password"
                placeholder="Enter your new password"
                value={newPassword}
                onChange={setNewPassword}
                error={errors.newPassword}
                showStrength
                required
            />

            <PasswordField
                label="Confirm New Password"
                placeholder="Confirm your new password"
                value={confirmPassword}
                onChange={setConfirmPassword}
                error={errors.confirmPassword}
                required
            />

            <div className="flex justify-end gap-2 pt-4">
                <Button variant="light" onPress={onClose} isDisabled={isLoading}>
                    Cancel
                </Button>
                <Button
                    type="submit"
                    color="primary"
                    isLoading={isLoading}
                    isDisabled={!currentPassword || !newPassword || !confirmPassword}
                >
                    Change Password
                </Button>
            </div>
        </form>
    );
}

// ============================================================================
// Security Panel Component
// ============================================================================

export function SecurityPanel({
                                  onSuccess,
                                  onError,
                                  showPasswordChange = true,
                                  showSessionManagement = true,
                                  showSecurityPreferences = false,
                                  showActivityLog = false,
                                  className = '',
                                  isDisabled = false,
                                  variant = 'bordered',
                                  size = 'md',
                                  customSections = [],
                                  hideSections = [],
                              }: SecurityPanelProps) {
    const { user } = useAuth();
    const {
        sessions,
        isCurrentDevice,
        hasMultipleSessions,
        revokeSession,
        revokeAllSessions,
    } = useSession();
    const { components } = useConfig();

    const changePasswordModal = useDisclosure();

    // Custom component override
    const CustomSecurityPanel = components.SecurityPanel;
    if (CustomSecurityPanel) {
        return <CustomSecurityPanel {...{
            onSuccess, onError, showPasswordChange, showSessionManagement,
            showSecurityPreferences, showActivityLog, className, isDisabled,
            variant, size, customSections, hideSections
        }} />;
    }

    // Handle session revocation
    const handleRevokeSession = async (sessionId: string) => {
        try {
            await revokeSession(sessionId);
            onSuccess?.('Session revoked successfully');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to revoke session';
            onError?.(message);
        }
    };

    // Handle revoking all other sessions
    const handleRevokeAllOthers = async () => {
        try {
            await revokeAllSessions(true);
            onSuccess?.('All other sessions revoked successfully');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to revoke sessions';
            onError?.(message);
        }
    };

    // Don't render if no user
    if (!user) {
        return null;
    }

    return (
        <div className={`space-y-6 ${className}`}>
            {/* Password Security */}
            {showPasswordChange && !hideSections.includes('password') && (
                <Card variant={variant}>
                    <CardHeader>
                        <div className="flex items-center gap-3">
                            <div className="flex items-center justify-center w-10 h-10 bg-primary/10 rounded-lg">
                                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                </svg>
                            </div>
                            <div>
                                <h4 className="text-md font-semibold">Password</h4>
                                <p className="text-sm text-default-500">
                                    Manage your password and account security
                                </p>
                            </div>
                        </div>
                    </CardHeader>
                    <Divider />
                    <CardBody>
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm font-medium">Password</p>
                                <p className="text-xs text-default-500">
                                    Last changed: {user.passwordUpdatedAt ?
                                    new Date(user.passwordUpdatedAt).toLocaleDateString() :
                                    'Unknown'
                                }
                                </p>
                            </div>
                            <Button
                                variant="bordered"
                                size="sm"
                                onPress={changePasswordModal.onOpen}
                                isDisabled={isDisabled}
                            >
                                Change Password
                            </Button>
                        </div>
                    </CardBody>
                </Card>
            )}

            {/* Active Sessions */}
            {showSessionManagement && !hideSections.includes('sessions') && (
                <Card variant={variant}>
                    <CardHeader>
                        <div className="flex items-center justify-between w-full">
                            <div className="flex items-center gap-3">
                                <div className="flex items-center justify-center w-10 h-10 bg-warning/10 rounded-lg">
                                    <svg className="w-5 h-5 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                </div>
                                <div>
                                    <h4 className="text-md font-semibold">Active Sessions</h4>
                                    <p className="text-sm text-default-500">
                                        Manage devices that are signed into your account
                                    </p>
                                </div>
                            </div>

                            {hasMultipleSessions && (
                                <Button
                                    variant="light"
                                    color="danger"
                                    size="sm"
                                    onPress={handleRevokeAllOthers}
                                    isDisabled={isDisabled}
                                >
                                    Sign out all others
                                </Button>
                            )}
                        </div>
                    </CardHeader>
                    <Divider />
                    <CardBody>
                        <div className="space-y-3">
                            {sessions.map((session, index) => {
                                const isCurrent = index === 0; // Assuming first session is current

                                return (
                                    <div
                                        key={session.id}
                                        className="flex items-center justify-between p-3 border border-default-200 rounded-lg"
                                    >
                                        <div className="flex items-center gap-3">
                                            {getDeviceIcon(session.deviceInfo)}

                                            <div className="flex flex-col">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-sm font-medium">
                                                        {session.deviceInfo?.browser || 'Unknown Browser'}
                                                    </span>
                                                    {isCurrent && (
                                                        <Chip size="sm" color="success" variant="flat">
                                                            Current
                                                        </Chip>
                                                    )}
                                                </div>

                                                <div className="flex items-center gap-2 text-xs text-default-500">
                                                    <span>{session.deviceInfo?.os || 'Unknown OS'}</span>
                                                    <span>•</span>
                                                    <span>{session.deviceInfo?.location || 'Unknown Location'}</span>
                                                    <span>•</span>
                                                    <span>Active {formatLastActive(session.lastActiveAt)}</span>
                                                </div>
                                            </div>
                                        </div>

                                        {!isCurrent && (
                                            <Button
                                                variant="light"
                                                color="danger"
                                                size="sm"
                                                onPress={() => handleRevokeSession(session.id)}
                                                isDisabled={isDisabled}
                                            >
                                                Sign out
                                            </Button>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </CardBody>
                </Card>
            )}

            {/* Security Preferences */}
            {showSecurityPreferences && !hideSections.includes('preferences') && (
                <Card variant={variant}>
                    <CardHeader>
                        <div className="flex items-center gap-3">
                            <div className="flex items-center justify-center w-10 h-10 bg-secondary/10 rounded-lg">
                                <svg className="w-5 h-5 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <div>
                                <h4 className="text-md font-semibold">Security Preferences</h4>
                                <p className="text-sm text-default-500">
                                    Configure your security and privacy settings
                                </p>
                            </div>
                        </div>
                    </CardHeader>
                    <Divider />
                    <CardBody>
                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium">Email notifications for sign-ins</p>
                                    <p className="text-xs text-default-500">
                                        Get notified when someone signs into your account
                                    </p>
                                </div>
                                <Switch
                                    defaultSelected
                                    size="sm"
                                    isDisabled={isDisabled}
                                />
                            </div>

                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium">Two-factor authentication</p>
                                    <p className="text-xs text-default-500">
                                        Add an extra layer of security to your account
                                    </p>
                                </div>
                                <Switch
                                    isSelected={user.mfaEnabled}
                                    size="sm"
                                    isDisabled={isDisabled}
                                />
                            </div>

                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium">Session timeout</p>
                                    <p className="text-xs text-default-500">
                                        Automatically sign out after inactivity
                                    </p>
                                </div>
                                <Switch
                                    defaultSelected
                                    size="sm"
                                    isDisabled={isDisabled}
                                />
                            </div>
                        </div>
                    </CardBody>
                </Card>
            )}

            {/* Custom Sections */}
            {customSections.map((section) => (
                !hideSections.includes(section.key) && (
                    <Card key={section.key} variant={variant}>
                        <CardHeader>
                            <div className="flex items-center gap-3">
                                {section.icon && (
                                    <div className="flex items-center justify-center w-10 h-10 bg-default/10 rounded-lg">
                                        {section.icon}
                                    </div>
                                )}
                                <div>
                                    <h4 className="text-md font-semibold">{section.title}</h4>
                                    {section.description && (
                                        <p className="text-sm text-default-500">
                                            {section.description}
                                        </p>
                                    )}
                                </div>
                            </div>
                        </CardHeader>
                        <Divider />
                        <CardBody>
                            {section.content}
                        </CardBody>
                    </Card>
                )
            ))}

            {/* Change Password Modal */}
            <Modal
                isOpen={changePasswordModal.isOpen}
                onOpenChange={changePasswordModal.onOpenChange}
                placement="center"
                size="md"
            >
                <ModalContent>
                    {(onClose) => (
                        <>
                            <ModalHeader>
                                <h3 className="text-lg font-semibold">Change Password</h3>
                            </ModalHeader>
                            <ModalBody>
                                <ChangePasswordForm
                                    onSuccess={(message) => {
                                        onSuccess?.(message);
                                        onClose();
                                    }}
                                    onError={(error) => onError?.(error)}
                                    onClose={onClose}
                                    isOpen={changePasswordModal.isOpen}
                                />
                            </ModalBody>
                        </>
                    )}
                </ModalContent>
            </Modal>
        </div>
    );
}

// ============================================================================
// Export
// ============================================================================

export default SecurityPanel;