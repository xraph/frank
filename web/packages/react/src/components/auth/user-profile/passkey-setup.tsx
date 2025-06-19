/**
 * @frank-auth/react - Passkey Setup Component
 *
 * Passkey (WebAuthn/FIDO2) setup and management interface for
 * passwordless authentication with hardware security keys and biometrics.
 */

'use client';

import React from 'react';
import {
    Alert,
    Button,
    Card,
    CardBody,
    CardHeader,
    Chip,
    Divider,
    Dropdown,
    DropdownItem,
    DropdownMenu,
    DropdownTrigger,
    Input,
    Modal,
    ModalBody,
    ModalContent,
    ModalHeader,
    useDisclosure,
} from '@heroui/react';
import {usePasskeys} from '../../../hooks/use-passkeys';
import {useConfig} from '../../../hooks/use-config';

// ============================================================================
// Passkey Setup Interface
// ============================================================================

export interface PasskeySetupProps {
    /**
     * Success callback
     */
    onSuccess?: (message: string) => void;

    /**
     * Error callback
     */
    onError?: (error: string) => void;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Whether component is disabled
     */
    isDisabled?: boolean;

    /**
     * Component variant
     */
    variant?: 'flat' | 'bordered' | 'shadow';

    /**
     * Component size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Show registration flow
     */
    showRegistration?: boolean;

    /**
     * Show passkey management
     */
    showManagement?: boolean;

    /**
     * Maximum number of passkeys
     */
    maxPasskeys?: number;

    /**
     * Hide specific sections
     */
    hideSections?: string[];

    /**
     * Custom passkey types
     */
    customTypes?: PasskeyTypeConfig[];
}

export interface PasskeyTypeConfig {
    key: string;
    name: string;
    description: string;
    icon: React.ReactNode;
    isRecommended?: boolean;
}

// ============================================================================
// Passkey Registration Component
// ============================================================================

interface PasskeyRegistrationProps {
    onSuccess: (message: string) => void;
    onError: (error: string) => void;
    onClose: () => void;
    isOpen: boolean;
}

function PasskeyRegistration({onSuccess, onError, onClose, isOpen}: PasskeyRegistrationProps) {
    const {registerPasskey, isSupported, isAvailable} = usePasskeys();

    const [step, setStep] = React.useState<'intro' | 'name' | 'registering'>('intro');
    const [passkeyName, setPasskeyName] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);

    // Reset state when modal opens/closes
    React.useEffect(() => {
        if (!isOpen) {
            setStep('intro');
            setPasskeyName('');
        } else {
            // Generate default name based on device
            const deviceInfo = getDeviceInfo();
            setPasskeyName(`${deviceInfo.browser} on ${deviceInfo.os}`);
        }
    }, [isOpen]);

    // Get device information for default naming
    const getDeviceInfo = () => {
        const userAgent = navigator.userAgent;
        let browser = 'Unknown Browser';
        let os = 'Unknown OS';

        // Detect browser
        if (userAgent.includes('Chrome')) browser = 'Chrome';
        else if (userAgent.includes('Firefox')) browser = 'Firefox';
        else if (userAgent.includes('Safari')) browser = 'Safari';
        else if (userAgent.includes('Edge')) browser = 'Edge';

        // Detect OS
        if (userAgent.includes('Windows')) os = 'Windows';
        else if (userAgent.includes('Mac')) os = 'macOS';
        else if (userAgent.includes('Linux')) os = 'Linux';
        else if (userAgent.includes('Android')) os = 'Android';
        else if (userAgent.includes('iOS')) os = 'iOS';

        return {browser, os};
    };

    // Handle passkey registration
    const handleRegister = async () => {
        if (!passkeyName.trim()) {
            onError('Please enter a name for your passkey');
            return;
        }

        try {
            setIsLoading(true);
            setStep('registering');

            await registerPasskey(passkeyName.trim());
            onSuccess('Passkey registered successfully');
            onClose();
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to register passkey';
            onError(message);
            setStep('name'); // Go back to name step
        } finally {
            setIsLoading(false);
        }
    };

    // Check support
    if (!isSupported) {
        return (
            <div className="text-center space-y-4">
                <div className="flex items-center justify-center w-16 h-16 bg-danger/10 rounded-full mx-auto">
                    <svg className="w-8 h-8 text-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                </div>

                <div>
                    <h3 className="text-lg font-semibold">Passkeys Not Supported</h3>
                    <p className="text-sm text-default-500 mt-2">
                        Your browser doesn't support passkeys. Please use a modern browser like Chrome, Firefox, Safari,
                        or Edge.
                    </p>
                </div>

                <Button variant="light" onPress={onClose}>
                    Close
                </Button>
            </div>
        );
    }

    if (!isAvailable) {
        return (
            <div className="text-center space-y-4">
                <div className="flex items-center justify-center w-16 h-16 bg-warning/10 rounded-full mx-auto">
                    <svg className="w-8 h-8 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                </div>

                <div>
                    <h3 className="text-lg font-semibold">No Authenticator Available</h3>
                    <p className="text-sm text-default-500 mt-2">
                        No biometric or security key authenticator is available on this device.
                    </p>
                </div>

                <Button variant="light" onPress={onClose}>
                    Close
                </Button>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {step === 'intro' && (
                <div className="text-center space-y-4">
                    <div className="flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mx-auto">
                        <svg className="w-8 h-8 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                        </svg>
                    </div>

                    <div>
                        <h3 className="text-lg font-semibold">Create a Passkey</h3>
                        <p className="text-sm text-default-500 mt-2">
                            Passkeys are a secure and convenient way to sign in without a password.
                        </p>
                    </div>

                    <div className="text-left space-y-3">
                        <div className="flex items-start gap-3">
                            <div
                                className="flex items-center justify-center w-6 h-6 bg-success text-white text-xs rounded-full flex-shrink-0 mt-0.5">✓
                            </div>
                            <div>
                                <p className="text-sm font-medium">More secure than passwords</p>
                                <p className="text-xs text-default-500">Protected by your device's security</p>
                            </div>
                        </div>
                        <div className="flex items-start gap-3">
                            <div
                                className="flex items-center justify-center w-6 h-6 bg-success text-white text-xs rounded-full flex-shrink-0 mt-0.5">✓
                            </div>
                            <div>
                                <p className="text-sm font-medium">Fast and convenient</p>
                                <p className="text-xs text-default-500">Sign in with just your fingerprint or face</p>
                            </div>
                        </div>
                        <div className="flex items-start gap-3">
                            <div
                                className="flex items-center justify-center w-6 h-6 bg-success text-white text-xs rounded-full flex-shrink-0 mt-0.5">✓
                            </div>
                            <div>
                                <p className="text-sm font-medium">Phishing resistant</p>
                                <p className="text-xs text-default-500">Can't be stolen or used on fake sites</p>
                            </div>
                        </div>
                    </div>

                    <Button
                        color="primary"
                        onPress={() => setStep('name')}
                        className="w-full"
                    >
                        Continue
                    </Button>
                </div>
            )}

            {step === 'name' && (
                <div className="space-y-4">
                    <div className="text-center">
                        <h3 className="text-lg font-semibold">Name Your Passkey</h3>
                        <p className="text-sm text-default-500 mt-2">
                            Give your passkey a name so you can identify it later.
                        </p>
                    </div>

                    <Input
                        label="Passkey Name"
                        placeholder="Enter a name for this passkey"
                        value={passkeyName}
                        onValueChange={setPasskeyName}
                        description="For example: 'iPhone Touch ID' or 'YubiKey'"
                        isInvalid={!passkeyName.trim()}
                        errorMessage={!passkeyName.trim() ? 'Name is required' : ''}
                    />

                    <div className="flex gap-2">
                        <Button
                            variant="light"
                            onPress={() => setStep('intro')}
                            className="flex-1"
                        >
                            Back
                        </Button>
                        <Button
                            color="primary"
                            onPress={handleRegister}
                            isDisabled={!passkeyName.trim()}
                            className="flex-1"
                        >
                            Create Passkey
                        </Button>
                    </div>
                </div>
            )}

            {step === 'registering' && (
                <div className="text-center space-y-4">
                    <div className="flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mx-auto">
                        <svg className="w-8 h-8 text-primary animate-pulse" fill="none" stroke="currentColor"
                             viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                        </svg>
                    </div>

                    <div>
                        <h3 className="text-lg font-semibold">Creating Passkey...</h3>
                        <p className="text-sm text-default-500 mt-2">
                            Follow your browser's prompts to complete the setup.
                        </p>
                    </div>

                    <Alert color="primary" variant="flat">
                        <div className="space-y-1">
                            <p className="text-sm font-medium">What to expect:</p>
                            <ul className="text-xs space-y-1 ml-4">
                                <li>• You may be asked to use your fingerprint, face, or PIN</li>
                                <li>• Or insert and tap your security key</li>
                                <li>• Allow the browser to create a passkey</li>
                            </ul>
                        </div>
                    </Alert>
                </div>
            )}
        </div>
    );
}

// ============================================================================
// Passkey Management Component
// ============================================================================

interface PasskeyItemProps {
    passkey: any;
    onRename: (id: string, newName: string) => void;
    onDelete: (id: string) => void;
    isDisabled?: boolean;
}

function PasskeyItem({passkey, onRename, onDelete, isDisabled}: PasskeyItemProps) {
    const [isEditing, setIsEditing] = React.useState(false);
    const [editName, setEditName] = React.useState(passkey.name);

    const handleSaveEdit = () => {
        if (editName.trim() && editName !== passkey.name) {
            onRename(passkey.id, editName.trim());
        }
        setIsEditing(false);
    };

    const handleCancelEdit = () => {
        setEditName(passkey.name);
        setIsEditing(false);
    };

    const getPasskeyIcon = () => {
        const authenticatorType = passkey.authenticatorType?.toLowerCase() || '';

        if (authenticatorType.includes('platform')) {
            // Platform authenticator (Touch ID, Face ID, Windows Hello, etc.)
            return (
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            );
        } else {
            // Cross-platform authenticator (Security keys, etc.)
            return (
                <svg className="w-5 h-5 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                </svg>
            );
        }
    }

    const formatDate = (date: string | Date) => {
        return new Date(date).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    };

    return (
        <div className="flex items-center justify-between p-4 border border-default-200 rounded-lg">
            <div className="flex items-center gap-3">
                <div className="flex items-center justify-center w-10 h-10 bg-default-100 rounded-lg">
                    {getPasskeyIcon()}
                </div>

                <div className="flex flex-col">
                    {isEditing ? (
                        <div className="flex items-center gap-2">
                            <Input
                                value={editName}
                                onValueChange={setEditName}
                                size="sm"
                                className="w-48"
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') handleSaveEdit();
                                    if (e.key === 'Escape') handleCancelEdit();
                                }}
                                autoFocus
                            />
                            <Button size="sm" color="primary" onPress={handleSaveEdit}>
                                Save
                            </Button>
                            <Button size="sm" variant="light" onPress={handleCancelEdit}>
                                Cancel
                            </Button>
                        </div>
                    ) : (
                        <>
                            <div className="flex items-center gap-2">
                                <span className="text-sm font-medium">{passkey.name}</span>
                                {passkey.isPrimary && (
                                    <Chip size="sm" color="primary" variant="flat">
                                        Primary
                                    </Chip>
                                )}
                            </div>
                            <div className="flex items-center gap-2 text-xs text-default-500">
                                <span>Created {formatDate(passkey.createdAt)}</span>
                                {passkey.lastUsedAt && (
                                    <>
                                        <span>•</span>
                                        <span>Last used {formatDate(passkey.lastUsedAt)}</span>
                                    </>
                                )}
                            </div>
                        </>
                    )}
                </div>
            </div>

            {!isEditing && (
                <Dropdown>
                    <DropdownTrigger>
                        <Button
                            isIconOnly
                            variant="light"
                            size="sm"
                            isDisabled={isDisabled}
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                      d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"/>
                            </svg>
                        </Button>
                    </DropdownTrigger>
                    <DropdownMenu>
                        <DropdownItem
                            key="rename"
                            onPress={() => setIsEditing(true)}
                        >
                            Rename
                        </DropdownItem>
                        <DropdownItem
                            key="delete"
                            color="danger"
                            onPress={() => onDelete(passkey.id)}
                        >
                            Delete
                        </DropdownItem>
                    </DropdownMenu>
                </Dropdown>
            )}
        </div>
    );
}

// ============================================================================
// Passkey Setup Component
// ============================================================================

export function PasskeySetup({
                                 onSuccess,
                                 onError,
                                 className = '',
                                 isDisabled = false,
                                 variant = 'bordered',
                                 size = 'md',
                                 showRegistration = true,
                                 showManagement = true,
                                 maxPasskeys = 10,
                                 hideSections = [],
                                 customTypes = [],
                             }: PasskeySetupProps) {
    const {
        passkeys,
        isSupported,
        isAvailable,
        deletePasskey,
        renamePasskey,
        passkeyCount,
        isLoading,
    } = usePasskeys();

    const {components} = useConfig();
    const registrationModal = useDisclosure();

    // Custom component override
    const CustomPasskeySetup = components.PasskeySetup;
    if (CustomPasskeySetup) {
        return <CustomPasskeySetup {...{
            onSuccess, onError, className, isDisabled, variant, size,
            showRegistration, showManagement, maxPasskeys, hideSections, customTypes
        }} />;
    }

    // Handle passkey deletion
    const handleDeletePasskey = async (passkeyId: string) => {
        try {
            await deletePasskey(passkeyId);
            onSuccess?.('Passkey deleted successfully');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to delete passkey';
            onError?.(message);
        }
    };

    // Handle passkey rename
    const handleRenamePasskey = async (passkeyId: string, newName: string) => {
        try {
            await renamePasskey(passkeyId, newName);
            onSuccess?.('Passkey renamed successfully');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to rename passkey';
            onError?.(message);
        }
    };

    return (
        <div className={`space-y-6 ${className}`}>
            {/* Passkey Status */}
            <Card variant={variant}>
                <CardHeader>
                    <div className="flex items-center justify-between w-full">
                        <div className="flex items-center gap-3">
                            <div className={`flex items-center justify-center w-10 h-10 rounded-lg ${
                                passkeyCount > 0 ? 'bg-success/10' : 'bg-default/10'
                            }`}>
                                <svg className={`w-5 h-5 ${passkeyCount > 0 ? 'text-success' : 'text-default-400'}`}
                                     fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                          d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                                </svg>
                            </div>
                            <div>
                                <h4 className="text-md font-semibold">Passkeys</h4>
                                <div className="flex items-center gap-2">
                                    <span className="text-sm text-default-500">
                                        {passkeyCount} of {maxPasskeys} passkeys configured
                                    </span>
                                    {passkeyCount > 0 && (
                                        <Chip size="sm" color="success" variant="flat">
                                            Active
                                        </Chip>
                                    )}
                                </div>
                            </div>
                        </div>

                        {showRegistration && isSupported && isAvailable && passkeyCount < maxPasskeys && (
                            <Button
                                color="primary"
                                size="sm"
                                onPress={registrationModal.onOpen}
                                isDisabled={isDisabled || isLoading}
                            >
                                Add Passkey
                            </Button>
                        )}
                    </div>
                </CardHeader>

                {passkeyCount === 0 && (
                    <>
                        <Divider/>
                        <CardBody>
                            {!isSupported ? (
                                <Alert color="warning" variant="flat">
                                    <div>
                                        <p className="text-sm font-medium">Passkeys Not Supported</p>
                                        <p className="text-xs mt-1">
                                            Your browser doesn't support passkeys. Please use a modern browser.
                                        </p>
                                    </div>
                                </Alert>
                            ) : !isAvailable ? (
                                <Alert color="warning" variant="flat">
                                    <div>
                                        <p className="text-sm font-medium">No Authenticator Available</p>
                                        <p className="text-xs mt-1">
                                            No biometric or security key authenticator is available on this device.
                                        </p>
                                    </div>
                                </Alert>
                            ) : (
                                <div className="space-y-3">
                                    <p className="text-sm text-default-600">
                                        Passkeys provide a secure and convenient way to sign in without passwords.
                                        They use your device's built-in security features like fingerprint, face
                                        recognition, or security keys.
                                    </p>

                                    <div className="flex items-center gap-2">
                                        <svg className="w-4 h-4 text-primary" fill="none" stroke="currentColor"
                                             viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                        </svg>
                                        <p className="text-xs text-default-500">
                                            Passkeys are more secure than passwords and can't be stolen or phished.
                                        </p>
                                    </div>
                                </div>
                            )}
                        </CardBody>
                    </>
                )}
            </Card>

            {/* Passkey Management */}
            {showManagement && passkeyCount > 0 && !hideSections.includes('management') && (
                <Card variant={variant}>
                    <CardHeader>
                        <div className="flex items-center gap-3">
                            <div className="flex items-center justify-center w-10 h-10 bg-primary/10 rounded-lg">
                                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor"
                                     viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                          d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                                </svg>
                            </div>
                            <div>
                                <h4 className="text-md font-semibold">Your Passkeys</h4>
                                <p className="text-sm text-default-500">
                                    Manage your registered passkeys
                                </p>
                            </div>
                        </div>
                    </CardHeader>
                    <Divider/>
                    <CardBody>
                        <div className="space-y-3">
                            {passkeys.map((passkey) => (
                                <PasskeyItem
                                    key={passkey.id}
                                    passkey={passkey}
                                    onRename={handleRenamePasskey}
                                    onDelete={handleDeletePasskey}
                                    isDisabled={isDisabled}
                                />
                            ))}
                        </div>
                    </CardBody>
                </Card>
            )}

            {/* Registration Modal */}
            <Modal
                isOpen={registrationModal.isOpen}
                onOpenChange={registrationModal.onOpenChange}
                size="md"
                placement="center"
                hideCloseButton
            >
                <ModalContent>
                    {(onClose) => (
                        <>
                            <ModalHeader/>
                            <ModalBody>
                                <PasskeyRegistration
                                    onSuccess={(message) => {
                                        onSuccess?.(message);
                                        onClose();
                                    }}
                                    onError={(error) => onError?.(error)}
                                    onClose={onClose}
                                    isOpen={registrationModal.isOpen}
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

export default PasskeySetup;