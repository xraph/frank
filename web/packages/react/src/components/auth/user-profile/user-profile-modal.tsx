/**
 * @frank-auth/react - User Profile Modal
 *
 * Modal wrapper for the user profile component with responsive
 * design and customizable modal behavior.
 */

'use client';

import React from 'react';
import {Button, Modal, ModalBody, ModalContent, ModalFooter, ModalHeader, useDisclosure,} from '@heroui/react';
import {useConfig} from '../../../hooks/use-config';
import {UserProfile, type UserProfileProps} from './user-profile';

// ============================================================================
// User Profile Modal Interface
// ============================================================================

export interface UserProfileModalProps extends Omit<UserProfileProps, 'onClose' | 'headerContent'> {
    /**
     * Modal trigger element
     */
    trigger?: React.ReactNode;

    /**
     * Whether modal is open (controlled)
     */
    isOpen?: boolean;

    /**
     * Modal open change handler (controlled)
     */
    onOpenChange?: (isOpen: boolean) => void;

    /**
     * Modal size
     */
    modalSize?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl' | '4xl' | '5xl' | 'full';

    /**
     * Modal placement
     */
    placement?: 'auto' | 'top' | 'center' | 'bottom';

    /**
     * Modal backdrop type
     */
    backdrop?: 'transparent' | 'opaque' | 'blur';

    /**
     * Whether modal is dismissable
     */
    isDismissable?: boolean;

    /**
     * Whether to close on outside click
     */
    closeOnOutsideClick?: boolean;

    /**
     * Whether to hide close button
     */
    hideCloseButton?: boolean;

    /**
     * Custom modal className
     */
    modalClassName?: string;

    /**
     * Modal title
     */
    title?: string;

    /**
     * Modal subtitle
     */
    subtitle?: string;

    /**
     * Custom header content
     */
    customHeaderContent?: React.ReactNode;

    /**
     * Custom footer actions
     */
    footerActions?: React.ReactNode;

    /**
     * Show default footer actions
     */
    showDefaultFooter?: boolean;

    /**
     * Save button text
     */
    saveButtonText?: string;

    /**
     * Cancel button text
     */
    cancelButtonText?: string;

    /**
     * Save handler
     */
    onSave?: () => void;

    /**
     * Cancel handler
     */
    onCancel?: () => void;

    /**
     * Modal close handler
     */
    onClose?: () => void;

    /**
     * Whether save button is loading
     */
    isSaveLoading?: boolean;

    /**
     * Whether save button is disabled
     */
    isSaveDisabled?: boolean;

    /**
     * Scroll behavior
     */
    scrollBehavior?: 'inside' | 'outside';

    /**
     * Whether modal should be keyboard focusable
     */
    isKeyboardDismissDisabled?: boolean;

    /**
     * Portal container
     */
    portalContainer?: Element;

    /**
     * Auto focus element
     */
    autoFocus?: boolean;

    /**
     * Default tab to show when modal opens
     */
    defaultActiveTab?: string;
}

// ============================================================================
// User Profile Modal Component
// ============================================================================

export function UserProfileModal({
                                     trigger,
                                     isOpen: controlledIsOpen,
                                     onOpenChange: controlledOnOpenChange,
                                     modalSize = 'lg',
                                     placement = 'center',
                                     backdrop = 'opaque',
                                     isDismissable = true,
                                     closeOnOutsideClick = true,
                                     hideCloseButton = false,
                                     modalClassName = '',
                                     title = 'Profile Settings',
                                     subtitle = 'Manage your account settings and preferences',
                                     customHeaderContent,
                                     footerActions,
                                     showDefaultFooter = false,
                                     saveButtonText = 'Save Changes',
                                     cancelButtonText = 'Cancel',
                                     onSave,
                                     onCancel,
                                     onClose,
                                     isSaveLoading = false,
                                     isSaveDisabled = false,
                                     scrollBehavior = 'inside',
                                     isKeyboardDismissDisabled = false,
                                     portalContainer,
                                     autoFocus = true,
                                     defaultActiveTab,
                                     // UserProfile props
                                     defaultTab,
                                     tabs,
                                     hideTabs,
                                     showOrganizationSettings,
                                     showSecuritySettings,
                                     showMFASettings,
                                     showPasskeySettings,
                                     className,
                                     variant = 'flat',
                                     orientation = 'horizontal',
                                     tabPlacement = 'top',
                                     footerContent,
                                     onProfileUpdate,
                                     onSuccess,
                                     onError,
                                     isLoading,
                                     isDisabled,
                                     size = 'md',
                                     customTabs,
                                 }: UserProfileModalProps) {
    const { components } = useConfig();

    // Use internal disclosure if not controlled
    const disclosure = useDisclosure();
    const isOpen = controlledIsOpen !== undefined ? controlledIsOpen : disclosure.isOpen;
    const onOpenChange = controlledOnOpenChange || disclosure.onOpenChange;

    // Custom component override
    const CustomUserProfileModal = components.UserProfileModal;
    if (CustomUserProfileModal) {
        return <CustomUserProfileModal {...{
            trigger, isOpen: controlledIsOpen, onOpenChange: controlledOnOpenChange,
            modalSize, placement, backdrop, isDismissable, closeOnOutsideClick,
            hideCloseButton, modalClassName, title, subtitle, customHeaderContent,
            footerActions, showDefaultFooter, saveButtonText, cancelButtonText,
            onSave, onCancel, onClose, isSaveLoading, isSaveDisabled,
            scrollBehavior, isKeyboardDismissDisabled, portalContainer, autoFocus,
            defaultActiveTab, defaultTab, tabs, hideTabs, showOrganizationSettings,
            showSecuritySettings, showMFASettings, showPasskeySettings, className,
            variant, orientation, tabPlacement, footerContent, onProfileUpdate,
            onSuccess, onError, isLoading, isDisabled, size, customTabs
        }} />;
    }

    // Handle modal close
    const handleClose = React.useCallback(() => {
        onClose?.();
        onOpenChange(false);
    }, [onClose, onOpenChange]);

    // Handle cancel
    const handleCancel = React.useCallback(() => {
        onCancel?.();
        handleClose();
    }, [onCancel, handleClose]);

    // Handle save
    const handleSave = React.useCallback(() => {
        onSave?.();
        // Note: Don't close modal here, let the parent handle success/error
    }, [onSave]);

    // Success handler that can close modal
    const handleSuccess = React.useCallback((message: string) => {
        onSuccess?.(message);
        if (onSave) {
            // If there's a save handler, the parent decides when to close
            return;
        }
        // Otherwise, close on success
        handleClose();
    }, [onSuccess, onSave, handleClose]);

    // Render trigger button if provided
    const triggerButton = trigger && React.cloneElement(trigger as React.ReactElement, {
        onPress: () => onOpenChange(true),
    });

    return (
        <>
            {triggerButton}

            <Modal
                isOpen={isOpen}
                onOpenChange={onOpenChange}
                size={modalSize}
                placement={placement}
                backdrop={backdrop}
                isDismissable={isDismissable}
                hideCloseButton={hideCloseButton}
                scrollBehavior={scrollBehavior}
                isKeyboardDismissDisabled={isKeyboardDismissDisabled}
                portalContainer={portalContainer}
                shouldBlockScroll={true}
                className={modalClassName}
                classNames={{
                    base: 'max-h-[90vh]',
                    body: 'p-0',
                }}
            >
                <ModalContent>
                    {(onModalClose) => (
                        <>
                            {/* Header */}
                            {(customHeaderContent || title) && (
                                <ModalHeader className="flex flex-col gap-1">
                                    {customHeaderContent || (
                                        <div>
                                            <h3 className="text-lg font-semibold">{title}</h3>
                                            {subtitle && (
                                                <p className="text-sm text-default-500 font-normal">
                                                    {subtitle}
                                                </p>
                                            )}
                                        </div>
                                    )}
                                </ModalHeader>
                            )}

                            {/* Body */}
                            <ModalBody>
                                <UserProfile
                                    defaultTab={defaultActiveTab || defaultTab}
                                    tabs={tabs}
                                    hideTabs={hideTabs}
                                    showOrganizationSettings={showOrganizationSettings}
                                    showSecuritySettings={showSecuritySettings}
                                    showMFASettings={showMFASettings}
                                    showPasskeySettings={showPasskeySettings}
                                    className={className}
                                    variant={variant}
                                    orientation={orientation}
                                    tabPlacement={tabPlacement}
                                    footerContent={footerContent}
                                    onProfileUpdate={onProfileUpdate}
                                    onSuccess={handleSuccess}
                                    onError={onError}
                                    onClose={handleClose}
                                    isLoading={isLoading}
                                    isDisabled={isDisabled}
                                    size={size}
                                    customTabs={customTabs}
                                />
                            </ModalBody>

                            {/* Footer */}
                            {(footerActions || showDefaultFooter) && (
                                <ModalFooter>
                                    {footerActions || (
                                        <div className="flex gap-2">
                                            <Button
                                                variant="light"
                                                onPress={handleCancel}
                                                isDisabled={isSaveLoading}
                                            >
                                                {cancelButtonText}
                                            </Button>
                                            {onSave && (
                                                <Button
                                                    color="primary"
                                                    onPress={handleSave}
                                                    isLoading={isSaveLoading}
                                                    isDisabled={isSaveDisabled}
                                                >
                                                    {saveButtonText}
                                                </Button>
                                            )}
                                        </div>
                                    )}
                                </ModalFooter>
                            )}
                        </>
                    )}
                </ModalContent>
            </Modal>
        </>
    );
}

// ============================================================================
// Hook for Modal Control
// ============================================================================

export function useUserProfileModal() {
    const disclosure = useDisclosure();

    return {
        ...disclosure,
        openProfile: disclosure.onOpen,
        closeProfile: disclosure.onClose,
        toggleProfile: () => disclosure.onOpenChange(!disclosure.isOpen),
    };
}

// ============================================================================
// Export
// ============================================================================

export default UserProfileModal;