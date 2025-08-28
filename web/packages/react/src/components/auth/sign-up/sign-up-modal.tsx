/**
 * @frank-auth/react - Sign Up Modal Component
 *
 * Modal wrapper for sign-up form with customizable overlay and behavior.
 */

"use client";

import { Button, Modal, ModalBody, ModalHeader } from "@/components/ui";
import { XMarkIcon } from "@heroicons/react/24/outline";
import React, { useCallback } from "react";

import { useConfig } from "../../../hooks/use-config";
import type { SignUpModalProps } from "./index";
import { SignUpForm } from "./sign-up-form";

// ============================================================================
// Sign Up Modal Component
// ============================================================================

export function SignUpModal({
  isOpen = false,
  onClose,
  modalSize = "md",
  closeOnBackdropClick = true,
  closeOnEscape = true,
  modalClassName = "",
  showCloseButton = true,
  methods = ["password", "oauth", "magic-link"],
  email,
  organizationId,
  invitationToken,
  redirectUrl,
  onSuccess,
  onError,
  title,
  subtitle,
  size = "md",
  showBranding = true,
  disabled = false,
  requireTerms = true,
  termsUrl = "/terms",
  privacyUrl = "/privacy",
  backdrop = "blur",
  placement = "center",
}: SignUpModalProps) {
  const { components } = useConfig();

  // Custom component override
  const CustomSignUpModal = components.SignUpModal;
  if (CustomSignUpModal) {
    return (
      <CustomSignUpModal
        {...{
          isOpen,
          onClose,
          modalSize,
          closeOnBackdropClick,
          closeOnEscape,
          modalClassName,
          showCloseButton,
          methods,
          email,
          organizationId,
          invitationToken,
          redirectUrl,
          onSuccess,
          onError,
          title,
          subtitle,
          size,
          showBranding,
          disabled,
          requireTerms,
          termsUrl,
          privacyUrl,
          backdrop,
          placement,
        }}
      />
    );
  }

  // Handle successful sign-up
  const handleSuccess = useCallback(
    (result: any) => {
      onSuccess?.(result);

      // Auto-close modal on success unless redirecting
      if (!redirectUrl) {
        setTimeout(() => {
          onClose?.();
        }, 2000); // Allow time to see success message
      }
    },
    [onSuccess, onClose, redirectUrl],
  );

  // Handle modal close
  const handleClose = useCallback(() => {
    if (disabled) return;
    onClose?.();
  }, [onClose, disabled]);

  // Get modal size mapping
  const getSizeProps = () => {
    switch (modalSize) {
      case "sm":
        return {
          size: "sm" as const,
          className: "max-w-sm max-h-[90vh]",
          scrollBehavior: "inside" as const,
        };
      case "md":
        return {
          size: "md" as const,
          className: "max-w-md max-h-[90vh]",
          scrollBehavior: "inside" as const,
        };
      case "lg":
        return {
          size: "lg" as const,
          className: "max-w-lg max-h-[90vh]",
          scrollBehavior: "inside" as const,
        };
      case "xl":
        return {
          size: "xl" as const,
          className: "max-w-xl max-h-[90vh]",
          scrollBehavior: "inside" as const,
        };
      case "full":
        return {
          size: "full" as const,
          className: "max-w-full h-full",
          scrollBehavior: "outside" as const,
        };
      default:
        return {
          size: "md" as const,
          className: "max-w-md max-h-[90vh]",
          scrollBehavior: "inside" as const,
        };
    }
  };

  const sizeProps = getSizeProps();

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      size={sizeProps.size}
      backdrop={backdrop}
      placement={placement}
      scrollBehavior={sizeProps.scrollBehavior}
      closeButton={false} // We'll handle the close button manually
      isDismissable={closeOnBackdropClick && !disabled}
      isKeyboardDismissDisabled={!closeOnEscape || disabled}
      className={`${modalClassName}`}
      classNames={{
        wrapper: "z-[9999]",
        backdrop: "z-[9998]",
        base: `${sizeProps.className}`,
        body: "px-0 py-0",
      }}
    >
      <>
        {/* Modal Header */}
        <ModalHeader className="flex items-center justify-between px-6 py-4 border-b border-divider">
          <div className="flex-1">
            {title && (
              <h2 className="text-lg font-semibold text-foreground">{title}</h2>
            )}
            {subtitle && (
              <p className="text-sm text-default-500 mt-1">{subtitle}</p>
            )}
          </div>

          {showCloseButton && (
            <Button
              isIconOnly
              variant="light"
              size="sm"
              onPress={handleClose}
              className="text-default-400 hover:text-default-600 -mr-2"
              isDisabled={disabled}
            >
              <XMarkIcon className="w-4 h-4" />
            </Button>
          )}
        </ModalHeader>

        {/* Modal Body */}
        <ModalBody>
          <div className="px-6 py-6">
            <SignUpForm
              methods={methods}
              email={email}
              organizationId={organizationId}
              invitationToken={invitationToken}
              redirectUrl={redirectUrl}
              onSuccess={handleSuccess}
              onError={onError}
              title={undefined} // Title is in header
              subtitle={undefined} // Subtitle is in header
              size={size}
              showBranding={showBranding}
              disabled={disabled}
              requireTerms={requireTerms}
              termsUrl={termsUrl}
              privacyUrl={privacyUrl}
              variant="minimal"
              className="space-y-4"
              showSignInLink={true}
              autoFocus={true}
            />
          </div>
        </ModalBody>
      </>
    </Modal>
  );
}

// ============================================================================
// Sign Up Modal Hook
// ============================================================================

/**
 * Hook for managing sign-up modal state
 */
export function useSignUpModal() {
  const [isOpen, setIsOpen] = React.useState(false);
  const [modalData, setModalData] = React.useState<{
    email?: string;
    organizationId?: string;
    invitationToken?: string;
  }>({});

  const open = useCallback((data?: typeof modalData) => {
    if (data) {
      setModalData(data);
    }
    setIsOpen(true);
  }, []);

  const close = useCallback(() => {
    setIsOpen(false);
    // Clear data after modal closes
    setTimeout(() => {
      setModalData({});
    }, 300);
  }, []);

  const toggle = useCallback(() => setIsOpen((prev) => !prev), []);

  return {
    isOpen,
    open,
    close,
    toggle,
    setIsOpen,
    modalData,
    setModalData,
  };
}

// ============================================================================
// Sign Up Modal with Trigger
// ============================================================================

export interface SignUpModalWithTriggerProps extends SignUpModalProps {
  /**
   * Trigger element
   */
  trigger?: React.ReactElement;

  /**
   * Trigger props (for default button)
   */
  triggerProps?: {
    children?: React.ReactNode;
    variant?:
      | "solid"
      | "bordered"
      | "light"
      | "flat"
      | "faded"
      | "shadow"
      | "ghost";
    color?:
      | "default"
      | "primary"
      | "secondary"
      | "success"
      | "warning"
      | "danger";
    size?: "sm" | "md" | "lg";
    fullWidth?: boolean;
    startContent?: React.ReactNode;
    endContent?: React.ReactNode;
    className?: string;
    disabled?: boolean;
  };

  /**
   * Pre-fill modal with data when opened
   */
  modalData?: {
    email?: string;
    organizationId?: string;
    invitationToken?: string;
  };
}

/**
 * Sign Up Modal with built-in trigger button
 */
export function SignUpModalWithTrigger({
  trigger,
  triggerProps = {},
  modalData,
  ...modalProps
}: SignUpModalWithTriggerProps) {
  const { isOpen, open, close } = useSignUpModal();

  // Default trigger button
  const defaultTrigger = (
    <Button
      variant={triggerProps.variant || "solid"}
      color={triggerProps.color || "primary"}
      size={triggerProps.size || "md"}
      fullWidth={triggerProps.fullWidth}
      startContent={triggerProps.startContent}
      endContent={triggerProps.endContent}
      className={triggerProps.className}
      isDisabled={triggerProps.disabled}
      onPress={() => open(modalData)}
    >
      {triggerProps.children || "Sign Up"}
    </Button>
  );

  // Use custom trigger or default
  const triggerElement = trigger
    ? React.cloneElement(trigger, {
        onClick: (e: React.MouseEvent) => {
          trigger.props.onClick?.(e);
          open(modalData);
        },
      })
    : defaultTrigger;

  return (
    <>
      {triggerElement}
      <SignUpModal
        {...modalProps}
        isOpen={isOpen}
        onClose={close}
        email={modalData?.email || modalProps.email}
        organizationId={modalData?.organizationId || modalProps.organizationId}
        invitationToken={
          modalData?.invitationToken || modalProps.invitationToken
        }
      />
    </>
  );
}

// ============================================================================
// Specialized Modal Variants
// ============================================================================

/**
 * Compact Sign Up Modal
 */
export function CompactSignUpModal(props: SignUpModalProps) {
  return <SignUpModal {...props} modalSize="sm" size="sm" />;
}

/**
 * Large Sign Up Modal
 */
export function LargeSignUpModal(props: SignUpModalProps) {
  return <SignUpModal {...props} modalSize="lg" size="lg" />;
}

/**
 * Full Screen Sign Up Modal
 */
export function FullScreenSignUpModal(props: SignUpModalProps) {
  return (
    <SignUpModal {...props} modalSize="full" size="lg" backdrop="opaque" />
  );
}

/**
 * Organization Invitation Modal
 */
export interface OrganizationInviteModalProps
  extends Omit<SignUpModalProps, "invitationToken" | "organizationId"> {
  /**
   * Invitation token
   */
  invitationToken: string;

  /**
   * Whether modal opens automatically
   */
  autoOpen?: boolean;
}

export function OrganizationInviteModal({
  invitationToken,
  autoOpen = false,
  title,
  subtitle,
  ...props
}: OrganizationInviteModalProps) {
  const [isOpen, setIsOpen] = React.useState(autoOpen);

  // Parse invitation token to get organization info
  const invitationData = React.useMemo(() => {
    try {
      const decoded = atob(invitationToken);
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }, [invitationToken]);

  const finalTitle =
    title ||
    (invitationData?.orgName
      ? `Join ${invitationData.orgName}`
      : "Organization Invitation");

  const finalSubtitle =
    subtitle ||
    (invitationData?.inviterName
      ? `${invitationData.inviterName} has invited you to join`
      : "You've been invited to join an organization");

  return (
    <SignUpModal
      {...props}
      isOpen={isOpen}
      onClose={() => setIsOpen(false)}
      invitationToken={invitationToken}
      organizationId={invitationData?.orgId}
      title={finalTitle}
      subtitle={finalSubtitle}
      showBranding={true}
      backdrop="blur"
      closeOnBackdropClick={false} // Require explicit close for invitations
    />
  );
}

// ============================================================================
// Export
// ============================================================================

export default SignUpModal;
