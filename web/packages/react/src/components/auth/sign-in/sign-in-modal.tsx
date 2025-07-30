/**
 * @frank-auth/react - Sign In Modal Component
 *
 * Modal wrapper for sign-in form with customizable overlay and behavior.
 */

"use client";

import {
	Button,
	Modal,
	ModalBody,
	ModalFooter,
	ModalHeader,
} from "@/components/ui";
import { XMarkIcon } from "@heroicons/react/24/outline";
import React, { useCallback } from "react";

import { useConfig } from "../../../hooks/use-config";
import { SignInForm } from "./sign-in-form";

// ============================================================================
// Sign In Modal Types
// ============================================================================

export interface SignInModalProps {
	/**
	 * Whether the modal is open
	 */
	isOpen?: boolean;

	/**
	 * Callback for when modal should close
	 */
	onClose?: () => void;

	/**
	 * Modal size
	 */
	modalSize?: "sm" | "md" | "lg" | "xl" | "full";

	/**
	 * Whether modal can be closed by clicking backdrop
	 */
	closeOnBackdropClick?: boolean;

	/**
	 * Whether modal can be closed by pressing escape
	 */
	closeOnEscape?: boolean;

	/**
	 * Custom modal className
	 */
	modalClassName?: string;

	/**
	 * Show close button
	 */
	showCloseButton?: boolean;

	/**
	 * Sign-in methods to show
	 */
	methods?: ("password" | "oauth" | "magic-link" | "passkey" | "sso")[];

	/**
	 * Initial email value
	 */
	email?: string;

	/**
	 * Initial organization ID
	 */
	organizationId?: string;

	/**
	 * Redirect URL after successful sign-in
	 */
	redirectUrl?: string;

	/**
	 * Success callback
	 */
	onSuccess?: (result: any) => void;

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
	 * Form size
	 */
	size?: "sm" | "md" | "lg";

	/**
	 * Whether to show branding
	 */
	showBranding?: boolean;

	/**
	 * Disabled state
	 */
	disabled?: boolean;

	/**
	 * Show sign-up link
	 */
	showSignUpLink?: boolean;

	/**
	 * Show forgot password link
	 */
	showForgotPasswordLink?: boolean;

	/**
	 * Custom footer content
	 */
	footer?: React.ReactNode;

	/**
	 * Custom header content
	 */
	header?: React.ReactNode;

	/**
	 * Modal backdrop blur
	 */
	backdrop?: "opaque" | "blur" | "transparent";

	/**
	 * Modal placement
	 */
	placement?: "auto" | "top" | "center" | "bottom";

	/**
	 * Custom modal header
	 */
	modalHeader?: React.ReactNode;

	/**
	 * Custom modal footer
	 */
	modalFooter?: React.ReactNode;

	/**
	 * Hide modal header
	 */
	hideHeader?: boolean;

	/**
	 * Hide modal footer
	 */
	hideFooter?: boolean;

	/**
	 * Modal scroll behavior
	 */
	scrollBehavior?: "inside" | "outside";

	showOrganizationSelector?: boolean;
}

// ============================================================================
// Sign In Modal Component
// ============================================================================

export function SignInModal({
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
	redirectUrl,
	onSuccess,
	onError,
	title,
	subtitle,
	size = "md",
	showBranding = true,
	disabled = false,
	showSignUpLink = true,
	showForgotPasswordLink = true,
	footer,
	header,
	backdrop = "blur",
	placement = "center",
	modalHeader,
	modalFooter,
	hideHeader = false,
	hideFooter = false,
	scrollBehavior = "inside",
}: SignInModalProps) {
	const { components } = useConfig();

	// Custom component override
	const CustomSignInModal = components.SignInModal;
	if (CustomSignInModal) {
		return (
			<CustomSignInModal
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
					redirectUrl,
					onSuccess,
					onError,
					title,
					subtitle,
					size,
					showBranding,
					disabled,
					showSignUpLink,
					showForgotPasswordLink,
					footer,
					header,
					backdrop,
					placement,
					modalHeader,
					modalFooter,
					hideHeader,
					hideFooter,
					scrollBehavior,
				}}
			/>
		);
	}

	// Handle successful sign-in
	const handleSuccess = useCallback(
		(result: any) => {
			onSuccess?.(result);

			// Auto-close modal on success unless redirecting
			if (!redirectUrl) {
				onClose?.();
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
				return { size: "sm" as const, className: "max-w-sm" };
			case "md":
				return { size: "md" as const, className: "max-w-md" };
			case "lg":
				return { size: "lg" as const, className: "max-w-lg" };
			case "xl":
				return { size: "xl" as const, className: "max-w-xl" };
			case "full":
				return { size: "full" as const, className: "max-w-full" };
			default:
				return { size: "md" as const, className: "max-w-md" };
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
			scrollBehavior={scrollBehavior}
			closeButton={showCloseButton}
			isDismissable={closeOnBackdropClick && !disabled}
			isKeyboardDismissDisabled={!closeOnEscape || disabled}
			className={`${modalClassName}`}
			classNames={{
				wrapper: "z-[9999]",
				backdrop: "z-[9998]",
				base: `${sizeProps.className}`,
			}}
		>
			<>
				{/* Modal Header */}
				{!hideHeader && (
					<ModalHeader className="flex flex-col gap-1 px-6 py-4">
						{modalHeader || (
							<div className="flex items-center justify-between w-full">
								<div>
									{title && (
										<h2 className="text-lg font-semibold text-foreground">
											{title}
										</h2>
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
										className="text-default-400 hover:text-default-600"
										isDisabled={disabled}
									>
										<XMarkIcon className="w-4 h-4" />
									</Button>
								)}
							</div>
						)}
					</ModalHeader>
				)}

				{/* Modal Body */}
				<ModalBody className="px-6 py-4">
					<SignInForm
						methods={methods}
						email={email}
						organizationId={organizationId}
						redirectUrl={redirectUrl}
						onSuccess={handleSuccess}
						onError={onError}
						title={hideHeader ? title : undefined}
						subtitle={hideHeader ? subtitle : undefined}
						size={size}
						showBranding={showBranding}
						disabled={disabled}
						showSignUpLink={showSignUpLink}
						showForgotPasswordLink={showForgotPasswordLink}
						header={header}
						footer={footer}
						variant="minimal"
						className="space-y-4"
					/>
				</ModalBody>

				{/* Modal Footer */}
				{!hideFooter && modalFooter && (
					<ModalFooter className="px-6 py-4">{modalFooter}</ModalFooter>
				)}
			</>
		</Modal>
	);
}

// ============================================================================
// Sign In Modal Hook
// ============================================================================

/**
 * Hook for managing sign-in modal state
 */
export function useSignInModal() {
	const [isOpen, setIsOpen] = React.useState(false);

	const open = useCallback(() => setIsOpen(true), []);
	const close = useCallback(() => setIsOpen(false), []);
	const toggle = useCallback(() => setIsOpen((prev) => !prev), []);

	return {
		isOpen,
		open,
		close,
		toggle,
		setIsOpen,
	};
}

// ============================================================================
// Sign In Modal with Trigger
// ============================================================================

export interface SignInModalWithTriggerProps extends SignInModalProps {
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
}

/**
 * Sign In Modal with built-in trigger button
 */
export function SignInModalWithTrigger({
	trigger,
	triggerProps = {},
	...modalProps
}: SignInModalWithTriggerProps) {
	const { isOpen, open, close } = useSignInModal();

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
			onPress={open}
		>
			{triggerProps.children || "Sign In"}
		</Button>
	);

	// Use custom trigger or default
	const triggerElement = trigger
		? React.cloneElement(trigger, {
				onClick: (e: React.MouseEvent) => {
					trigger.props.onClick?.(e);
					open();
				},
			})
		: defaultTrigger;

	return (
		<>
			{triggerElement}
			<SignInModal {...modalProps} isOpen={isOpen} onClose={close} />
		</>
	);
}

// ============================================================================
// Export
// ============================================================================

export default SignInModal;
