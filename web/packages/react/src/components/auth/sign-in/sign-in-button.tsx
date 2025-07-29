/**
 * @frank-auth/react - Sign In Button Component
 *
 * Trigger button for sign-in that can work in navigation or modal mode.
 */

"use client";

import { Button } from "@/components/ui/button";
import {
	ArrowRightOnRectangleIcon,
	LockClosedIcon,
	UserIcon,
} from "@heroicons/react/24/outline";
import type React from "react";
import { useCallback } from "react";

import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import { SignInModal, useSignInModal } from "./sign-in-modal";

// ============================================================================
// Sign In Button Types
// ============================================================================

export interface SignInButtonProps {
	/**
	 * Button text
	 */
	children?: React.ReactNode;

	/**
	 * Button variant
	 */
	variant?:
		| "bordered"
		| "light"
		| "ghost"
		| "default"
		| "primary"
		| "secondary"
		| "link"
		| "destructive"
		| "outline"
		| "tertiary"
		| "quaternary"
		| null
		| undefined;

	/**
	 * Button color
	 */
	color?:
		| "default"
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger";

	/**
	 * Button size
	 */
	size?: "sm" | "md" | "lg";

	/**
	 * Full width button
	 */
	fullWidth?: boolean;

	/**
	 * Button icon
	 */
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Modal mode - opens sign-in in modal instead of navigation
	 */
	modalMode?: boolean;

	/**
	 * Props to pass to the sign-in modal
	 */
	modalProps?: {
		methods?: ("password" | "oauth" | "magic-link" | "passkey" | "sso")[];
		email?: string;
		organizationId?: string;
		redirectUrl?: string;
		title?: string;
		subtitle?: string;
		size?: "sm" | "md" | "lg";
		showBranding?: boolean;
		modalSize?: "sm" | "md" | "lg" | "xl" | "full";
		backdrop?: "opaque" | "blur" | "transparent";
		placement?: "auto" | "top" | "center" | "bottom";
	};

	/**
	 * Navigation URL (when not in modal mode)
	 */
	href?: string;

	/**
	 * Custom onClick handler
	 */
	onClick?: () => void;

	/**
	 * Success callback
	 */
	onSuccess?: (result: any) => void;

	/**
	 * Error callback
	 */
	onError?: (error: Error) => void;

	/**
	 * Disabled state
	 */
	disabled?: boolean;

	/**
	 * Loading state
	 */
	loading?: boolean;

	/**
	 * Show different states based on auth status
	 */
	showAuthenticatedState?: boolean;

	/**
	 * Icon mode - show only icon
	 */
	iconOnly?: boolean;

	/**
	 * Redirect after sign-in
	 */
	redirectAfterSignIn?: string;

	/**
	 * Auto-redirect based on user type
	 */
	autoRedirect?: boolean;
}

// ============================================================================
// Sign In Button Component
// ============================================================================

export function SignInButton({
	children,
	variant = "primary",
	color,
	size = "md",
	fullWidth = false,
	startContent,
	endContent,
	className = "",
	modalMode = false,
	modalProps = {},
	href = "/auth/sign-in",
	onClick,
	onSuccess,
	onError,
	disabled = false,
	loading = false,
	showAuthenticatedState = true,
	iconOnly = false,
	redirectAfterSignIn,
	autoRedirect = true,
}: SignInButtonProps) {
	const { isSignedIn, user, isLoading } = useAuth();
	const { components } = useConfig();
	const { isOpen, open, close } = useSignInModal();

	// Custom component override
	const CustomSignInButton = components.SignInButton;
	if (CustomSignInButton) {
		return (
			<CustomSignInButton
				{...{
					children,
					variant,
					color,
					size,
					fullWidth,
					startContent,
					endContent,
					className,
					modalMode,
					modalProps,
					href,
					onClick,
					onSuccess,
					onError,
					disabled,
					loading,
					showAuthenticatedState,
					iconOnly,
					redirectAfterSignIn,
					autoRedirect,
				}}
			/>
		);
	}

	// Handle sign-in success
	const handleSuccess = useCallback(
		(result: any) => {
			onSuccess?.(result);

			// Auto-redirect logic
			if (autoRedirect && redirectAfterSignIn) {
				setTimeout(() => {
					window.location.href = redirectAfterSignIn;
				}, 1000);
			} else if (autoRedirect && result.user) {
				// Default redirects based on user type
				const userType = result.user.userType || "external";
				const defaultRedirects = {
					internal: "/admin/dashboard",
					external: "/dashboard",
					end_user: "/app",
				};

				const redirectUrl =
					defaultRedirects[userType as keyof typeof defaultRedirects] ||
					"/dashboard";
				setTimeout(() => {
					window.location.href = redirectUrl;
				}, 1000);
			}
		},
		[onSuccess, autoRedirect, redirectAfterSignIn],
	);

	// Handle button click
	const handleClick = useCallback(() => {
		if (disabled || loading || isLoading) return;

		// Custom onClick handler
		if (onClick) {
			onClick();
			return;
		}

		// Modal mode
		if (modalMode) {
			open();
			return;
		}

		// Navigation mode
		if (href) {
			window.location.href = href;
		}
	}, [disabled, loading, isLoading, onClick, modalMode, open, href]);

	// Show authenticated state
	if (showAuthenticatedState && isSignedIn && user) {
		return (
			<Button
				variant="light"
				size={size}
				className={`${className} text-success-600`}
				startContent={<UserIcon className="w-4 h-4" />}
				isDisabled
			>
				{iconOnly
					? null
					: `Welcome, ${user.firstName || user.primaryEmailAddress || "User"}`}
			</Button>
		);
	}

	// Default content
	const defaultStartContent =
		startContent ||
		(iconOnly ? (
			<ArrowRightOnRectangleIcon className="w-4 h-4" />
		) : (
			<ArrowRightOnRectangleIcon className="w-4 h-4" />
		));

	const buttonContent = children || (iconOnly ? null : "Sign In");

	return (
		<>
			<Button
				variant={variant}
				color={color}
				size={size}
				fullWidth={fullWidth}
				startContent={defaultStartContent}
				endContent={endContent}
				className={className}
				onPress={handleClick}
				isDisabled={disabled || isLoading}
				isLoading={loading || isLoading}
				isIconOnly={iconOnly}
			>
				{buttonContent}
			</Button>

			{/* Modal */}
			{modalMode && (
				<SignInModal
					isOpen={isOpen}
					onClose={close}
					onSuccess={handleSuccess}
					onError={onError}
					redirectUrl={redirectAfterSignIn}
					{...modalProps}
				/>
			)}
		</>
	);
}

// ============================================================================
// Sign In Button Variants
// ============================================================================

/**
 * Primary Sign In Button
 */
export function PrimarySignInButton(
	props: Omit<SignInButtonProps, "variant" | "color">,
) {
	return <SignInButton {...props} variant="solid" color="primary" />;
}

/**
 * Secondary Sign In Button
 */
export function SecondarySignInButton(
	props: Omit<SignInButtonProps, "variant" | "color">,
) {
	return <SignInButton {...props} variant="bordered" color="default" />;
}

/**
 * Ghost Sign In Button
 */
export function GhostSignInButton(props: Omit<SignInButtonProps, "variant">) {
	return <SignInButton {...props} variant="ghost" />;
}

/**
 * Icon-only Sign In Button
 */
export function IconSignInButton(props: Omit<SignInButtonProps, "iconOnly">) {
	return <SignInButton {...props} iconOnly />;
}

// ============================================================================
// Modal Sign In Button
// ============================================================================

/**
 * Sign In Button that always opens in modal
 */
export function ModalSignInButton(props: Omit<SignInButtonProps, "modalMode">) {
	return <SignInButton {...props} modalMode />;
}

// ============================================================================
// Specialized Sign In Buttons
// ============================================================================

/**
 * Navigation Sign In Button (for nav bars)
 */
export function NavSignInButton({
	className = "",
	...props
}: SignInButtonProps) {
	return (
		<SignInButton
			{...props}
			variant="ghost"
			size="sm"
			className={`font-medium ${className}`}
			modalMode
		/>
	);
}

/**
 * Header Sign In Button (for headers)
 */
export function HeaderSignInButton({
	className = "",
	...props
}: SignInButtonProps) {
	return (
		<SignInButton
			{...props}
			variant="bordered"
			size="sm"
			className={`border-default-200 ${className}`}
			modalMode
		/>
	);
}

/**
 * Hero Sign In Button (for landing pages)
 */
export function HeroSignInButton({
	size = "lg",
	className = "",
	...props
}: SignInButtonProps) {
	return (
		<SignInButton
			{...props}
			variant="solid"
			color="primary"
			size={size}
			className={`font-semibold ${className}`}
			endContent={<ArrowRightOnRectangleIcon className="w-5 h-5" />}
		/>
	);
}

/**
 * Quick Access Sign In Button (floating action)
 */
export function QuickSignInButton({
	className = "",
	...props
}: SignInButtonProps) {
	return (
		<SignInButton
			{...props}
			variant="shadow"
			color="secondary"
			iconOnly
			className={`fixed bottom-4 right-4 z-50 rounded-full w-12 h-12 shadow-lg ${className}`}
			modalMode
			startContent={<UserIcon className="w-6 h-6" />}
		/>
	);
}

// ============================================================================
// Secure Sign In Button (with extra visual cues)
// ============================================================================

export function SecureSignInButton({
	children,
	startContent,
	className = "",
	...props
}: SignInButtonProps) {
	return (
		<SignInButton
			{...props}
			startContent={startContent || <LockClosedIcon className="w-4 h-4" />}
			className={`border-success-200 text-success-700 hover:bg-success-50 ${className}`}
			variant="bordered"
		>
			{children || "Secure Sign In"}
		</SignInButton>
	);
}

// ============================================================================
// Organization-specific Sign In Button
// ============================================================================

export interface OrganizationSignInButtonProps extends SignInButtonProps {
	/**
	 * Organization ID
	 */
	organizationId: string;

	/**
	 * Organization name (for display)
	 */
	organizationName?: string;

	/**
	 * Organization logo
	 */
	organizationLogo?: string;
}

export function OrganizationSignInButton({
	organizationId,
	organizationName,
	organizationLogo,
	children,
	startContent,
	modalProps = {},
	...props
}: OrganizationSignInButtonProps) {
	const content =
		children ||
		(organizationName
			? `Sign in to ${organizationName}`
			: "Sign in to Organization");

	const logoContent = organizationLogo ? (
		<img
			src={organizationLogo}
			alt={organizationName}
			className="w-4 h-4 rounded"
		/>
	) : (
		<UserIcon className="w-4 h-4" />
	);

	return (
		<SignInButton
			{...props}
			startContent={startContent || logoContent}
			modalProps={{
				...modalProps,
				organizationId,
				title: organizationName ? `Welcome to ${organizationName}` : "Welcome",
				showBranding: true,
			}}
		>
			{content}
		</SignInButton>
	);
}

// ============================================================================
// Export
// ============================================================================

export default SignInButton;
