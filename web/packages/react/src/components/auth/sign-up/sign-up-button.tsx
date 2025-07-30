/**
 * @frank-auth/react - Sign Up Button Component
 *
 * Trigger button for sign-up that can work in navigation or modal mode.
 */

"use client";

import { Button } from "@/components/ui";
import {
	ArrowRightIcon,
	SparklesIcon,
	UserIcon,
	UserPlusIcon,
} from "@heroicons/react/24/outline";
import React, { useCallback, useState } from "react";

import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import type { SignUpButtonProps } from "./index";
import { SignUpModal, useSignUpModal } from "./sign-up-modal";

// ============================================================================
// Sign Up Button Component
// ============================================================================

export function SignUpButton({
	children,
	variant = "solid",
	color = "primary",
	size = "md",
	fullWidth = false,
	startContent,
	endContent,
	className = "",
	modalMode = false,
	modalProps = {},
	href = "/auth/sign-up",
	onClick,
	onSuccess,
	onError,
	disabled = false,
	loading = false,
	showAuthenticatedState = true,
	iconOnly = false,
	redirectAfterSignUp,
	autoRedirect = true,
}: SignUpButtonProps) {
	const { isSignedIn, user, isLoading } = useAuth();
	const { components, features } = useConfig();
	const { isOpen, open, close } = useSignUpModal();

	// Custom component override
	const CustomSignUpButton = components.SignUpButton;
	if (CustomSignUpButton) {
		return (
			<CustomSignUpButton
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
					redirectAfterSignUp,
					autoRedirect,
				}}
			/>
		);
	}

	// Check if sign-up is available
	if (!features.signUp) {
		return null;
	}

	// Handle sign-up success
	const handleSuccess = useCallback(
		(result: any) => {
			onSuccess?.(result);

			// Auto-redirect logic
			if (autoRedirect && redirectAfterSignUp) {
				setTimeout(() => {
					window.location.href = redirectAfterSignUp;
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
		[onSuccess, autoRedirect, redirectAfterSignUp],
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

	// Show authenticated state (user already signed up)
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
			<UserPlusIcon className="w-4 h-4" />
		) : (
			<UserPlusIcon className="w-4 h-4" />
		));

	const buttonContent = children || (iconOnly ? null : "Sign Up");

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
				<SignUpModal
					isOpen={isOpen}
					onClose={close}
					onSuccess={handleSuccess}
					onError={onError}
					redirectUrl={redirectAfterSignUp}
					{...modalProps}
				/>
			)}
		</>
	);
}

// ============================================================================
// Sign Up Button Variants
// ============================================================================

/**
 * Primary Sign Up Button
 */
export function PrimarySignUpButton(
	props: Omit<SignUpButtonProps, "variant" | "color">,
) {
	return <SignUpButton {...props} variant="solid" color="primary" />;
}

/**
 * Secondary Sign Up Button
 */
export function SecondarySignUpButton(
	props: Omit<SignUpButtonProps, "variant" | "color">,
) {
	return <SignUpButton {...props} variant="bordered" color="default" />;
}

/**
 * Success Sign Up Button (emphasizes positive action)
 */
export function SuccessSignUpButton(
	props: Omit<SignUpButtonProps, "variant" | "color">,
) {
	return <SignUpButton {...props} variant="solid" color="success" />;
}

/**
 * Ghost Sign Up Button
 */
export function GhostSignUpButton(props: Omit<SignUpButtonProps, "variant">) {
	return <SignUpButton {...props} variant="ghost" />;
}

/**
 * Icon-only Sign Up Button
 */
export function IconSignUpButton(props: Omit<SignUpButtonProps, "iconOnly">) {
	return <SignUpButton {...props} iconOnly />;
}

// ============================================================================
// Modal Sign Up Button
// ============================================================================

/**
 * Sign Up Button that always opens in modal
 */
export function ModalSignUpButton(props: Omit<SignUpButtonProps, "modalMode">) {
	return <SignUpButton {...props} modalMode />;
}

// ============================================================================
// Specialized Sign Up Buttons
// ============================================================================

/**
 * Navigation Sign Up Button (for nav bars)
 */
export function NavSignUpButton({
	className = "",
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="ghost"
			size="sm"
			className={`font-medium ${className}`}
			modalMode
		/>
	);
}

/**
 * Header Sign Up Button (for headers)
 */
export function HeaderSignUpButton({
	className = "",
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="solid"
			color="primary"
			size="sm"
			className={`${className}`}
			modalMode
		/>
	);
}

/**
 * Hero Sign Up Button (for landing pages)
 */
export function HeroSignUpButton({
	size = "lg",
	className = "",
	children,
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="solid"
			color="primary"
			size={size}
			className={`font-semibold ${className}`}
			endContent={<ArrowRightIcon className="w-5 h-5" />}
		>
			{children || "Get Started"}
		</SignUpButton>
	);
}

/**
 * Call-to-Action Sign Up Button (premium feel)
 */
export function CTASignUpButton({
	className = "",
	children,
	startContent,
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="shadow"
			color="secondary"
			size="lg"
			className={`font-semibold shadow-lg hover:shadow-xl transition-shadow ${className}`}
			startContent={startContent || <SparklesIcon className="w-5 h-5" />}
			endContent={<ArrowRightIcon className="w-5 h-5" />}
		>
			{children || "Start Free Trial"}
		</SignUpButton>
	);
}

/**
 * Quick Access Sign Up Button (floating action)
 */
export function QuickSignUpButton({
	className = "",
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="shadow"
			color="primary"
			iconOnly
			className={`fixed bottom-4 right-4 z-50 rounded-full w-12 h-12 shadow-lg ${className}`}
			modalMode
			startContent={<UserPlusIcon className="w-6 h-6" />}
		/>
	);
}

/**
 * Free Sign Up Button (emphasizes no cost)
 */
export function FreeSignUpButton({
	children,
	className = "",
	...props
}: SignUpButtonProps) {
	return (
		<SignUpButton
			{...props}
			variant="solid"
			color="success"
			className={`${className}`}
		>
			{children || "Sign Up Free"}
		</SignUpButton>
	);
}

// ============================================================================
// Organization-specific Sign Up Button
// ============================================================================

export interface OrganizationSignUpButtonProps extends SignUpButtonProps {
	/**
	 * Organization ID
	 */
	organizationId?: string;

	/**
	 * Organization name (for display)
	 */
	organizationName?: string;

	/**
	 * Organization logo
	 */
	organizationLogo?: string;

	/**
	 * Invitation token (for invited sign-ups)
	 */
	invitationToken?: string;
}

export function OrganizationSignUpButton({
	organizationId,
	organizationName,
	organizationLogo,
	invitationToken,
	children,
	startContent,
	modalProps = {},
	...props
}: OrganizationSignUpButtonProps) {
	const content =
		children ||
		(invitationToken
			? `Accept Invitation`
			: organizationName
				? `Join ${organizationName}`
				: "Join Organization");

	const logoContent = organizationLogo ? (
		<img
			src={organizationLogo}
			alt={organizationName}
			className="w-4 h-4 rounded"
		/>
	) : (
		<UserPlusIcon className="w-4 h-4" />
	);

	return (
		<SignUpButton
			{...props}
			startContent={startContent || logoContent}
			modalProps={{
				...modalProps,
				organizationId,
				invitationToken,
				title: organizationName
					? `Join ${organizationName}`
					: "Join Organization",
				showBranding: true,
			}}
		>
			{content}
		</SignUpButton>
	);
}

// ============================================================================
// Multi-step Sign Up Button
// ============================================================================

export interface MultiStepSignUpButtonProps extends SignUpButtonProps {
	/**
	 * Steps to show in the sign-up process
	 */
	steps?: Array<{
		title: string;
		description?: string;
		fields: string[];
	}>;

	/**
	 * Current step (for controlled mode)
	 */
	currentStep?: number;

	/**
	 * Step change callback
	 */
	onStepChange?: (step: number) => void;
}

export function MultiStepSignUpButton({
	steps = [
		{
			title: "Basic Info",
			description: "Your email and password",
			fields: ["email", "password"],
		},
		{
			title: "Personal Details",
			description: "Tell us about yourself",
			fields: ["firstName", "lastName"],
		},
		{
			title: "Verification",
			description: "Verify your email",
			fields: ["verification"],
		},
	],
	currentStep,
	onStepChange,
	modalProps = {},
	...props
}: MultiStepSignUpButtonProps) {
	const [internalStep, setInternalStep] = useState(0);

	const activeStep = currentStep !== undefined ? currentStep : internalStep;

	const handleStepChange = useCallback(
		(step: number) => {
			if (onStepChange) {
				onStepChange(step);
			} else {
				setInternalStep(step);
			}
		},
		[onStepChange],
	);

	return (
		<SignUpButton
			{...props}
			modalMode
			modalProps={{
				...modalProps,
				title: `Step ${activeStep + 1} of ${steps.length}: ${steps[activeStep]?.title}`,
				subtitle: steps[activeStep]?.description,
			}}
		/>
	);
}

// ============================================================================
// Trial Sign Up Button
// ============================================================================

export interface TrialSignUpButtonProps extends SignUpButtonProps {
	/**
	 * Trial duration
	 */
	trialDays?: number;

	/**
	 * Whether trial requires credit card
	 */
	requiresCreditCard?: boolean;
}

export function TrialSignUpButton({
	trialDays = 14,
	requiresCreditCard = false,
	children,
	modalProps = {},
	...props
}: TrialSignUpButtonProps) {
	const trialText = `Start ${trialDays}-Day Free Trial`;
	const subtitle = requiresCreditCard
		? `No charge for ${trialDays} days, cancel anytime`
		: `No credit card required`;

	return (
		<SignUpButton
			{...props}
			color="success"
			modalProps={{
				...modalProps,
				title: `Start Your Free Trial`,
				subtitle,
			}}
		>
			{children || trialText}
		</SignUpButton>
	);
}

// ============================================================================
// Export
// ============================================================================

export default SignUpButton;
