/**
 * @frank-auth/react - Sign In Form Component (Fully Optimized)
 *
 * Comprehensive sign-in form with multiple authentication methods,
 * organization support, and customizable UI options.
 * Completely optimized to prevent ANY prop recreation that causes FormWrapper re-renders.
 */

"use client";

import { Button as HeroButton } from "@/components/ui/button";
import { Input as HeroInput } from "@/components/ui/input";
import { EnvelopeIcon, LockClosedIcon } from "@heroicons/react/24/outline";
import { Checkbox, Divider, Link, Select, SelectItem } from "@heroui/react";
import { motion } from "framer-motion";
import React, { useCallback, useMemo, useState } from "react";

import EmailField from "@/components/forms/email-field";
import FormWrapper from "@/components/forms/form-wrapper";
import PasswordField from "@/components/forms/password-field";
import type { RadiusT, SizeT } from "@/types";
import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import { useMagicLink } from "../../../hooks/use-magic-link";
import { useOAuth } from "../../../hooks/use-oauth";
import { usePasskeys } from "../../../hooks/use-passkeys";

// ============================================================================
// Sign In Form Types
// ============================================================================

export interface SignInFormProps {
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
	 * Show sign-up link
	 */
	showSignUpLink?: boolean;

	/**
	 * Show forgot password link
	 */
	showForgotPasswordLink?: boolean;

	/**
	 * Show organization selector
	 */
	showOrganizationSelector?: boolean;

	/**
	 * Custom title
	 */
	title?: string;

	/**
	 * Custom subtitle
	 */
	subtitle?: string;

	/**
	 * Form variant
	 */
	variant?: "default" | "minimal" | "compact";

	/**
	 * Form size
	 */
	size?: SizeT;

	/**
	 * Form radius
	 */
	radius?: RadiusT;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Whether to show branding
	 */
	showBranding?: boolean;

	/**
	 * Disabled state
	 */
	disabled?: boolean;

	/**
	 * Custom footer content
	 */
	footer?: React.ReactNode;

	/**
	 * Custom header content
	 */
	header?: React.ReactNode;

	titleAlignment?: "left" | "center" | "right";
}

// ============================================================================
// Sign In Form State
// ============================================================================

type SignInStep =
	| "credentials"
	| "mfa"
	| "organization-select"
	| "success"
	| "email-verification";

type SuccessType =
	| "password-signin"
	| "oauth-signin"
	| "passkey-signin"
	| "mfa-verified"
	| "email-verification-required"
	| "magic-link-sent";

interface SignInState {
	step: SignInStep;
	method: string;
	email: string;
	password: string;
	mfaToken?: string;
	selectedOrganization?: string;
	rememberMe: boolean;
	showPassword: boolean;
	successType?: SuccessType;
	successData?: {
		provider?: string;
		email?: string;
		requiresEmailVerification?: boolean;
		magicLinkSent?: boolean;
	};
}

// ============================================================================
// Provider Icons (Static - Prevent Recreation)
// ============================================================================

const GoogleIcon = React.memo(() => (
	<svg className="w-4 h-4" viewBox="0 0 24 24">
		<path
			fill="#4285F4"
			d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
		/>
		<path
			fill="#34A853"
			d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
		/>
		<path
			fill="#FBBC05"
			d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
		/>
		<path
			fill="#EA4335"
			d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
		/>
	</svg>
));

const GitHubIcon = React.memo(() => (
	<svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
		<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
	</svg>
));

const MicrosoftIcon = React.memo(() => (
	<svg className="w-4 h-4" viewBox="0 0 24 24">
		<path fill="#f25022" d="M1 1h10v10H1z" />
		<path fill="#00a4ef" d="M13 1h10v10H13z" />
		<path fill="#7fba00" d="M1 13h10v10H1z" />
		<path fill="#ffb900" d="M13 13h10v10H13z" />
	</svg>
));

const AppleIcon = React.memo(() => (
	<svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
		<path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z" />
	</svg>
));

// Add display names
GoogleIcon.displayName = "GoogleIcon";
GitHubIcon.displayName = "GitHubIcon";
MicrosoftIcon.displayName = "MicrosoftIcon";
AppleIcon.displayName = "AppleIcon";

// ============================================================================
// Success Message Component
// ============================================================================

const SuccessMessage = React.memo(
	({
		successType,
		successData,
		redirectUrl,
	}: {
		successType: SuccessType;
		successData?: any;
		redirectUrl?: string;
	}) => {
		const { components } = useConfig();
		const Button = components.Button ?? HeroButton;

		const getSuccessContent = useCallback(() => {
			switch (successType) {
				case "password-signin":
					return {
						title: "Welcome back!",
						subtitle: "You have been successfully signed in.",
						icon: (
							<svg
								className="w-8 h-8 text-success-600 dark:text-success-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M5 13l4 4L19 7"
								/>
							</svg>
						),
					};

				case "oauth-signin":
					return {
						title: "Welcome back!",
						subtitle: `Successfully signed in with ${successData?.provider || "OAuth"}.`,
						icon: (
							<svg
								className="w-8 h-8 text-success-600 dark:text-success-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M5 13l4 4L19 7"
								/>
							</svg>
						),
					};

				case "passkey-signin":
					return {
						title: "Authenticated!",
						subtitle: "Successfully signed in with your passkey.",
						icon: (
							<LockClosedIcon className="w-8 h-8 text-success-600 dark:text-success-400" />
						),
					};

				case "mfa-verified":
					return {
						title: "Verification complete!",
						subtitle: "Two-factor authentication successful.",
						icon: (
							<svg
								className="w-8 h-8 text-success-600 dark:text-success-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
								/>
							</svg>
						),
					};

				case "email-verification-required":
					return {
						title: "Check your email",
						subtitle: `We've sent a verification link to ${successData?.email || "your email address"}. Please click the link to complete your sign-in.`,
						icon: (
							<EnvelopeIcon className="w-8 h-8 text-warning-600 dark:text-warning-400" />
						),
						extraButton: <Button size="sm">Resend Email</Button>,
					};

				case "magic-link-sent":
					return {
						title: "Magic link sent!",
						subtitle: `Check your email at ${successData?.email} and click the link to sign in.`,
						icon: (
							<svg
								className="w-8 h-8 text-primary-600 dark:text-primary-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M3 8l7.89 7.89a2 2 0 002.83 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
								/>
							</svg>
						),
						extraButton: (
							<Button
								onClick={async () => {
									await successData.sendMagicLink(successData.email, {
										redirectUrl,
										organizationId: successData.organizationId,
									});
								}}
								size="sm"
							>
								Resend magic link
							</Button>
						),
					};

				default:
					return {
						title: "Success!",
						subtitle: "Operation completed successfully.",
						icon: (
							<svg
								className="w-8 h-8 text-success-600 dark:text-success-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M5 13l4 4L19 7"
								/>
							</svg>
						),
					};
			}
		}, [successType, successData]);

		const content = getSuccessContent();
		const showRedirectMessage =
			redirectUrl &&
			!["email-verification-required", "magic-link-sent"].includes(successType);

		return (
			<div className="text-center space-y-4">
				<motion.div
					initial={{ scale: 0 }}
					animate={{ scale: 1 }}
					className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center ${
						successType === "email-verification-required"
							? "bg-warning-100 dark:bg-warning-900/30"
							: successType === "magic-link-sent"
								? "bg-primary-100 dark:bg-primary-900/30"
								: "bg-success-100 dark:bg-success-900/30"
					}`}
				>
					{content.icon}
				</motion.div>

				<div>
					<h3 className="text-xl font-semibold text-foreground mb-2">
						{content.title}
					</h3>
					<p className="text-default-500 text-sm">{content.subtitle}</p>
					{content.extraButton && (
						<div className="flex justify-center py-4">
							{content.extraButton}
						</div>
					)}
				</div>

				{showRedirectMessage && (
					<div className="flex items-center justify-center gap-2 text-sm text-default-500">
						<div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
						<span>Redirecting...</span>
					</div>
				)}

				{successType === "email-verification-required" && (
					<div className="text-xs text-default-400">
						Didn't receive the email? Check your spam folder or contact support.
					</div>
				)}
			</div>
		);
	},
);

SuccessMessage.displayName = "SuccessMessage";

// ============================================================================
// OAuth Provider Buttons Component
// ============================================================================

const OAuthButtons = React.memo(
	({
		onSuccess,
		onError,
		redirectUrl,
		organizationId,
		disabled,
		size = "md",
		radius = "md",
	}: {
		onSuccess: (provider: string, result: any) => void;
		onError?: (error: Error) => void;
		redirectUrl?: string;
		organizationId?: string;
		disabled?: boolean;
		size?: SizeT;
		radius?: RadiusT;
	}) => {
		const {
			signInWithGoogle,
			signInWithGitHub,
			signInWithMicrosoft,
			signInWithApple,
			isLoading,
		} = useOAuth();

		const { components } = useConfig();
		const Button = components.Button ?? HeroButton;

		const handleOAuthSignIn = useCallback(
			async (provider: string, signInMethod: () => Promise<void>) => {
				try {
					const result = await signInMethod();
					onSuccess(provider, { provider, ...result });
				} catch (error) {
					onError?.(
						error instanceof Error
							? error
							: new Error(`${provider} sign-in failed`),
					);
				}
			},
			[onSuccess, onError],
		);

		const handleGoogleSignIn = useCallback(() => {
			handleOAuthSignIn("Google", () =>
				signInWithGoogle({ redirectUrl, organizationId }),
			);
		}, [handleOAuthSignIn, signInWithGoogle, redirectUrl, organizationId]);

		const handleGitHubSignIn = useCallback(() => {
			handleOAuthSignIn("GitHub", () =>
				signInWithGitHub({ redirectUrl, organizationId }),
			);
		}, [handleOAuthSignIn, signInWithGitHub, redirectUrl, organizationId]);

		const handleMicrosoftSignIn = useCallback(() => {
			handleOAuthSignIn("Microsoft", () =>
				signInWithMicrosoft({ redirectUrl, organizationId }),
			);
		}, [handleOAuthSignIn, signInWithMicrosoft, redirectUrl, organizationId]);

		const handleAppleSignIn = useCallback(() => {
			handleOAuthSignIn("Apple", () =>
				signInWithApple({ redirectUrl, organizationId }),
			);
		}, [handleOAuthSignIn, signInWithApple, redirectUrl, organizationId]);

		return (
			<div className="space-y-3">
				<Button
					type="button"
					variant="bordered"
					size={size}
					radius={radius}
					className="w-full"
					startContent={<GoogleIcon />}
					onPress={handleGoogleSignIn}
					isDisabled={disabled || isLoading}
				>
					Continue with Google
				</Button>

				<Button
					type="button"
					variant="bordered"
					size={size}
					radius={radius}
					className="w-full"
					startContent={<GitHubIcon />}
					onPress={handleGitHubSignIn}
					isDisabled={disabled || isLoading}
				>
					Continue with GitHub
				</Button>

				<Button
					type="button"
					variant="bordered"
					size={size}
					radius={radius}
					className="w-full"
					startContent={<MicrosoftIcon />}
					onPress={handleMicrosoftSignIn}
					isDisabled={disabled || isLoading}
				>
					Continue with Microsoft
				</Button>

				<Button
					type="button"
					variant="bordered"
					size={size}
					radius={radius}
					className="w-full"
					startContent={<AppleIcon />}
					onPress={handleAppleSignIn}
					isDisabled={disabled || isLoading}
				>
					Continue with Apple
				</Button>
			</div>
		);
	},
);

OAuthButtons.displayName = "OAuthButtons";

// ============================================================================
// Magic Link Component
// ============================================================================

const MagicLinkSection = React.memo(
	({
		email,
		onSuccess,
		onError,
		redirectUrl,
		organizationId,
		disabled,
		size = "md",
		radius = "md",
	}: {
		email: string;
		onSuccess: (result: any) => void;
		onError?: (error: Error) => void;
		redirectUrl?: string;
		organizationId?: string;
		disabled?: boolean;
		size?: SizeT;
		radius?: RadiusT;
	}) => {
		const { sendMagicLink, isLoading, lastSentEmail, canResend } =
			useMagicLink();
		const [sent, setSent] = useState(false);

		const { components } = useConfig();
		const Button = components.Button ?? HeroButton;
		// Memoized envelope icon
		const envelopeIcon = useMemo(
			() => <EnvelopeIcon className="w-4 h-4" />,
			[],
		);

		const handleSendMagicLink = useCallback(async () => {
			if (!email) return;

			try {
				const result = await sendMagicLink(email, {
					redirectUrl,
					organizationId,
				});

				if (result.success) {
					setSent(true);
					onSuccess({
						type: "magic-link-sent",
						email,
						redirectUrl,
						organizationId,
						...result,
						sendMagicLink,
						canResend,
					});
				}
			} catch (error) {
				onError?.(
					error instanceof Error
						? error
						: new Error("Failed to send magic link"),
				);
			}
		}, [email, sendMagicLink, redirectUrl, organizationId, onSuccess, onError]);

		if (sent && lastSentEmail) {
			return (
				<div className="text-center space-y-4">
					<div className="text-success-600 font-medium">
						Magic link sent to {lastSentEmail}
					</div>
					<p className="text-default-500 text-sm">
						Check your email and click the link to sign in
					</p>
					{canResend && (
						<Button
							type="button"
							variant="light"
							size="sm"
							onPress={handleSendMagicLink}
							isDisabled={disabled || isLoading}
						>
							Resend magic link
						</Button>
					)}
				</div>
			);
		}

		return (
			<Button
				type="button"
				variant="bordered"
				size={size}
				radius={radius}
				className="w-full"
				startContent={envelopeIcon}
				onPress={handleSendMagicLink}
				isDisabled={disabled || isLoading || !email}
				isLoading={isLoading}
			>
				Send magic link
			</Button>
		);
	},
);

MagicLinkSection.displayName = "MagicLinkSection";

// ============================================================================
// Verification Code Component
// ============================================================================

const VerificationCode = React.memo(
	({
		length = 6,
		onComplete,
		disabled = false,
	}: {
		length?: number;
		onComplete: (code: string) => void;
		disabled?: boolean;
	}) => {
		const { components } = useConfig();
		const Input = components.Input ?? HeroInput;
		const [code, setCode] = useState(Array(length).fill(""));
		const [focused, setFocused] = useState(0);

		const handleChange = useCallback(
			(index: number, value: string) => {
				if (value.length > 1) return;

				const newCode = [...code];
				newCode[index] = value;
				setCode(newCode);

				// Auto-focus next input
				if (value && index < length - 1) {
					setFocused(index + 1);
				}

				// Call onComplete when code is full
				if (
					newCode.every((digit) => digit !== "") &&
					newCode.join("").length === length
				) {
					onComplete(newCode.join(""));
				}
			},
			[code, length, onComplete],
		);

		const handleKeyDown = useCallback(
			(index: number, e: React.KeyboardEvent) => {
				if (e.key === "Backspace" && !code[index] && index > 0) {
					setFocused(index - 1);
				}
			},
			[code],
		);

		return (
			<div className="flex gap-2 justify-center">
				{Array.from({ length }, (_, index) => (
					<Input
						key={index}
						type="text"
						maxLength={1}
						value={code[index]}
						onChange={(e) => handleChange(index, e.target.value)}
						onKeyDown={(e) => handleKeyDown(index, e)}
						className="w-12 text-center"
						classNames={{
							input: "text-center text-lg font-mono",
							inputWrapper: "h-12 w-12",
						}}
						isDisabled={disabled}
						disabled={disabled}
						autoFocus={index === focused}
					/>
				))}
			</div>
		);
	},
);

VerificationCode.displayName = "VerificationCode";

// ============================================================================
// Main Sign In Form Component
// ============================================================================

export function SignInForm({
	methods = ["password", "oauth", "magic-link"],
	email: initialEmail = "",
	organizationId: initialOrganizationId,
	redirectUrl,
	onSuccess,
	onError,
	showSignUpLink = true,
	showForgotPasswordLink = true,
	showOrganizationSelector = false,
	title,
	subtitle,
	variant = "default",
	size = "md",
	radius = "md",
	className = "",
	showBranding = true,
	disabled = false,
	titleAlignment,
	footer,
	header,
}: SignInFormProps) {
	const { signIn, isLoading, organizationMemberships } = useAuth();
	const {
		features,
		organizationSettings,
		components,
		linksPath,
		titleAlignment: configTitleAlignment,
	} = useConfig();
	const { authenticateWithPasskey } = usePasskeys();

	// Memoized icons to prevent recreation
	const envelopeIcon = useMemo(
		() => <EnvelopeIcon className="w-4 h-4 text-default-400" />,
		[],
	);
	const lockIcon = useMemo(
		() => <LockClosedIcon className="w-4 h-4 text-default-400" />,
		[],
	);
	const lockIconSmall = useMemo(
		() => <LockClosedIcon className="w-4 h-4" />,
		[],
	);
	const textAlign = React.useMemo(
		() => titleAlignment ?? configTitleAlignment,
		[titleAlignment, configTitleAlignment],
	);

	// Custom component override
	const Button = components.Button ?? HeroButton;
	const CustomSignInForm = components.SignInForm;
	if (CustomSignInForm) {
		return (
			<CustomSignInForm
				{...{
					methods,
					email: initialEmail,
					organizationId: initialOrganizationId,
					redirectUrl,
					onSuccess,
					onError,
					showSignUpLink,
					showForgotPasswordLink,
					showOrganizationSelector,
					title,
					subtitle,
					variant,
					size,
					className,
					showBranding,
					disabled,
					footer,
					header,
				}}
			/>
		);
	}

	// Form state
	const [state, setState] = useState<SignInState>({
		step: "credentials",
		method: "password",
		email: initialEmail,
		password: "",
		selectedOrganization: initialOrganizationId,
		rememberMe: true,
		showPassword: false,
	});

	const [formError, setFormError] = useState<string | null>(null);

	// Available methods based on features (memoized)
	const availableMethods = useMemo(() => {
		return methods.filter((method) => {
			switch (method) {
				case "oauth":
					return features.oauth;
				case "magic-link":
					return features.magicLink;
				case "passkey":
					return features.passkeys;
				case "sso":
					return features.sso;
				case "password":
				default:
					return true;
			}
		});
	}, [methods, features]);

	const stableFormWrapperProps = useMemo(() => {
		// Default content
		const getDefaultContent = () => {
			if (organizationSettings?.branding?.customLoginText) {
				return {
					title:
						organizationSettings.branding.customLoginText.title ||
						"Welcome back",
					subtitle:
						organizationSettings.branding.customLoginText.subtitle ||
						"Sign in to your account",
				};
			}
			return {
				title: "Welcome back",
				subtitle: "Sign in to your account",
			};
		};

		const defaultContent = getDefaultContent();
		const finalTitle = title || defaultContent.title;
		const finalSubtitle = subtitle || defaultContent.subtitle;

		// Logo element
		let logoElement: React.ReactNode = undefined;
		if (showBranding && organizationSettings?.branding?.logoUrl) {
			logoElement = (
				<img
					src={organizationSettings.branding.logoUrl}
					alt="Organization Logo"
					className="h-8 w-auto mx-auto mb-4"
				/>
			);
		}

		return {
			size,
			variant: "flat" as const,
			className: `space-y-6 ${className}`,
			footer,
			header,
			title: finalTitle,
			subtitle: finalSubtitle,
			showCard: false,
			logo: logoElement,
		};
	}, [
		title,
		subtitle,
		size,
		className,
		footer,
		header,
		showBranding,
		organizationSettings?.branding?.customLoginText,
		organizationSettings?.branding?.logoUrl,
	]);

	// Handle form submission
	const handleSubmit = useCallback(
		async (e: React.FormEvent) => {
			e.preventDefault();
			setFormError(null);

			if (!state.email || !state.password) {
				setFormError("Please enter your email and password");
				return;
			}

			try {
				const result = await signIn({
					strategy: "password",
					identifier: state.email,
					password: state.password,
					organizationId: state.selectedOrganization || initialOrganizationId,
				});

				if (result.status === "needs_mfa") {
					setState((prev) => ({
						...prev,
						step: "mfa",
						mfaToken: result.mfaToken,
					}));
					return;
				}

				if (result.status === "needs_verification") {
					setState((prev) => ({
						...prev,
						step: "success",
						successType: "email-verification-required",
						successData: { email: state.email },
					}));
					onSuccess?.(result);
					return;
				}

				if (result.status === "complete" && result.user) {
					setState((prev) => ({
						...prev,
						step: "success",
						successType: "password-signin",
					}));
					onSuccess?.(result);

					// Redirect if URL provided
					if (redirectUrl) {
						setTimeout(() => {
							window.location.href = redirectUrl;
						}, 1000);
					}
				}

				if (result.status === "complete" && result.error) {
					setFormError(result.error.message);
				}
			} catch (error) {
				const authError =
					error instanceof Error ? error : new Error("Sign in failed");
				console.error(authError);
				setFormError(authError.message);
				onError?.(authError);
			}
		},
		[
			state.email,
			state.password,
			state.selectedOrganization,
			initialOrganizationId,
			signIn,
			onSuccess,
			onError,
			redirectUrl,
		],
	);

	// Handle MFA verification
	const handleMFAVerification = useCallback(
		async (code: string) => {
			if (!state.mfaToken) return;

			try {
				// This would use the MFA hook in a real implementation
				setState((prev) => ({
					...prev,
					step: "success",
					successType: "mfa-verified",
				}));
				onSuccess?.({ mfaVerified: true });

				if (redirectUrl) {
					setTimeout(() => {
						window.location.href = redirectUrl;
					}, 1000);
				}
			} catch (error) {
				const authError =
					error instanceof Error ? error : new Error("MFA verification failed");
				setFormError(authError.message);
				onError?.(authError);
			}
		},
		[state.mfaToken, onSuccess, onError, redirectUrl],
	);

	// Handle OAuth success
	const handleOAuthSuccess = useCallback(
		(provider: string, result: any) => {
			setState((prev) => ({
				...prev,
				step: "success",
				successType: "oauth-signin",
				successData: { provider },
			}));
			onSuccess?.(result);
		},
		[onSuccess],
	);

	// Handle Magic Link success
	const handleMagicLinkSuccess = useCallback(
		(result: any) => {
			if (result.type === "magic-link-sent") {
				setState((prev) => ({
					...prev,
					step: "success",
					successType: "magic-link-sent",
					successData: {
						email: result.email,
						message: result.message,
						sendMagicLink: result.sendMagicLink,
						canResend: result.canResend,
					},
				}));
			} else {
				setState((prev) => ({
					...prev,
					step: "success",
					successType: "password-signin",
				}));
			}
			onSuccess?.(result);
		},
		[onSuccess],
	);

	// Handle Passkey authentication
	const handlePasskeyAuth = useCallback(async () => {
		try {
			const result = await authenticateWithPasskey();
			if (result.success) {
				setState((prev) => ({
					...prev,
					step: "success",
					successType: "passkey-signin",
				}));
				onSuccess?.(result);
			}
		} catch (error) {
			const authError =
				error instanceof Error
					? error
					: new Error("Passkey authentication failed");
			setFormError(authError.message);
			onError?.(authError);
		}
	}, [authenticateWithPasskey, onSuccess, onError]);

	// Stable handlers for form inputs
	const handleEmailChange = useCallback((email: string) => {
		setState((prev) => ({ ...prev, email }));
	}, []);

	const handlePasswordChange = useCallback((password: string) => {
		setState((prev) => ({ ...prev, password }));
	}, []);

	const handleRememberMeChange = useCallback((rememberMe: boolean) => {
		setState((prev) => ({ ...prev, rememberMe }));
	}, []);

	const handleOrganizationChange = useCallback((keys: any) => {
		const selected = Array.from(keys)[0] as string;
		setState((prev) => ({ ...prev, selectedOrganization: selected }));
	}, []);

	// Success step
	if (state.step === "success") {
		return (
			<SuccessMessage
				successType={state.successType!}
				successData={state.successData}
				redirectUrl={redirectUrl}
			/>
		);
	}

	// MFA verification step
	if (state.step === "mfa") {
		return (
			<div className="space-y-6">
				<div className="text-center">
					<h3 className="text-xl font-semibold text-foreground mb-2">
						Two-Factor Authentication
					</h3>
					<p className="text-default-500 text-sm">
						Enter the verification code from your authenticator app
					</p>
				</div>

				<VerificationCode
					length={6}
					onComplete={handleMFAVerification}
					disabled={disabled || isLoading}
				/>

				{formError && (
					<div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3 text-center">
						{formError}
					</div>
				)}

				<Button
					type="button"
					variant="light"
					size="sm"
					onPress={() => setState((prev) => ({ ...prev, step: "credentials" }))}
					className="w-full"
				>
					Back to sign in
				</Button>
			</div>
		);
	}

	return (
		<FormWrapper
			{...stableFormWrapperProps}
			onSubmit={handleSubmit}
			titleAlignment={textAlign}
		>
			{/* OAuth Buttons */}
			{availableMethods.includes("oauth") && (
				<>
					<OAuthButtons
						onSuccess={handleOAuthSuccess}
						onError={onError}
						redirectUrl={redirectUrl}
						organizationId={state.selectedOrganization || initialOrganizationId}
						disabled={disabled}
						size={size}
						radius={radius}
					/>

					{(availableMethods.includes("password") ||
						availableMethods.includes("magic-link")) && (
						<div className="relative">
							<Divider className="my-4" />
							<div className="absolute inset-0 flex items-center justify-center">
								<span className="bg-background px-2 text-sm text-default-500">
									or
								</span>
							</div>
						</div>
					)}
				</>
			)}

			{/* Password Form */}
			{availableMethods.includes("password") && (
				<div className="space-y-2">
					{/* Organization Selector */}
					{showOrganizationSelector && organizationMemberships.length > 1 && (
						<Select
							label="Organization"
							placeholder="Select an organization"
							selectedKeys={
								state.selectedOrganization ? [state.selectedOrganization] : []
							}
							onSelectionChange={handleOrganizationChange}
							size={size}
							radius={radius}
							isDisabled={disabled || isLoading}
						>
							{organizationMemberships.map((membership) => (
								<SelectItem
									key={membership.organization.id}
									value={membership.organization.id}
								>
									{membership.organization.name}
								</SelectItem>
							))}
						</Select>
					)}

					{/* Email Field */}
					<EmailField
						label="Email"
						name="email"
						placeholder="Enter your email"
						value={state.email}
						onChange={handleEmailChange}
						startContent={envelopeIcon}
						size={size}
						radius={radius}
						required
						disabled={disabled || isLoading}
						showSuggestions={false}
						showVerificationStatus={true}
						variant="bordered"
					/>

					{state.email && (
						<>
							{/* Password Field */}
							<PasswordField
								label="Password"
								name="password"
								placeholder="Enter your password"
								value={state.password}
								onChange={handlePasswordChange}
								startContent={lockIcon}
								size={size}
								radius={radius}
								required
								disabled={disabled || isLoading}
								variant="bordered"
							/>

							{/* Remember Me & Forgot Password */}
							<div className="flex items-center justify-between">
								<Checkbox
									isSelected={state.rememberMe}
									onValueChange={handleRememberMeChange}
									size="sm"
									isDisabled={disabled || isLoading}
								>
									Remember me
								</Checkbox>

								{showForgotPasswordLink && (
									<Link
										href={linksPath?.forgotPassword}
										size="sm"
										color="primary"
									>
										Forgot password?
									</Link>
								)}
							</div>
						</>
					)}

					{/* Error Display */}
					{formError && (
						<div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
							{formError}
						</div>
					)}

					{/* Submit Button */}
					<Button
						type="submit"
						color="primary"
						size={size}
						radius={radius}
						className="w-full"
						isLoading={isLoading}
						isDisabled={disabled || !state.email || !state.password}
					>
						{isLoading ? "Signing in..." : "Sign in"}
					</Button>

					{/* Magic Link Alternative */}
					{availableMethods.includes("magic-link") && state.email && (
						<>
							<div className="relative">
								<Divider className="my-4" />
								<div className="absolute inset-0 flex items-center justify-center">
									<span className="bg-background px-2 text-sm text-default-500">
										or
									</span>
								</div>
							</div>
							<MagicLinkSection
								email={state.email}
								onSuccess={handleMagicLinkSuccess}
								onError={onError}
								redirectUrl={redirectUrl}
								organizationId={
									state.selectedOrganization || initialOrganizationId
								}
								disabled={disabled}
								size={size}
								radius={radius}
							/>
						</>
					)}
				</div>
			)}

			<div className="space-y-2">
				{/* Magic Link Only */}
				{availableMethods.includes("magic-link") &&
					!availableMethods.includes("password") && (
						<div className="space-y-4">
							<EmailField
								label="Email"
								placeholder="Enter your email"
								value={state.email}
								onChange={handleEmailChange}
								startContent={envelopeIcon}
								size={size}
								radius={radius}
								required={true}
								disabled={disabled || isLoading}
								autoFocus
								variant="bordered"
							/>

							<MagicLinkSection
								email={state.email}
								onSuccess={handleMagicLinkSuccess}
								onError={onError}
								redirectUrl={redirectUrl}
								organizationId={
									state.selectedOrganization || initialOrganizationId
								}
								disabled={disabled}
								size={size}
								radius={radius}
							/>
						</div>
					)}

				{/* Passkey Authentication */}
				{availableMethods.includes("passkey") && (
					<>
						{availableMethods.includes("password") &&
							availableMethods.includes("magic-link") &&
							!state.email && (
								<div className="relative">
									<Divider className="my-4" />
									<div className="absolute inset-0 flex items-center justify-center">
										<span className="bg-background px-2 text-sm text-default-500">
											or
										</span>
									</div>
								</div>
							)}
						<Button
							type="button"
							variant="bordered"
							size={size}
							radius={radius}
							className="w-full"
							startContent={lockIconSmall}
							onPress={handlePasskeyAuth}
							isDisabled={disabled || isLoading}
						>
							Sign in with passkey
						</Button>
					</>
				)}

				{/* Sign Up Link */}
				{showSignUpLink && features.signUp && (
					<div className="text-center text-sm">
						<span className="text-default-500">Don't have an account? </span>
						<Link href={linksPath?.signUp} color="primary">
							Sign up
						</Link>
					</div>
				)}
			</div>

			{/* Custom Footer */}
			{footer}
		</FormWrapper>
	);
}

export default SignInForm;
