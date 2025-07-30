/**
 * @frank-auth/react - Sign Up Card Component
 *
 * Card wrapper for sign-up form with customizable styling and layout.
 */

"use client";

import {
	Card,
	CardBody,
	CardFooter,
	CardHeader,
	Divider,
} from "@/components/ui";
import { motion } from "framer-motion";
import React from "react";

import { useConfig } from "../../../hooks/use-config";
import { useTheme } from "../../../hooks/use-theme";
import type { SignUpCardProps } from "./index";
import { SignUpForm } from "./sign-up-form";

// ============================================================================
// Sign Up Card Component
// ============================================================================

export function SignUpCard({
	variant = "shadow",
	className = "",
	padding = "lg",
	radius = "lg",
	shadow = "md",
	isBlurred = false,
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
	footer,
	header,
	maxWidth = 450,
	centered = false,
}: SignUpCardProps) {
	const { components, organizationSettings } = useConfig();
	const { getColorValue } = useTheme();

	// Custom component override
	const CustomSignUpCard = components.SignUpCard;
	if (CustomSignUpCard) {
		return (
			<CustomSignUpCard
				{...{
					variant,
					className,
					padding,
					radius,
					shadow,
					isBlurred,
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
					footer,
					header,
					maxWidth,
					centered,
				}}
			/>
		);
	}

	// Animation variants
	const cardVariants = {
		hidden: {
			opacity: 0,
			y: 20,
			scale: 0.95,
		},
		visible: {
			opacity: 1,
			y: 0,
			scale: 1,
			transition: {
				duration: 0.3,
				ease: "easeOut",
			},
		},
	};

	// Card styles
	const cardStyles: React.CSSProperties = {
		maxWidth: typeof maxWidth === "number" ? `${maxWidth}px` : maxWidth,
	};

	// Organization branding
	const orgBranding = showBranding && organizationSettings?.branding;

	// Parse invitation data for display
	const invitationData = React.useMemo(() => {
		if (!invitationToken) return null;
		try {
			const decoded = atob(invitationToken);
			return JSON.parse(decoded);
		} catch {
			return null;
		}
	}, [invitationToken]);

	// Default content
	const getDefaultContent = () => {
		if (invitationData) {
			return {
				title: `Join ${invitationData.orgName || "Organization"}`,
				subtitle: invitationData.inviterName
					? `${invitationData.inviterName} has invited you to join`
					: "You've been invited to join",
			};
		}

		if (orgBranding?.customSignUpText) {
			return {
				title: orgBranding.customSignUpText.title || "Create your account",
				subtitle: orgBranding.customSignUpText.subtitle || "Join us today",
			};
		}

		return {
			title: "Create your account",
			subtitle: "Join us today",
		};
	};

	const defaultContent = getDefaultContent();
	const finalTitle = title || defaultContent.title;
	const finalSubtitle = subtitle || defaultContent.subtitle;

	// Container classes
	const containerClasses = [
		centered ? "flex items-center justify-center min-h-screen p-4" : "",
	]
		.filter(Boolean)
		.join(" ");

	// Card component
	const cardContent = (
		<Card
			className={`${className} ${centered ? "w-full" : ""}`}
			style={cardStyles}
			shadow={shadow}
			radius={radius}
			isBlurred={isBlurred}
		>
			{/* Card Header */}
			<CardHeader
				className={`flex flex-col items-center text-center gap-3 p-${padding}`}
			>
				{header || (
					<>
						{/* Organization Logo */}
						{orgBranding?.logoUrl && (
							<img
								src={orgBranding.logoUrl}
								alt="Organization Logo"
								className="h-12 w-auto mb-2"
							/>
						)}

						{/* Title */}
						{finalTitle && (
							<h1 className="text-2xl font-bold text-foreground">
								{finalTitle}
							</h1>
						)}

						{/* Subtitle */}
						{finalSubtitle && (
							<p className="text-default-500 text-sm max-w-sm">
								{finalSubtitle}
							</p>
						)}

						{/* Invitation Badge */}
						{invitationData && (
							<div className="bg-primary-50 dark:bg-primary-900/20 rounded-lg px-3 py-2 text-sm">
								<p className="text-primary-600 dark:text-primary-400">
									<span className="font-medium">Role:</span>{" "}
									{invitationData.role}
								</p>
								{invitationData.expiresAt && (
									<p className="text-primary-500 text-xs mt-1">
										Expires:{" "}
										{new Date(invitationData.expiresAt).toLocaleDateString()}
									</p>
								)}
							</div>
						)}
					</>
				)}
			</CardHeader>

			{/* Divider */}
			<Divider />

			{/* Card Body */}
			<CardBody className={`p-${padding}`}>
				<SignUpForm
					methods={methods}
					email={email}
					organizationId={organizationId}
					invitationToken={invitationToken}
					redirectUrl={redirectUrl}
					onSuccess={onSuccess}
					onError={onError}
					title={undefined} // Title is in header
					subtitle={undefined} // Subtitle is in header
					size={size}
					showBranding={false} // Branding is in header
					disabled={disabled}
					requireTerms={requireTerms}
					termsUrl={termsUrl}
					privacyUrl={privacyUrl}
					variant="minimal"
					className="space-y-4"
					showSignInLink={true}
					autoFocus={true}
				/>
			</CardBody>

			{/* Card Footer */}
			{footer && (
				<>
					<Divider />
					<CardFooter className={`p-${padding} text-center`}>
						{footer}
					</CardFooter>
				</>
			)}
		</Card>
	);

	// Wrap with animation
	const animatedCard = (
		<motion.div
			initial="hidden"
			animate="visible"
			variants={cardVariants}
			style={{ maxWidth }}
			className={centered ? "w-full" : ""}
		>
			{cardContent}
		</motion.div>
	);

	// Wrap with container if centered
	return centered ? (
		<div className={containerClasses}>{animatedCard}</div>
	) : (
		animatedCard
	);
}

// ============================================================================
// Sign Up Card Variants
// ============================================================================

/**
 * Bordered Sign Up Card
 */
export function BorderedSignUpCard(props: Omit<SignUpCardProps, "variant">) {
	return <SignUpCard {...props} variant="bordered" />;
}

/**
 * Flat Sign Up Card
 */
export function FlatSignUpCard(props: Omit<SignUpCardProps, "variant">) {
	return <SignUpCard {...props} variant="flat" />;
}

/**
 * Compact Sign Up Card
 */
export function CompactSignUpCard(props: SignUpCardProps) {
	return <SignUpCard {...props} padding="sm" size="sm" maxWidth={350} />;
}

/**
 * Large Sign Up Card
 */
export function LargeSignUpCard(props: SignUpCardProps) {
	return <SignUpCard {...props} padding="lg" size="lg" maxWidth={550} />;
}

/**
 * Centered Sign Up Card (for full-page layouts)
 */
export function CenteredSignUpCard(props: Omit<SignUpCardProps, "centered">) {
	return <SignUpCard {...props} centered />;
}

/**
 * Blurred Glass Sign Up Card
 */
export function GlassSignUpCard(props: SignUpCardProps) {
	return (
		<SignUpCard
			{...props}
			variant="shadow"
			isBlurred
			className="backdrop-blur-md border border-white/20 bg-background/80"
		/>
	);
}

/**
 * Gradient Sign Up Card
 */
export function GradientSignUpCard({
	className = "",
	...props
}: SignUpCardProps) {
	return (
		<SignUpCard
			{...props}
			variant="shadow"
			className={`bg-gradient-to-br from-primary-50 to-secondary-50 dark:from-primary-900/20 dark:to-secondary-900/20 ${className}`}
		/>
	);
}

/**
 * Minimal Sign Up Card
 */
export function MinimalSignUpCard(props: SignUpCardProps) {
	return <SignUpCard {...props} variant="flat" shadow="none" padding="md" />;
}

// ============================================================================
// Invitation Sign Up Card
// ============================================================================

export interface InvitationSignUpCardProps
	extends Omit<SignUpCardProps, "invitationToken" | "organizationId"> {
	/**
	 * Invitation token
	 */
	invitationToken: string;

	/**
	 * Show invitation details
	 */
	showInvitationDetails?: boolean;

	/**
	 * Invitation expires warning threshold (hours)
	 */
	expirationWarningHours?: number;
}

export function InvitationSignUpCard({
	invitationToken,
	showInvitationDetails = true,
	expirationWarningHours = 24,
	header,
	className = "",
	...props
}: InvitationSignUpCardProps) {
	// Parse invitation data
	const invitationData = React.useMemo(() => {
		try {
			const decoded = atob(invitationToken);
			return JSON.parse(decoded);
		} catch {
			return null;
		}
	}, [invitationToken]);

	// Check if invitation is expiring soon
	const isExpiringSoon = React.useMemo(() => {
		if (!invitationData?.expiresAt) return false;

		const expiresAt = new Date(invitationData.expiresAt);
		const now = new Date();
		const hoursUntilExpiry =
			(expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

		return hoursUntilExpiry <= expirationWarningHours && hoursUntilExpiry > 0;
	}, [invitationData, expirationWarningHours]);

	// Check if invitation is expired
	const isExpired = React.useMemo(() => {
		if (!invitationData?.expiresAt) return false;
		return new Date(invitationData.expiresAt) <= new Date();
	}, [invitationData]);

	if (isExpired) {
		return (
			<Card className={`max-w-md mx-auto ${className}`} variant="bordered">
				<CardBody className="text-center p-8">
					<div className="text-danger-500 mb-4">
						<svg
							className="w-16 h-16 mx-auto"
							fill="currentColor"
							viewBox="0 0 20 20"
						>
							<path
								fillRule="evenodd"
								d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
								clipRule="evenodd"
							/>
						</svg>
					</div>
					<h2 className="text-xl font-semibold text-foreground mb-2">
						Invitation Expired
					</h2>
					<p className="text-default-500 mb-4">
						This invitation has expired. Please contact the organization to
						request a new invitation.
					</p>
					{invitationData?.inviterEmail && (
						<p className="text-sm text-default-400">
							Contact: {invitationData.inviterEmail}
						</p>
					)}
				</CardBody>
			</Card>
		);
	}

	const customHeader =
		header ||
		(showInvitationDetails && invitationData && (
			<div className="text-center space-y-3">
				{/* Organization Logo */}
				{invitationData.orgLogo && (
					<img
						src={invitationData.orgLogo}
						alt={`${invitationData.orgName} Logo`}
						className="h-16 w-auto mx-auto"
					/>
				)}

				{/* Title */}
				<h1 className="text-2xl font-bold text-foreground">
					Join {invitationData.orgName}
				</h1>

				{/* Invitation Details */}
				<div className="space-y-2">
					{invitationData.inviterName && (
						<p className="text-default-600">
							{invitationData.inviterName} has invited you to join as a{" "}
							<span className="font-medium text-primary-600">
								{invitationData.role}
							</span>
						</p>
					)}

					{/* Expiration Warning */}
					{isExpiringSoon && (
						<div className="bg-warning-50 dark:bg-warning-900/20 border border-warning-200 dark:border-warning-800 rounded-lg p-3">
							<p className="text-warning-700 dark:text-warning-400 text-sm">
								⚠️ This invitation expires soon. Please sign up as soon as
								possible.
							</p>
						</div>
					)}
				</div>
			</div>
		));

	return (
		<SignUpCard
			{...props}
			invitationToken={invitationToken}
			organizationId={invitationData?.orgId}
			header={customHeader}
			className={`${className} ${isExpiringSoon ? "border-warning-200" : ""}`}
		/>
	);
}

// ============================================================================
// Trial Sign Up Card
// ============================================================================

export interface TrialSignUpCardProps extends SignUpCardProps {
	/**
	 * Trial duration in days
	 */
	trialDays?: number;

	/**
	 * Features included in trial
	 */
	trialFeatures?: string[];

	/**
	 * Whether credit card is required
	 */
	requiresCreditCard?: boolean;
}

export function TrialSignUpCard({
	trialDays = 14,
	trialFeatures = [],
	requiresCreditCard = false,
	title,
	subtitle,
	header,
	footer,
	...props
}: TrialSignUpCardProps) {
	const defaultTitle = `Start Your ${trialDays}-Day Free Trial`;
	const defaultSubtitle = requiresCreditCard
		? `No charge for ${trialDays} days, cancel anytime`
		: "No credit card required";

	const customHeader = header || (
		<div className="text-center space-y-3">
			{/* Trial Badge */}
			<div className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400">
				FREE TRIAL
			</div>

			<h1 className="text-2xl font-bold text-foreground">
				{title || defaultTitle}
			</h1>

			<p className="text-default-500">{subtitle || defaultSubtitle}</p>

			{/* Trial Features */}
			{trialFeatures.length > 0 && (
				<div className="bg-default-50 dark:bg-default-900/20 rounded-lg p-4 text-left">
					<h3 className="font-medium text-foreground mb-2 text-center">
						What's included:
					</h3>
					<ul className="space-y-1 text-sm text-default-600">
						{trialFeatures.map((feature, index) => (
							<li key={index} className="flex items-center gap-2">
								<svg
									className="w-4 h-4 text-success-500 flex-shrink-0"
									fill="currentColor"
									viewBox="0 0 20 20"
								>
									<path
										fillRule="evenodd"
										d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
										clipRule="evenodd"
									/>
								</svg>
								{feature}
							</li>
						))}
					</ul>
				</div>
			)}
		</div>
	);

	const customFooter = footer || (
		<div className="text-center text-xs text-default-500">
			{requiresCreditCard && (
				<p>
					Your trial starts today. You can cancel anytime before it ends to
					avoid charges.
				</p>
			)}
		</div>
	);

	return (
		<SignUpCard
			{...props}
			title={undefined} // Title is in custom header
			subtitle={undefined} // Subtitle is in custom header
			header={customHeader}
			footer={customFooter}
			variant="shadow"
			className="border-success-200 dark:border-success-800"
		/>
	);
}

// ============================================================================
// Organization Themed Sign Up Card
// ============================================================================

export function OrganizationSignUpCard(props: SignUpCardProps) {
	const { organizationSettings } = useConfig();

	if (!organizationSettings) {
		return <SignUpCard {...props} />;
	}

	const branding = organizationSettings.branding;

	// Apply organization theme
	const orgProps = {
		...props,
		showBranding: true,
		className: `${props.className || ""} organization-themed`,
		style: {
			"--org-primary": branding?.primaryColor,
			"--org-secondary": branding?.secondaryColor,
		} as React.CSSProperties,
	};

	return <SignUpCard {...orgProps} />;
}

// ============================================================================
// Export
// ============================================================================

export default SignUpCard;
