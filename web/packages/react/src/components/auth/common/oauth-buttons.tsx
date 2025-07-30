/**
 * @frank-auth/react - OAuth Buttons Component
 *
 * OAuth provider buttons with organization-specific configurations,
 * custom styling, and comprehensive provider support.
 */

"use client";

import { Button } from "@/components/ui";
import { motion } from "framer-motion";
import React from "react";
import { useConfig } from "../../../hooks/use-config";
import { type OAuthProviderType, useOAuth } from "../../../hooks/use-oauth";

// ============================================================================
// OAuth Buttons Types
// ============================================================================

export interface OAuthButtonsProps {
	/**
	 * OAuth providers to show
	 */
	providers?: OAuthProviderType[];

	/**
	 * Button layout
	 */
	layout?: "vertical" | "horizontal" | "grid";

	/**
	 * Button variant
	 */
	variant?:
		| "solid"
		| "bordered"
		| "light"
		| "flat"
		| "faded"
		| "shadow"
		| "ghost";

	/**
	 * Button size
	 */
	size?: "sm" | "md" | "lg";

	/**
	 * Whether to show provider icons
	 */
	showIcons?: boolean;

	/**
	 * Whether to show provider names
	 */
	showNames?: boolean;

	/**
	 * Custom button text format
	 */
	textFormat?: "continue" | "sign-in" | "sign-up" | "connect" | "custom";

	/**
	 * Custom text template (use {provider} placeholder)
	 */
	customText?: string;

	/**
	 * Redirect URL after OAuth
	 */
	redirectUrl?: string;

	/**
	 * Organization ID for OAuth
	 */
	organizationId?: string;

	/**
	 * Success callback
	 */
	onSuccess?: (provider: string, result: any) => void;

	/**
	 * Error callback
	 */
	onError?: (provider: string, error: Error) => void;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Disabled state
	 */
	disabled?: boolean;

	/**
	 * Whether to animate buttons
	 */
	animated?: boolean;

	/**
	 * Custom button props
	 */
	buttonProps?: any;
}

// ============================================================================
// Provider Configurations
// ============================================================================

const PROVIDER_CONFIGS = {
	google: {
		name: "Google",
		color: "#4285f4",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
				/>
				<path
					fill="currentColor"
					d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
				/>
				<path
					fill="currentColor"
					d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
				/>
				<path
					fill="currentColor"
					d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
				/>
			</svg>
		),
	},
	microsoft: {
		name: "Microsoft",
		color: "#00a1f1",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path fill="#f25022" d="M1 1h10v10H1z" />
				<path fill="#00a4ef" d="M13 1h10v10H13z" />
				<path fill="#7fba00" d="M1 13h10v10H1z" />
				<path fill="#ffb900" d="M13 13h10v10H13z" />
			</svg>
		),
	},
	github: {
		name: "GitHub",
		color: "#333333",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"
				/>
			</svg>
		),
	},
	apple: {
		name: "Apple",
		color: "#000000",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"
				/>
			</svg>
		),
	},
	facebook: {
		name: "Facebook",
		color: "#1877f2",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"
				/>
			</svg>
		),
	},
	twitter: {
		name: "Twitter",
		color: "#1da1f2",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"
				/>
			</svg>
		),
	},
	linkedin: {
		name: "LinkedIn",
		color: "#0077b5",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"
				/>
			</svg>
		),
	},
	discord: {
		name: "Discord",
		color: "#5865f2",
		textColor: "#ffffff",
		icon: (
			<svg viewBox="0 0 24 24" className="w-5 h-5">
				<path
					fill="currentColor"
					d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.120.098.246.191.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.500-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"
				/>
			</svg>
		),
	},
} as const;

// ============================================================================
// OAuth Button Component
// ============================================================================

interface OAuthButtonProps {
	provider: OAuthProviderType;
	variant?:
		| "solid"
		| "bordered"
		| "light"
		| "flat"
		| "faded"
		| "shadow"
		| "ghost";
	size?: "sm" | "md" | "lg";
	showIcon?: boolean;
	showName?: boolean;
	text?: string;
	onClick?: () => void;
	disabled?: boolean;
	isLoading?: boolean;
	className?: string;
	animated?: boolean;
	buttonProps?: any;
}

function OAuthButton({
	provider,
	variant = "bordered",
	size = "md",
	showIcon = true,
	showName = true,
	text,
	onClick,
	disabled = false,
	isLoading = false,
	className = "",
	animated = true,
	buttonProps = {},
}: OAuthButtonProps) {
	const config = PROVIDER_CONFIGS[provider];
	const { components } = useConfig();

	// Custom component override
	const CustomOAuthButton = components.OAuthButton;
	if (CustomOAuthButton) {
		return (
			<CustomOAuthButton
				{...{
					provider,
					variant,
					size,
					showIcon,
					showName,
					text,
					onClick,
					disabled,
					isLoading,
					className,
					animated,
					buttonProps,
				}}
			/>
		);
	}

	const buttonText = text || `Continue with ${config.name}`;

	const buttonContent = (
		<>
			{showIcon && (
				<span className={`${isLoading ? "opacity-50" : ""}`}>
					{config.icon}
				</span>
			)}
			{showName && (
				<span
					className={`font-medium ${isLoading ? "opacity-70" : ""} ${!showIcon ? "" : "ml-2"}`}
				>
					{isLoading ? "Connecting..." : buttonText}
				</span>
			)}
			{isLoading && (
				<div className="ml-2">
					<div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin opacity-60" />
				</div>
			)}
		</>
	);

	const buttonElement = (
		<Button
			variant={variant}
			size={size}
			onPress={onClick}
			isDisabled={disabled || isLoading}
			className={`
        ${variant === "solid" ? `bg-[${config.color}] text-[${config.textColor}] hover:opacity-90` : ""}
        ${variant === "bordered" ? `border-[${config.color}] text-[${config.color}] hover:bg-[${config.color}]/10` : ""}
        ${variant === "light" ? `text-[${config.color}] hover:bg-[${config.color}]/10` : ""}
        w-full justify-start
        ${className}
      `}
			startContent={showIcon ? config.icon : undefined}
			{...buttonProps}
		>
			{showName ? (isLoading ? "Connecting..." : buttonText) : null}
		</Button>
	);

	if (animated) {
		return (
			<motion.div
				whileHover={{ scale: disabled || isLoading ? 1 : 1.02 }}
				whileTap={{ scale: disabled || isLoading ? 1 : 0.98 }}
				transition={{ duration: 0.1 }}
			>
				{buttonElement}
			</motion.div>
		);
	}

	return buttonElement;
}

// ============================================================================
// OAuth Buttons Component
// ============================================================================

export function OAuthButtons({
	providers = ["google", "microsoft", "github"],
	layout = "vertical",
	variant = "bordered",
	size = "md",
	showIcons = true,
	showNames = true,
	textFormat = "continue",
	customText,
	redirectUrl,
	organizationId,
	onSuccess,
	onError,
	className = "",
	disabled = false,
	animated = true,
	buttonProps = {},
}: OAuthButtonsProps) {
	const { signInWithProvider, isLoading } = useOAuth();
	const { organizationSettings, features } = useConfig();
	const { components } = useConfig();

	// Custom component override
	const CustomOAuthButtons = components.OAuthButtons;
	if (CustomOAuthButtons) {
		return (
			<CustomOAuthButtons
				{...{
					providers,
					layout,
					variant,
					size,
					showIcons,
					showNames,
					textFormat,
					customText,
					redirectUrl,
					organizationId,
					onSuccess,
					onError,
					className,
					disabled,
					animated,
					buttonProps,
				}}
			/>
		);
	}

	// Filter providers based on organization settings
	const availableProviders = React.useMemo(() => {
		if (!features.oauth) return [];

		// Get organization-allowed providers
		const orgProviders = organizationSettings?.oauthProviders || [];

		if (orgProviders.length > 0) {
			return providers.filter((provider) =>
				orgProviders.some((op: any) => op.provider === provider && op.enabled),
			);
		}

		return providers;
	}, [providers, organizationSettings, features.oauth]);

	// Generate button text
	const getButtonText = (provider: OAuthProviderType) => {
		if (customText) {
			return customText.replace("{provider}", PROVIDER_CONFIGS[provider].name);
		}

		const providerName = PROVIDER_CONFIGS[provider].name;

		switch (textFormat) {
			case "sign-in":
				return `Sign in with ${providerName}`;
			case "sign-up":
				return `Sign up with ${providerName}`;
			case "connect":
				return `Connect ${providerName}`;
			case "continue":
			default:
				return `Continue with ${providerName}`;
		}
	};

	// Handle OAuth provider click
	const handleProviderClick = React.useCallback(
		async (provider: OAuthProviderType) => {
			if (disabled || isLoading) return;

			try {
				await signInWithProvider(provider, {
					redirectUrl,
					organizationId,
				});

				onSuccess?.(provider, { provider });
			} catch (error) {
				const authError =
					error instanceof Error
						? error
						: new Error("OAuth authentication failed");
				onError?.(provider, authError);
			}
		},
		[
			signInWithProvider,
			redirectUrl,
			organizationId,
			onSuccess,
			onError,
			disabled,
			isLoading,
		],
	);

	// Don't render if no providers available
	if (availableProviders.length === 0) {
		return null;
	}

	// Layout classes
	const layoutClasses = {
		vertical: "flex flex-col gap-3",
		horizontal: "flex flex-row gap-3 flex-wrap",
		grid: "grid grid-cols-1 sm:grid-cols-2 gap-3",
	};

	return (
		<div className={`${layoutClasses[layout]} ${className}`}>
			{availableProviders.map((provider, index) => (
				<motion.div
					key={provider}
					initial={animated ? { opacity: 0, y: 10 } : false}
					animate={animated ? { opacity: 1, y: 0 } : false}
					transition={animated ? { delay: index * 0.1 } : undefined}
				>
					<OAuthButton
						provider={provider}
						variant={variant}
						size={size}
						showIcon={showIcons}
						showName={showNames}
						text={getButtonText(provider)}
						onClick={() => handleProviderClick(provider)}
						disabled={disabled}
						isLoading={isLoading}
						animated={animated}
						buttonProps={buttonProps}
					/>
				</motion.div>
			))}
		</div>
	);
}

// ============================================================================
// OAuth Divider Component
// ============================================================================

export function OAuthDivider({
	text = "or",
	className = "",
}: {
	text?: string;
	className?: string;
}) {
	return (
		<div className={`relative flex items-center my-6 ${className}`}>
			<div className="flex-grow border-t border-default-200 dark:border-default-700" />
			<span className="px-4 text-sm text-default-500 bg-background">
				{text}
			</span>
			<div className="flex-grow border-t border-default-200 dark:border-default-700" />
		</div>
	);
}

// ============================================================================
// Export
// ============================================================================

export default OAuthButtons;
