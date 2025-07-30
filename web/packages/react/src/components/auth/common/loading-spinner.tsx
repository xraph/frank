/**
 * @frank-auth/react - Loading Spinner Component
 *
 * Versatile loading component with multiple variants and customization options.
 * Supports organization theming and various loading states.
 */

"use client";

import { Spinner } from "@/components/ui";
import { motion } from "framer-motion";
import React from "react";
import { useConfig } from "../../../hooks/use-config";
import { useTheme } from "../../../hooks/use-theme";

// ============================================================================
// Loading Spinner Interface
// ============================================================================

export interface LoadingSpinnerProps {
	/**
	 * Loading variant
	 */
	variant?: "spinner" | "dots" | "pulse" | "bars" | "custom";

	/**
	 * Size of the loading component
	 */
	size?: "sm" | "md" | "lg" | "xl";

	/**
	 * Color theme
	 */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "default";

	/**
	 * Loading text
	 */
	text?: string;

	/**
	 * Whether to show text
	 */
	showText?: boolean;

	/**
	 * Text position relative to spinner
	 */
	textPosition?: "top" | "bottom" | "left" | "right";

	/**
	 * Whether to center the component
	 */
	centered?: boolean;

	/**
	 * Whether to show as overlay
	 */
	overlay?: boolean;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Custom loading content
	 */
	children?: React.ReactNode;

	/**
	 * Animation duration (in seconds)
	 */
	duration?: number;

	/**
	 * Whether to show backdrop
	 */
	backdrop?: boolean;

	/**
	 * Backdrop opacity
	 */
	backdropOpacity?: number;
}

// ============================================================================
// Loading Variants
// ============================================================================

const SpinnerVariant = ({
	size,
	color,
	duration = 1,
}: { size: string; color: string; duration?: number }) => (
	<motion.div
		className={`border-2 border-transparent border-t-current border-r-current rounded-full ${size}`}
		animate={{ rotate: 360 }}
		transition={{ duration, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
		style={{ color: `var(--${color})` }}
	/>
);

const DotsVariant = ({
	size,
	color,
	duration = 1.4,
}: { size: string; color: string; duration?: number }) => {
	const dotSizes = {
		"w-2 h-2": "w-2 h-2",
		"w-3 h-3": "w-3 h-3",
		"w-4 h-4": "w-4 h-4",
		"w-6 h-6": "w-6 h-6",
	};

	const dotSize = dotSizes[size as keyof typeof dotSizes] || "w-3 h-3";

	return (
		<div className="flex gap-1">
			{[0, 1, 2].map((index) => (
				<motion.div
					key={index}
					className={`${dotSize} rounded-full bg-current`}
					style={{ color: `var(--${color})` }}
					animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
					transition={{
						duration,
						repeat: Number.POSITIVE_INFINITY,
						delay: index * 0.2,
						ease: "easeInOut",
					}}
				/>
			))}
		</div>
	);
};

const PulseVariant = ({
	size,
	color,
	duration = 1.5,
}: { size: string; color: string; duration?: number }) => (
	<motion.div
		className={`rounded-full bg-current ${size}`}
		style={{ color: `var(--${color})` }}
		animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
		transition={{
			duration,
			repeat: Number.POSITIVE_INFINITY,
			ease: "easeInOut",
		}}
	/>
);

const BarsVariant = ({
	size,
	color,
	duration = 1.2,
}: { size: string; color: string; duration?: number }) => {
	const barHeights = {
		"w-2 h-2": "w-1 h-4",
		"w-3 h-3": "w-1 h-6",
		"w-4 h-4": "w-1 h-8",
		"w-6 h-6": "w-2 h-12",
	};

	const barHeight = barHeights[size as keyof typeof barHeights] || "w-1 h-6";

	return (
		<div className="flex items-end gap-1">
			{[0, 1, 2, 3].map((index) => (
				<motion.div
					key={index}
					className={`${barHeight} bg-current rounded-sm`}
					style={{ color: `var(--${color})` }}
					animate={{ scaleY: [1, 2, 1] }}
					transition={{
						duration,
						repeat: Number.POSITIVE_INFINITY,
						delay: index * 0.1,
						ease: "easeInOut",
					}}
				/>
			))}
		</div>
	);
};

// ============================================================================
// Loading Spinner Component
// ============================================================================

export function LoadingSpinner({
	variant = "spinner",
	size = "md",
	color = "primary",
	text = "Loading...",
	showText = false,
	textPosition = "bottom",
	centered = false,
	overlay = false,
	className = "",
	children,
	duration = 1,
	backdrop = false,
	backdropOpacity = 0.5,
}: LoadingSpinnerProps) {
	const { getColorValue } = useTheme();
	const { components } = useConfig();

	// Custom component override
	const CustomLoadingSpinner = components.LoadingSpinner;
	if (CustomLoadingSpinner) {
		return (
			<CustomLoadingSpinner
				{...{
					variant,
					size,
					color,
					text,
					showText,
					textPosition,
					centered,
					overlay,
					className,
					children,
					duration,
					backdrop,
					backdropOpacity,
				}}
			/>
		);
	}

	// Size mappings
	const sizeClasses = {
		sm: "w-4 h-4",
		md: "w-6 h-6",
		lg: "w-8 h-8",
		xl: "w-12 h-12",
	};

	const textSizes = {
		sm: "text-xs",
		md: "text-sm",
		lg: "text-base",
		xl: "text-lg",
	};

	// Get color value
	const colorValue = getColorValue(color);

	// Render spinner based on variant
	const renderSpinner = () => {
		const sizeClass = sizeClasses[size];
		const colorClass = `text-${color}-600 dark:text-${color}-400`;

		switch (variant) {
			case "dots":
				return (
					<DotsVariant
						size={sizeClass}
						color={colorClass}
						duration={duration}
					/>
				);
			case "pulse":
				return (
					<PulseVariant
						size={sizeClass}
						color={colorClass}
						duration={duration}
					/>
				);
			case "bars":
				return (
					<BarsVariant
						size={sizeClass}
						color={colorClass}
						duration={duration}
					/>
				);
			case "custom":
				return (
					children || (
						<SpinnerVariant
							size={sizeClass}
							color={colorClass}
							duration={duration}
						/>
					)
				);
			case "spinner":
			default:
				return <Spinner size={size} color={color as any} />;
		}
	};

	// Render text
	const renderText = () => {
		if (!showText || !text) return null;

		return (
			<span
				className={`${textSizes[size]} text-${color}-600 dark:text-${color}-400 font-medium`}
			>
				{text}
			</span>
		);
	};

	// Content layout based on text position
	const renderContent = () => {
		const spinner = renderSpinner();
		const textElement = renderText();

		if (!showText) {
			return spinner;
		}

		const flexDirection = {
			top: "flex-col-reverse",
			bottom: "flex-col",
			left: "flex-row-reverse",
			right: "flex-row",
		};

		const gap = {
			top: "gap-2",
			bottom: "gap-2",
			left: "gap-3",
			right: "gap-3",
		};

		return (
			<div
				className={`flex items-center justify-center ${flexDirection[textPosition]} ${gap[textPosition]}`}
			>
				{spinner}
				{textElement}
			</div>
		);
	};

	// Base content
	const content = (
		<div
			className={`
      ${centered ? "flex items-center justify-center" : ""}
      ${className}
    `}
		>
			{renderContent()}
		</div>
	);

	// Overlay variant
	if (overlay) {
		return (
			<div className="fixed inset-0 z-50 flex items-center justify-center">
				{/* Backdrop */}
				{backdrop && (
					<motion.div
						initial={{ opacity: 0 }}
						animate={{ opacity: backdropOpacity }}
						exit={{ opacity: 0 }}
						className="absolute inset-0 bg-background/80 backdrop-blur-sm"
					/>
				)}

				{/* Content */}
				<motion.div
					initial={{ opacity: 0, scale: 0.8 }}
					animate={{ opacity: 1, scale: 1 }}
					exit={{ opacity: 0, scale: 0.8 }}
					className="relative z-10"
				>
					{content}
				</motion.div>
			</div>
		);
	}

	return content;
}

// ============================================================================
// Loading Button Component
// ============================================================================

export interface LoadingButtonProps
	extends React.ButtonHTMLAttributes<HTMLButtonElement> {
	/**
	 * Whether button is loading
	 */
	isLoading?: boolean;

	/**
	 * Loading text (overrides children when loading)
	 */
	loadingText?: string;

	/**
	 * Loading spinner props
	 */
	spinnerProps?: Partial<LoadingSpinnerProps>;

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
	 * Button color
	 */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "default";

	/**
	 * Button size
	 */
	size?: "sm" | "md" | "lg";
}

export function LoadingButton({
	isLoading = false,
	loadingText = "Loading...",
	spinnerProps = {},
	variant = "solid",
	color = "primary",
	size = "md",
	children,
	disabled,
	className = "",
	...props
}: LoadingButtonProps) {
	const { components } = useConfig();

	// Custom component override
	const CustomLoadingButton = components.LoadingButton;
	if (CustomLoadingButton) {
		return (
			<CustomLoadingButton
				{...{
					isLoading,
					loadingText,
					spinnerProps,
					variant,
					color,
					size,
					children,
					disabled,
					className,
					...props,
				}}
			/>
		);
	}

	const spinnerSize = {
		sm: "sm" as const,
		md: "sm" as const,
		lg: "md" as const,
	};

	return (
		<button
			{...props}
			disabled={disabled || isLoading}
			className={`
        relative inline-flex items-center justify-center gap-2 px-4 py-2 
        text-sm font-medium rounded-md transition-colors
        ${variant === "solid" ? `bg-${color}-600 text-white hover:bg-${color}-700` : ""}
        ${variant === "bordered" ? `border border-${color}-600 text-${color}-600 hover:bg-${color}-50` : ""}
        ${variant === "light" ? `text-${color}-600 hover:bg-${color}-50` : ""}
        disabled:opacity-50 disabled:cursor-not-allowed
        ${className}
      `}
		>
			{isLoading && (
				<LoadingSpinner
					variant="spinner"
					size={spinnerSize[size]}
					color={variant === "solid" ? "default" : color}
					{...spinnerProps}
				/>
			)}

			<span className={isLoading ? "opacity-70" : ""}>
				{isLoading ? loadingText : children}
			</span>
		</button>
	);
}

// ============================================================================
// Loading States
// ============================================================================

/**
 * Common loading states for authentication flows
 */
export const LoadingStates = {
	signIn: {
		text: "Signing in...",
		variant: "spinner" as const,
	},
	signUp: {
		text: "Creating account...",
		variant: "spinner" as const,
	},
	signOut: {
		text: "Signing out...",
		variant: "dots" as const,
	},
	verifying: {
		text: "Verifying...",
		variant: "pulse" as const,
	},
	processing: {
		text: "Processing...",
		variant: "bars" as const,
	},
	loading: {
		text: "Loading...",
		variant: "spinner" as const,
	},
	sending: {
		text: "Sending...",
		variant: "dots" as const,
	},
	redirecting: {
		text: "Redirecting...",
		variant: "pulse" as const,
	},
} as const;

// ============================================================================
// Loading Context
// ============================================================================

interface LoadingContextValue {
	isLoading: boolean;
	loadingText: string;
	setLoading: (loading: boolean, text?: string) => void;
}

const LoadingContext = React.createContext<LoadingContextValue | null>(null);

export function LoadingProvider({ children }: { children: React.ReactNode }) {
	const [isLoading, setIsLoading] = React.useState(false);
	const [loadingText, setLoadingText] = React.useState("Loading...");

	const setLoading = React.useCallback(
		(loading: boolean, text = "Loading...") => {
			setIsLoading(loading);
			setLoadingText(text);
		},
		[],
	);

	return (
		<LoadingContext.Provider value={{ isLoading, loadingText, setLoading }}>
			{children}
			{isLoading && (
				<LoadingSpinner
					overlay
					backdrop
					showText
					text={loadingText}
					variant="spinner"
					size="lg"
					color="primary"
				/>
			)}
		</LoadingContext.Provider>
	);
}

export function useLoading() {
	const context = React.useContext(LoadingContext);
	if (!context) {
		throw new Error("useLoading must be used within a LoadingProvider");
	}
	return context;
}

// ============================================================================
// Export
// ============================================================================

export default LoadingSpinner;
