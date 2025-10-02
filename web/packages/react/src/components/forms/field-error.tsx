/**
 * @frank-auth/react - Field Error Component
 *
 * Displays field validation errors with consistent styling and animation.
 * Integrates with form validation system and supports organization theming.
 */

"use client";

import { HelperText } from "@/components/ui/input/input";
import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import type { SizeT } from "@/types";
import styled from "@emotion/styled";
import { AnimatePresence, motion } from "framer-motion";
import React from "react";

// ============================================================================
// Field Error Interface
// ============================================================================

export interface FieldErrorProps {
	/**
	 * The error message to display
	 */
	error?: string | string[] | null;

	/**
	 * Field name for accessibility
	 */
	fieldName?: string;

	/**
	 * Whether to show error immediately or animate in
	 */
	immediate?: boolean;

	/**
	 * Custom className for styling
	 */
	className?: string;

	/**
	 * Custom error icon
	 */
	icon?: React.ReactNode;

	/**
	 * Whether to show multiple errors or just the first one
	 */
	showMultiple?: boolean;

	/**
	 * Custom styling variant
	 */
	variant?: "default" | "inline" | "tooltip";

	/**
	 * Size variant
	 */
	size?: SizeT;
}

// ============================================================================
// Styled Components
// ============================================================================

const ErrorContainer = styled(motion.div)<
	StyledProps & {
		size: SizeT;
		variant: "default" | "inline" | "tooltip";
	}
>`
	display: flex;
	align-items: flex-start;
	gap: ${(props) => props.theme.spacing[1]};
	color: ${(props) => props.theme.colors.danger[600]};

	font-size: ${(props) => {
		switch (props.size) {
			case "sm":
				return props.theme.fontSizes.xs;
			case "lg":
				return props.theme.fontSizes.base;
			default:
				return props.theme.fontSizes.sm;
		}
	}};

	${(props) => {
		switch (props.variant) {
			case "inline":
				return `
					margin-left: ${props.theme.spacing[2]};
					display: inline-flex;
				`;
			case "tooltip":
				return `
					position: absolute;
					z-index: ${props.theme.zIndex.tooltip};
					margin-top: ${props.theme.spacing[1]};
				`;
			default:
				// Fixed: Removed margin-top since parent container handles spacing with gap
				return "";
		}
	}}
`;

const ErrorIcon = styled.span<StyledProps>`
	color: ${(props) => props.theme.colors.danger[500]};
	margin-top: ${(props) => props.theme.spacing[0.5] || "0.125rem"};
	flex-shrink: 0;

	svg {
		width: ${(props) => props.theme.spacing[4]};
		height: ${(props) => props.theme.spacing[4]};
	}
`;

const ErrorContent = styled.div<StyledProps>`
	flex: 1;
	min-width: 0;
`;

const ErrorMessage = styled.div<StyledProps & { hasMargin?: boolean }>`
	${(props) => props.hasMargin && `margin-top: ${props.theme.spacing[1]};`}
`;

const ErrorText = styled.span<StyledProps>`
	display: block;
	color: inherit;
	word-break: break-words;
`;

// ============================================================================
// Field Error Component
// ============================================================================

export function FieldError({
	error,
	fieldName,
	immediate = false,
	className = "",
	icon,
	showMultiple = false,
	variant = "default",
	size = "md",
}: FieldErrorProps) {
	const { theme } = useTheme();

	// Normalize error to array
	const errors = React.useMemo(() => {
		if (!error) return [];
		if (Array.isArray(error)) return error.filter(Boolean);
		return [error];
	}, [error]);

	// Don't render if no errors
	if (errors.length === 0) return null;

	// Display errors (show all if showMultiple is true, otherwise just first)
	const displayErrors = showMultiple ? errors : errors.slice(0, 1);

	// Animation variants
	const animationVariants = {
		initial: { opacity: 0, y: -10, height: 0 },
		animate: {
			opacity: 1,
			y: 0,
			height: "auto",
			transition: { duration: 0.2, ease: "easeOut" },
		},
		exit: {
			opacity: 0,
			y: -10,
			height: 0,
			transition: { duration: 0.15, ease: "easeIn" },
		},
	};

	// Default error icon
	const defaultIcon = (
		<svg
			fill="none"
			stroke="currentColor"
			viewBox="0 0 24 24"
			aria-hidden="true"
		>
			<path
				strokeLinecap="round"
				strokeLinejoin="round"
				strokeWidth={2}
				d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
			/>
		</svg>
	);

	const errorIcon = icon || defaultIcon;

	return (
		<AnimatePresence mode="wait">
			{displayErrors.length > 0 && (
				<ErrorContainer
					theme={theme}
					size={size}
					variant={variant}
					className={className}
					initial={immediate ? "animate" : "initial"}
					animate="animate"
					exit="exit"
					variants={animationVariants}
					role="alert"
					aria-live="polite"
					aria-relevant="all"
				>
					{errorIcon && <ErrorIcon theme={theme}>{errorIcon}</ErrorIcon>}

					<ErrorContent theme={theme}>
						{displayErrors.map((errorMessage, index) => (
							<ErrorMessage
								key={`${fieldName}-error-${index}`}
								theme={theme}
								hasMargin={index > 0}
							>
								{/*<ErrorText theme={theme}>{errorMessage}</ErrorText>*/}
								<HelperText theme={theme} isError={!!errorMessage}>
									{errorMessage}
								</HelperText>
							</ErrorMessage>
						))}
					</ErrorContent>
				</ErrorContainer>
			)}
		</AnimatePresence>
	);
}

// ============================================================================
// Field Error Hook
// ============================================================================

/**
 * Hook for managing field error state
 */
export function useFieldError(fieldName?: string) {
	const [error, setError] = React.useState<string | string[] | null>(null);
	const [touched, setTouched] = React.useState(false);

	const showError = React.useMemo(() => {
		return touched && !!error;
	}, [touched, error]);

	const clearError = React.useCallback(() => {
		setError(null);
	}, []);

	const setFieldError = React.useCallback(
		(newError: string | string[] | null) => {
			setError(newError);
		},
		[],
	);

	const touch = React.useCallback(() => {
		setTouched(true);
	}, []);

	const reset = React.useCallback(() => {
		setError(null);
		setTouched(false);
	}, []);

	return {
		error,
		showError,
		touched,
		setError: setFieldError,
		clearError,
		touch,
		reset,
		fieldName,
	};
}

// ============================================================================
// Export
// ============================================================================

export default FieldError;
